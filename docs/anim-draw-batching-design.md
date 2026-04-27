# AnimNode DrawCacheRender 批处理 Hook 设计文档

## 1. 文档目的

本文档描述针对 Don't Starve / DST 动画渲染路径的运行时优化方案：

- **不重写整个渲染管线**
- **不改动 CacheRender 快照阶段的数据结构**
- 仅通过 **DLL 注入 + 函数 hook** 拦截 `TDataCacheAnimNode::DrawCacheRender`
- 将当前“每个 symbol 1~2 次 draw call”的路径，改造成“**按原始绘制顺序保序合批**”的路径

目标是降低动画实体渲染中的 draw call 数量、纹理状态切换次数和 per-symbol 常量上传次数，同时保持与原始渲染结果一致。

---

## 2. 背景与问题定义

根据当前逆向分析，游戏动画渲染采用如下路径：

```text
CacheRender
  -> AnimNode::DoCacheForRender
    -> 构造 TDataCacheAnimNode（复制世界矩阵、颜色、override、隐藏表等）

DrawCacheRender
  -> CacheWorldRender
    -> TDataCacheAnimNode::DrawCacheRender
      -> sAnim::GetFrame
      -> 计算 passMatrix
      -> for each sAnimElement:
           GetOverrideBuildForSymbol
           ApplyTextures(if build changed)
           上传 elemFinal 矩阵常量
           Draw(vbHandle2)
           Draw(vbHandle)
```

当前路径的核心问题：

1. **每个可见 symbol 都会单独提交 draw call**
   - 一个元素通常触发 1~2 次 `Renderer::Draw`
   - 实体层级上会形成大量小 draw

2. **每个 symbol 都会上传独立 model matrix 常量**
   - 即便多个 symbol 共享相同 build / texture / shader / blend / vertex format
   - 仍然因为变换不同而无法直接复用现有 draw path

3. **symbol transform 在每帧 draw 阶段重新计算**
   - 当前没有 dirty flag，也没有跨帧缓存
   - 每帧都会做 `passMatrix * elemAffine`

4. **现有 UI Batcher 的结论不能直接套用到动画渲染**
   - `Batcher::Flush` 路径的 adjacent merge ROI 已被判定较低
   - 但 `DrawCacheRender` 是另一条路径，瓶颈形态不同：
     - per-entity symbol 数量更高
     - 同一 AnimNode 往往大量元素共享同一个 `sBuild`
     - 顶点格式和 CPU 侧顶点副本已知，具备“保序重打包”条件

---

## 3. 已知事实与设计约束

以下事实来自现有 Ghidra 分析和文档，属于本方案的输入约束。

### 3.1 已确认的数据结构

- `TDataCacheAnimNode`：248B，完整
- `AnimNode`：348B，完整
- `sAnim` / `sFrame` / `sAnimElement`：完整
- `sBuild`：76B，完整
- `sBuildSymbolEntry`：16B，文档已明确
- `sBuildSymbolFrame`：52B，完整
- `Renderer` / `GameRenderer` / `Batcher` / `BatchVertex`：完整
- `AutoShaderConstant`：已知布局与行为

### 3.2 已确认的顶点格式

动画路径使用的顶点布局与 `BatchVertex` 一致，stride 为 **24 字节**：

```text
position: float x, y, z
uv:       float u, v
color:    RGBA8 packed
```

即：

- slot0 = POSITION(xyz)
- slot1 = TEXCOORD0(uv)
- slot10 = DIFFUSE(color)

这意味着我们可以在 CPU 上直接读取 `sBuild` 中的顶点副本，对 position 做矩阵变换，保留 uv/color 不变，然后写入新的 transient VB。

### 3.3 已确认的 `DrawCacheRender` 特征

`TDataCacheAnimNode::DrawCacheRender` 的 outer state 具有以下性质：

- **节点级固定**：effect 选择、blend mode、vertexDesc、颜色常量、depth bias、部分 shader 常量
- **pass 级固定**：rotation/passMatrix、stencil/depth/write 状态
- **元素级变化**：
  - `elemFinal = passMatrix * elemAffine`
  - `GetOverrideBuildForSymbol`
  - `ApplyTextures`（当 build 改变时）
  - primary / secondary VB 子范围提交

### 3.4 必须保留的语义

以下行为不能被破坏：

1. **元素顺序语义**
   - 原始顺序是遍历 `sFrame` 中的元素顺序
   - 单个元素内部顺序是：`vbHandle2` 先画，`vbHandle` 后画

2. **pass 语义**
   - stencil/depth/color write 状态必须按原逻辑切换
   - 不允许跨 pass 合批

3. **build override / hidden symbol / hidden layer**
   - 必须沿用原始可见性判断和 build 解析逻辑

4. **透明混合顺序**
   - 不允许为了 texture 排序而重排元素
   - 本方案只能做 **保序合批**，不能做全局 sort-by-texture

5. **跨平台实现边界**
   - 以 macOS 符号二进制为真值来源
   - Windows x64 通过 signature / fuzzy match 落地

---

## 4. 设计目标与非目标

## 4.1 目标

1. **在不改变输出顺序的前提下减少 draw call**
2. **尽量复用现有 Renderer / VBPool 基础设施**
3. **将风险控制在单个 hook 点内**
4. **当任何前提不满足时可以安全回退到原始路径**
5. **允许分阶段上线：先统计、再旁路验证、最后切主路径**

## 4.2 非目标

1. 不重写 `CacheRender` / `CacheWorldRender` / 排序器
2. 不引入新的 GPU shader 协议或 instancing 管线作为首版前提
3. 不做跨节点重排
4. 不改变当前 `sBuild` 静态 VB 的资源生成方式
5. 不试图一次性解决所有渲染优化问题（如 std::map/vector 拷贝、跨帧 dirty cache）

---

## 5. 方案选择

## 5.1 为什么选 `TDataCacheAnimNode::DrawCacheRender`

这是收益/侵入比最好的 hook 点：

- 已经拿到完整渲染快照（world matrix、颜色、override、隐藏表）
- 已经位于 draw phase，不需要改 cache phase 的数据生命周期
- 原函数天然包含完整的可见性、build 解析、pass 设置语义
- 可以仅替换“元素内循环”这一段，而保留节点级/pass 级状态设置

## 5.2 为什么不是“只减少 ApplyTextures”

`DrawCacheRender` 已经在 `build` 不变时跳过 `ApplyTextures`。这能减少一部分纹理绑定，但**不能减少 draw call 数量**，也不能消除 per-element 常量上传。

## 5.3 为什么不是“直接合并原始 Draw 调用”

原始路径每个 symbol 都依赖独立的 `elemFinal` 矩阵常量。即便 texture/effect 一样，若仍沿用当前 shader 协议，就仍然需要：

- 一次常量上传
- 一次 draw

因此，若不改变数据表达方式，仅“按状态归并 draw”没有意义。

## 5.4 为什么采用“CPU 预变换 + 保序重打包”

因为当前已知条件正好满足：

1. 顶点格式已知且简单（24B）
2. `sBuild` 持有 CPU 侧顶点数据指针
3. 每个 `sBuildSymbolFrame` 都给出 vertex range
4. 元素最终矩阵在 CPU 侧已可计算

因此可将多个原本要分别 draw 的 symbol 顶点，按照**原始提交顺序**直接写入一个 transient buffer 中：

- position：CPU 变换到最终空间
- uv/color：原样复制
- 最终只需要一次 model matrix（单位矩阵或 pass 统一约定）
- 一个 batch 对应一次 `Renderer::Draw`

这才是真正能减少 draw call 的路径。

---

## 6. 总体架构

## 6.1 架构原则

首版只替换原函数的 **Phase 6 Element Inner Loop**，保留其余阶段：

- 保留 `sAnim::GetFrame`
- 保留 `CalculateScaleMatrix` / billboard / rotation / pass loop
- 保留颜色、effect、depth、vertexDesc 等节点级状态设置
- 保留 hidden/override 预处理逻辑
- **仅将“逐元素直接 draw”改为“逐元素生成 RenderItem → 保序批量写顶点 → flush”**

## 6.2 逻辑分层

```text
Hooked_DrawCacheRender
  ├─ Frame / pass / global state：尽量沿用原始逻辑
  ├─ ResolvePhase
  │    └─ 按原顺序解析每个元素的可见 geometry -> RenderItem
  ├─ BatchBuildPhase
  │    └─ 将相邻且兼容的 RenderItem 追加到 CPU scratch buffer
  ├─ FlushPhase
  │    └─ CreateVB(transient) -> SetTexture/SetEffect -> Draw -> ReleaseVB
  └─ Fallback
       └─ 任一条件不满足时跳回 original_DrawCacheRender
```

---

## 7. RenderItem 设计

## 7.1 RenderItem 定义

`RenderItem` 是对原始“一个 draw 子提交”的抽象。一个 `sAnimElement` 最多生成两个 `RenderItem`：

- 一个对应 `vbHandle2 + vertexStart2 + vertexCount2`
- 一个对应 `vbHandle + vertexStart + vertexCount`

建议结构：

```cpp
struct AnimRenderItem {
    const sBuild*            build;
    const BatchVertex*       srcVerts;
    uint32_t                 vertexStart;
    uint32_t                 vertexCount;
    Matrix4                  elemFinal;

    uint32_t                 tex0;
    uint32_t                 tex1;
    uint32_t                 tex2;
    uint32_t                 effectHandle;
    uint32_t                 blendMode;
    uint32_t                 vertexDescHandle;

    uint8_t                  passIndex;
    uint8_t                  drawKind;   // secondary / primary
};
```

其中：

- `srcVerts` 指向 `sBuild` 的 CPU 顶点数组
- `vertexStart / vertexCount` 来自 `sBuildSymbolFrame`
- `elemFinal` 是该元素最终矩阵
- `tex0..2` 表示本 draw 实际绑定纹理句柄

## 7.2 为什么 RenderItem 粒度是“子提交”而不是“元素”

因为原始顺序是：

```text
elem1.secondary
elem1.primary
elem2.secondary
elem2.primary
...
```

若以元素为单位做后处理，仍需在内部展开两次 draw 语义；直接把“secondary / primary 子范围”建模成独立 `RenderItem`，更容易保证顺序完全一致。

---

## 8. BatchKey 与 flush 条件

## 8.1 BatchKey

由于本方案要求保序，因此 **只允许合并相邻且兼容的 RenderItem**。建议 batch key 包含：

```cpp
struct AnimBatchKey {
    uint32_t tex0;
    uint32_t tex1;
    uint32_t tex2;
    uint32_t effectHandle;
    uint32_t blendMode;
    uint32_t vertexDescHandle;
    uint8_t  passIndex;
};
```

说明：

- `passIndex` 不同不能合并
- `effectHandle`、`blendMode`、`vertexDescHandle` 不同不能合并
- 任一纹理槽位不同不能合并
- **不按 build 指针强制分割**；若两个 build 解析后的纹理状态一致，理论上可进入同一 batch
- 但首版实现可以保守地把 `build` 也纳入 key，简化验证

## 8.2 flush 条件

在以下情况必须 flush 当前 batch：

1. 当前 `RenderItem` 与 active key 不兼容
2. CPU scratch buffer 容量不足
3. 检测到源 vertex range 越界
4. 缺失 CPU 顶点副本或纹理状态解析失败
5. 即将切换 pass
6. 节点渲染结束

---

## 9. 顶点重打包策略

## 9.1 输入数据

单个 `RenderItem` 的输入：

- `srcVerts[vertexStart .. vertexStart + vertexCount)`
- `elemFinal`

每个源顶点是 24 字节：

- `xyz`：需要 CPU 变换
- `uv`：直接拷贝
- `color`：直接拷贝

## 9.2 输出数据

输出仍使用相同的 24 字节格式，写入临时连续数组 `BatchVertex[]`：

```cpp
dst.pos = TransformPoint(elemFinal, src.pos);
dst.uv = src.uv;
dst.color = src.color;
```

## 9.3 模型矩阵策略

因为 position 已在 CPU 侧被变换到最终空间，batch draw 时不再需要 per-element model matrix。建议：

- batch draw 使用统一矩阵常量（单位矩阵，或与原 shader 协议一致的“已变换空间矩阵”）
- 该常量必须在实现时通过对比实验确认与原路径等价

**注意**：这是实现中最需要验证的点。文档当前给出的设计方向是：

1. 将元素级变换下沉到 CPU
2. 将 GPU 侧矩阵输入降为 batch 级常量

若发现 shader 仍依赖其他矩阵语义，则必须：

- 调整 batch 顶点写入的空间选择，或
- 在首版中限定为某些 billboard / pass 条件下才启用

---

## 10. Hook 函数的执行流程

建议的 `hooked_DrawCacheRender` 流程：

```text
1. 读取 TDC / renderer / camera / cache
2. 调用与原逻辑等价的 frame 选择
3. 做节点级 shader/effect/depth/blend/vertexDesc 设置
4. 进入 pass loop
5. 做 hidden/override 预处理
6. 遍历元素，按原顺序生成 RenderItem：
   - hidden skip
   - GetOverrideBuildForSymbol
   - 生成 secondary RenderItem（若有）
   - 生成 primary RenderItem（若有）
7. 将 RenderItem 追加到 active batch：
   - key 不同 -> flush
   - 容量不足 -> flush
   - 将源顶点按 elemFinal 变换后写入 scratch
8. pass 结束前 flush
9. 恢复原始 depth/stencil/colour write 状态
10. 节点结束
```

---

## 11. 与现有 VB Pool 的协同

本方案**刻意依赖现有 Phase 1 Vertex Buffer Pool**，原因如下：

1. batch flush 仍会创建 transient VB
2. 但有 VBPool 时，这些 CreateVB/ReleaseVB 会被高命中率复用
3. 因此无需为动画批处理再单独设计一套 GPU buffer 生命周期管理

建议首版 batch flush 继续复用现有接口：

```text
Renderer::CreateVB(STREAM_DRAW, 24, batchVertexCount, scratchData, shadow=false)
Renderer::SetTexture(...)
Renderer::Draw(...)
Renderer::ReleaseVB(...)
```

这样实现更简单，风险更低，也与当前 `GameRenderHook` 的架构一致。

---

## 12. 兼容性与回退设计

## 12.1 启用条件

建议仅在以下条件全部满足时进入批处理路径：

1. 成功定位 `DrawCacheRender`、`Renderer::Draw`、`CreateVB`、`ReleaseVB` 等必要函数
2. `TDataCacheAnimNode::vertexDescHandle` 与预期动画顶点格式一致
3. `sBuild` 的 CPU 顶点数组指针有效
4. `vertexStart + vertexCount` 未越界
5. 当前 pass / effect / shader 语义在已验证白名单内

## 12.2 回退策略

出现以下任一情况，立即回退到原始函数：

- 结构布局或签名解析失败
- 不支持的 shader / pass 组合
- 源顶点数据缺失
- buffer 溢出或内部一致性校验失败
- 调试开关强制禁用

回退要求：

- 以“**整节点回退**”为优先，而不是“半节点一半 batch、一半原函数”
- 避免在同一个节点的中间状态切换两套渲染路径，降低状态恢复风险

---

## 13. 关键风险

## 13.1 矩阵空间假设风险（最高）

最大风险是：当前 shader 最终使用的矩阵空间不一定等价于“CPU 直接写最终位置 + GPU 用单位矩阵”。

必须重点验证：

- full billboard
- cylindrical billboard
- 非 billboard
- depth/stencil 双 pass
- rotation / offset / depth fog 常量

## 13.2 透明混合与绘制顺序风险

即使不做全局排序，只要 batch append 顺序与原始 draw 顺序不同，也会出错。实现时必须保证：

- RenderItem 生成顺序 == 原始 draw 提交顺序
- flush 后绘制顺序 == RenderItem 在 scratch buffer 中的追加顺序

## 13.3 CPU 开销回归风险

本方案以 CPU 顶点变换换取 draw call 减少。若某些极端场景顶点数远高于预期，则可能出现：

- CPU transform 开销上升
- scratch buffer 扩容频繁

因此需要在诊断阶段记录：

- 每节点 symbol 数
- 每节点顶点总数
- 可合并 run 长度分布

## 13.4 特效 / shader 常量遗漏风险

若某些元素级行为并不只依赖 `elemFinal`，而还依赖隐式常量、特殊 effect 参数或状态副作用，则批处理可能破坏输出。

首版应采取白名单策略，只支持已验证的常见 anim shader 组合。

---

## 14. 分阶段实施计划

## Phase A — 诊断与观测

目标：只加统计，不改变渲染结果。

记录指标：

- 每帧进入 `DrawCacheRender` 的节点数
- 每节点元素数 / 可见元素数
- 每节点 secondary / primary draw 数
- build 切换次数
- 相邻兼容 RenderItem run 分布
- 每节点累计顶点数

产出：判断实际可合批率和 scratch buffer 上限。

## Phase B — RenderItem 旁路构建

目标：在不提交 batch draw 的前提下，完整构建 RenderItem 序列并做一致性检查。

检查内容：

- RenderItem 数量是否等于原始 draw 次数
- build / vertex range / 纹理状态是否与原路径一致
- hidden / override 结果是否一致

## Phase C — 批处理输出（实验开关）

目标：对通过白名单的节点启用真正的 batch draw，并保留快速回退开关。

策略：

- 默认关闭
- 仅对单一 shader/effect 组合启用
- 发生任意校验失败立刻整节点回退

## Phase D — 默认启用与扩大覆盖

在验证通过后逐步覆盖：

- 更多 effect 组合
- 更多 billboard 模式
- DST / 不同平台版本

---

## 15. 验证计划

## 15.1 正确性验证

1. **像素级截图对比**
   - 同场景、同时间点、同摄像机
   - 原始路径 vs batch 路径

2. **渲染顺序验证日志**
   - 输出每节点原始 draw 序列摘要与 batch 展开序列摘要
   - 确认顺序完全一致

3. **覆盖场景**
   - 玩家角色
   - 大量怪物 / 掉落物
   - 特效实体（带 bloom / haunted / fade）
   - billboard 与非 billboard 混合场景

## 15.2 性能验证

1. 每帧 `Renderer::Draw` 次数
2. 每帧 `ApplyTextures` 次数
3. 每帧 `CreateVB/ReleaseVB` 次数
4. CPU frame time / render thread time
5. 大场景稳态 FPS

## 15.3 健壮性验证

1. 长时间运行无崩溃
2. 切地图 / 菜单 / 暂停 / Alt-Tab 正常
3. 开关 batch 功能可热切换（若实现）

---

## 16. 与现有 render-hook-design.md 的关系

本设计文档是对现有 `docs/render-hook-design.md` 的补充，不冲突。

- 现有文档中的 **Phase 1 VBPool**：保留并复用
- 现有文档中已放弃的 **UI Batcher::Flush adjacent merge**：结论仍然成立
- 本文新增的是 **AnimNode / DrawCacheRender 路径的保序批处理**，属于另一条渲染路径，问题形态不同，不能直接套用 UI Batcher 的 ROI 结论

---

## 17. 当前结论

在现有逆向成果基础上，已经具备开始实现该方案的必要信息：

- hook 点明确
- 结构体布局完整
- 顶点格式明确
- 渲染顺序与 pass 语义明确
- `sBuild` 的 CPU 顶点数据和 symbol frame 范围已知

因此，推荐的下一步不是继续扩展结构体逆向，而是按本文的 **Phase A → Phase B → Phase C** 顺序推进实现。

当前最重要的技术验证点只有一个：

> **CPU 预变换顶点 + batch 级矩阵常量** 是否在所有目标 shader / billboard 模式下与原始路径完全等价。

只要这个点验证通过，该方案就具备落地价值。
