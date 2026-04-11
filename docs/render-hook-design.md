# GameRenderHook 设计文档

## 概述

GameRenderHook 是 Don't Starve 渲染管线的运行时优化系统。通过 DLL 注入 + 函数 hook，拦截游戏的 OpenGL 渲染调用，减少每帧 GPU 资源分配/释放的开销。

核心问题：Don't Starve 的 `Batcher::Flush` 每次调用都会 `CreateVB` 分配新的 Vertex Buffer，draw 之后立即 `Release` 销毁。这意味着每帧数百次 `glGenBuffers`/`glDeleteBuffers`，造成不必要的 GPU 驱动开销。

解决方案：
- **Phase 1**（已完成）：Vertex Buffer Pool — 拦截 CreateVB/ReleaseVB，复用已分配的 VB 对象
- **Phase 2**（已评估，放弃）：Draw Call Batcher — 运行时诊断显示仅 ~12% 的 Flush 可合并，ROI 不足

## 架构概览

```
游戏启动 → DLL 注入 (DontStarveInjector)
         → InstallRenderHooks()
           → 通过 MemorySignature 扫描二进制特征码定位函数地址
           → 通过 Frida gum_interceptor_replace() 安装 hook
           → CreateVB / ReleaseVB / BatcherFlush 被替换为自定义实现
```

技术栈：
- **Frida GumInterceptor** — 运行时函数替换（非 inline hook）
- **MemorySignature** — 字节特征码扫描，定位无符号二进制中的目标函数
- **spdlog** — 日志输出

Hook 安装流程（`GameRenderHook.cpp`）：

1. `gum_module_get_path(gum_process_get_main_module())` 获取主模块路径
2. 扫描辅助函数签名：`GetResource_sig`、`IsRenderThread_sig` — 仅解析地址，不 hook
3. 扫描并 hook 三个渲染函数：`CreateVB_sig`、`ReleaseVB_sig`、`BatcherFlush_sig`
4. 任一辅助签名扫描失败时自动禁用 pool（`g_enableBufferPool = false`）

## 二进制依赖分析

### HWBuffer 结构体布局

从 macOS 符号二进制 Ghidra 逆向得出，在 Windows 无符号二进制上已验证一致：

```cpp
struct HWBuffer {
    void*       vtable;      // +0x00  虚表指针
    uint32_t    stride;      // +0x08  每顶点字节数
    uint32_t    count;       // +0x0C  顶点数量
    uint32_t    glBufferID;  // +0x10  GL buffer 句柄
    eUsageType  usageType;   // +0x14  用途类型
};
```

vtable 布局：
| 索引 | 函数 | 签名 |
|------|------|------|
| [0] | 析构函数 | `void dtor(HWBuffer*)` |
| [1] | UploadData | `void UploadData(HWBuffer*, const void* data)` |
| [2] | BindVertexState | `void BindVertexState(HWBuffer*, attribs, desc)` |

Phase 1 的 pool 命中路径在 Windows 上直接调用 `glBindBuffer` + `glBufferSubData` 上传数据（绕过 `vtable[1]` UploadData 避免纹理损坏），非 Windows 平台仍使用 `vtable[1]`。

### eUsageType 枚举

macOS 与 Windows 二进制中值完全一致：

```cpp
enum class eUsageType : uint32_t {
    STATIC_DRAW  = 9,    // → GL_STATIC_DRAW  (0x88E4)
    STREAM_DRAW  = 10,   // → GL_STREAM_DRAW  (0x88E0)
    STATIC_COPY  = 0xC,  // → GL_STATIC_COPY  (0x88E8)
    STATIC_READ  = 0x11, // → GL_STATIC_READ  (0x88E5)
    STREAM_READ  = 0x12, // → GL_STREAM_READ  (0x88E1)
    STREAM_COPY  = 0x14, // → GL_STREAM_COPY  (0x88E9)
    DYNAMIC_READ = 0x21, // → GL_DYNAMIC_READ (0x88E6)
    DYNAMIC_DRAW = 0x22, // → GL_DYNAMIC_DRAW (0x88E2)
    DYNAMIC_COPY = 0x24, // → GL_DYNAMIC_COPY (0x88EA)
};
```

### Batcher 结构体偏移

| 字段 | macOS 偏移 | Windows 偏移 | 说明 |
|------|-----------|-------------|------|
| 纹理槽位 | — | +0x08/0x0C/0x10 | 3 个 texture handle (int) |
| 顶点描述 | — | +0x20 | vertex description handle |
| 混合模式 | +0x38 | +0x24 | blend mode |
| Effect/Shader | — | +0x28 | effect handle |
| 顶点数据起始指针 | +0x40 | +0x70 | vertex data buffer begin |
| 顶点数据结束指针 | +0x48 | +0x78 | vertex data buffer end |

顶点 stride 固定为 `0x18`（24 字节），顶点数 = `(end - begin) / 0x18`。

### Renderer 结构体偏移

| 字段 | 偏移 | 说明 |
|------|------|------|
| cResourceManager\<VB\> | +0x1a8 | VB 资源管理器指针（Windows 已验证） |
| 命令队列 | +0x200 | 渲染命令队列（Windows，非渲染线程时使用） |
| cResourceManager\<Texture\> | +0x1c0 | 纹理资源管理器 |

### 函数签名（Typedefs）

```cpp
// 创建顶点缓冲区 — 6 参数
using CreateVB_t = void* (*)(void* renderer, eUsageType usage,
    uint32_t stride, uint32_t count, const void* data, bool shadow);

// 释放资源 — 注意第二个参数是 handle (uint32_t)，不是指针
using ReleaseVB_t = void (*)(void* resourceMgr, uint32_t handle);

// Batcher 刷新
using BatcherFlush_t = void (*)(void* batcher);

// 渲染器绘制（Windows 有 3 个 HW 层变体）
using RendererDraw_t = void (*)(void* renderer, void* matrix,
    uint32_t vertexCount, uint32_t primType);

// 辅助函数（不 hook，仅调用）
using GetResource_t = void* (*)(void* resourceMgr, uint32_t handle);
using IsRenderThread_t = int (*)();
```

**重要**：`ReleaseVB_t` 的第二个参数是 `uint32_t handle`（cResourceManager 的资源句柄），而非 `void*` 指针。需要通过 `GetResource(mgr, handle)` 解析为 `HWBuffer*`。

## Phase 1: Vertex Buffer Pool

### 设计思路

拦截 VB 的分配/释放路径，将即将销毁的 VB 缓存到 pool 中。下次分配相同规格的 VB 时，直接复用已有对象，仅重新上传顶点数据。

**仅缓存 `STREAM_DRAW` 类型的 VB**。`STATIC_DRAW`（UI 元素、海洋网格等长生命周期对象）和其他类型走原始路径，不经过 pool。这是因为 `Batcher::Flush` 的 create→draw→release 热循环专用 `STREAM_DRAW`，而 `STATIC_DRAW` VB 若被 pool 回收后重用为 `STREAM_DRAW`，其 GL buffer 内容会被覆盖，导致 UI 贴图消失。

```
CreateVB 调用 → usage == STREAM_DRAW && pool 中有匹配 VB？
  ├─ 命中（Windows）：GetResource(handle) → HWBuffer* → glBindBuffer + glBufferSubData 上传数据 → 返回 handle
  ├─ 命中（非 Windows）：GetResource(handle) → HWBuffer* → vtable[1] UploadData → 返回 handle
  └─ 未命中 / 非 STREAM_DRAW：调用原始 CreateVB

ReleaseVB 调用 → GetResource(handle) → 读取 stride/count/usageType
  ├─ usageType == STREAM_DRAW && pool 未满：缓存 handle，跳过原始 Release
  └─ 非 STREAM_DRAW / pool 已满：调用原始 Release 销毁
```

### Pool Key 策略

```cpp
struct VBPoolKey {
    uint32_t stride;          // 每顶点字节数（精确匹配）
    uint32_t capacityBucket;  // roundUpPow2(count)，最小 64
};
```

使用 `roundUpPow2(count)` 作为容量桶，避免碎片化。例如 count=100 和 count=120 都会映射到 bucket=128。

### 容量限制

| 参数 | 值 | 说明 |
|------|---|------|
| MAX_POOL_SIZE_PER_BUCKET | 32 | 每个 (stride, bucket) 组合最多缓存 32 个 VB |
| MAX_TOTAL_POOLED | 256 | 全局最多缓存 256 个 VB |

超出限制时 pool.release() 返回 false，handle 被正常销毁。

### hooked_CreateVB

```
1. 首次调用时捕获 renderer 指针 (g_renderer)
2. 检查前置条件：g_enableBufferPool && usage == STREAM_DRAW && g_GetResource && g_IsRenderThread
3. 检查 IsRenderThread() — 仅在渲染线程上使用 pool
4. pool.acquire(stride, count) → 如果命中：
   a. 通过 GetResource(renderer+0x1a8, handle) 解析 HWBuffer*
   b. Windows：glBindBuffer + glBufferSubData 直接上传数据
      非 Windows：HWBuffer->vtable[1](buf, data) 上传数据
   c. 返回复用的 handle
5. 未命中 / 非 STREAM_DRAW → 调用 original_CreateVB
```

### hooked_ReleaseVB

```
1. 检查 g_enableBufferPool && g_GetResource
2. GetResource(resourceMgr, handle) → HWBuffer*
3. 检查 hwBuf->usageType == STREAM_DRAW
4. 读取 hwBuf->stride 和 hwBuf->count
5. pool.release(handle, stride, count)
   ├─ 成功：return（不调用原始 Release，VB 保留在 GPU 中）
   └─ 失败（pool 满）/ 非 STREAM_DRAW：调用 original_ReleaseVB 正常销毁
```

### hooked_BatcherFlush

直通模式：调用 `original_BatcherFlush(batcher)` 后执行 `logStatsIfNeeded()`。

## Phase 2: Draw Call Batcher（已评估，放弃）

### 评估过程

通过运行时诊断模块（已移除）对 Batcher::Flush 进行了连续调用的状态比较分析。诊断逻辑：
1. 每次 Flush 时捕获完整的 Batcher 状态快照（纹理×3、sampler flags×3、vertexDesc、blendMode、effect、shaderConst×3、scissor rect、条件标志）
2. 调用 `GameRenderer::GetMatrix(0)` 和 `GetMatrix(1)` 获取变换矩阵
3. 与前一次 Flush 的状态/矩阵进行比较，统计连续匹配（可合并）的 run

### 诊断数据

| 指标 | 短时间运行 | 长时间运行 | 稳态 |
|------|-----------|-----------|------|
| 总 Flush 次数 | 194,843 | 938,296 | 1,946,590 |
| 状态匹配率 | 8.9% | 6.3% | 7.2% |
| 矩阵匹配率（状态匹配中） | 100% | 100% | 100% |
| 可合并占比 | 15.1% | 11.3% | 12.7% |
| 最大连续 run | 12 | 12 | 12 |
| 平均 run 长度 | ~2.4 | ~2.3 | ~2.3 |

关键发现：
- **矩阵始终一致**：当渲染状态匹配时，变换矩阵 100% 匹配 — Adjacent Merge 在技术上可行
- **收益有限**：稳态仅 ~12.7% 的 Flush 可合并，大部分为 2 次连续合并
- **Phase 1 已覆盖主要开销**：VBPool 命中率 100%（hits=1,966,422, misses=8），GPU 缓冲区分配/释放开销已完全消除

### 放弃原因

1. **ROI 不足**：~12% 可合并率意味着每帧约减少 40 次 glDrawArrays 调用（325 次/帧中），而 glDrawArrays 的 per-call 开销在现代驱动上很小
2. **Phase 1 已解决核心问题**：VBPool 消除了 glGenBuffers/glDeleteBuffers 的高频开销（100% 命中率），这是原始性能瓶颈的主要来源
3. **实现复杂度与收益不匹配**：Adjacent Merge 需要正确处理顶点数据拼接、VB 大小管理、状态验证等，引入的 bug 风险与 ~12% 的 draw call 减少不成比例

### 原始设计方案（已废弃）

最初考虑的"延迟排序"方案（defer+sort by texture/effect/blend）因以下问题被否决：
- Alpha 混合依赖绘制顺序，重排会导致渲染错误
- 矩阵/shader constants 在帧内变化，快照时机难以把控
- 状态捕获不完整的风险高

## 跨平台签名

每个目标函数使用 `function_relocation::MemorySignature` 进行字节特征码匹配：

```cpp
inline function_relocation::MemorySignature CreateVB_sig{
#ifdef _WIN32
    "4C 89 6C 24 58 4C 8B E9 B9 20 00 00 00", -0xB
#elif defined(__linux__)
    "TODO_FILL_LINUX_PATTERN", 0
#elif defined(__APPLE__)
    "TODO_FILL_MACOS_PATTERN", 0
#endif
};
```

`??` 表示通配符（用于跳过重定位地址等可变字节）。第二个参数为偏移量：从匹配位置到函数入口的字节偏移（0 表示匹配位置即函数入口）。

### 当前签名状态

| 函数 | Windows | Linux | macOS |
|------|---------|-------|-------|
| CreateVB | 已填充 | TODO | TODO |
| ReleaseVB (cResourceManager::Release) | 已填充 | TODO | TODO |
| BatcherFlush | 已填充 | TODO | TODO |
| RendererDraw | 已填充 | TODO | TODO |
| GetResource | 已填充 | TODO | TODO |
| IsRenderThread | 已填充 | TODO | TODO |

## Windows 二进制分析

### 分析方法

macOS 二进制 (`dontstarve_steam_12527201`) 保留了完整符号，作为参考基准。Windows 二进制 (`dontstarve_steam_x64.exe`) 无符号，通过以下方法交叉定位：

1. 字符串锚点（`"CreateVB"`、`"HWBuffer.cpp(37)"`、`"RenderBufferCommands.h"` 等）
2. 导入表（glDrawArrays、glGenBuffers 等 GL 函数的 xref）
3. 结构体偏移模式匹配（Batcher 中 0x70/0x78 的指针差计算）
4. 调用图比对（caller/callee 关系）

### 函数地址映射

| 函数 | macOS 地址 | Windows 地址 | 备注 |
|------|-----------|-------------|------|
| CreateVB | 0x1001f3e0e | 0x1403e2d10 | 6 参数，调用者 22/23 个 |
| cResourceManager::Release | 0x10013b1b0 | 0x140018a30 | VB 模板实例，stride=0x40 |
| Batcher::Flush | 0x100167c6c | 0x140036360 | 顶点偏移 0x70/0x78 |
| HWRenderer::Draw | 0x1001ead48 | 0x1403dc610 | 调用 glDrawArrays |
| GetResource | — | 0x1403dc420 | 43 个调用者 |
| IsRenderThread | — | 0x140002160 | 比较 GetCurrentThreadId |
| eUsageType→GL | 0x1001e62e8 | 0x1403e6970 | 值完全一致 |
| HWBuffer::HWBuffer | 0x1001e6288 | 0x1403e68c0 | 布局一致 |

### Windows 特殊架构：命令队列

Windows 版本使用 **ANGLE**（EGL）而非直接 OpenGL，并采用命令队列架构：

- **渲染线程**上：`CreateVB` 直接调用 `HWBuffer->vtable[1](buf, data)` 上传数据
- **游戏线程**上：`CreateVB` 复制数据，创建 `CreateVBCmd` 命令对象（vtable 0x1405a70c8），推入 `renderer+0x200` 的命令队列

当前 Phase 1 的 pool 逻辑仅在渲染线程上激活（`IsRenderThread()` 检查），回避了命令队列的复杂性。

### ReleaseVB 签名唯一性

`cResourceManager::Release` 是模板函数，Windows 二进制中存在 3 个实例化：

| 地址 | stride | 断言行号 | 用途 |
|------|--------|---------|------|
| 0x140002ef0 | 112 | — | 其他资源类型 |
| 0x140018a30 | 64 | 0x40 | **VB（目标）** |
| 0x140031800 | 64 | 0xE9 | 其他资源类型 |

通过包含 `BA 40 00 00 00`（`mov edx, 0x40` 即断言行号 64）的较长特征码区分。

## 安全防护

| 防护 | 说明 |
|------|------|
| IsRenderThread 检查 | Pool 仅在渲染线程上激活，避免命令队列竞态 |
| GetResource null 检查 | 解析失败时跳过 pool 逻辑，回退原始路径 |
| Pool 容量限制 | 超出 MAX_TOTAL_POOLED/MAX_POOL_SIZE_PER_BUCKET 时正常释放 |
| g_enableBufferPool 开关 | 签名扫描失败时自动禁用 |
| 签名扫描失败降级 | GetResource 或 IsRenderThread 扫描失败 → 禁用 pool，hook 退化为纯透传 |

## 统计与调试

`logStatsIfNeeded()` 每 600 帧输出一次统计信息：

```
[RenderHook] VBPool hits=1234 misses=56 evictions=3 hitRate=95.7%
```

统计字段：
- **hits** — pool 命中次数（复用已有 VB）
- **misses** — pool 未命中次数（需分配新 VB）
- **evictions** — pool 满导致的驱逐次数
- **hitRate** — 命中率 = hits / (hits + misses)

## 已知限制与风险

1. **VB 大小不匹配**：pool 使用 `roundUpPow2(count)` 作为 bucket key，复用的 VB 容量可能大于实际需求（浪费显存），但不会小于（安全）
2. **Handle 生命周期**：pooled handle 的 refcount 未被修改，如果引擎其他地方也持有同一 handle 的引用，可能导致 use-after-pool
3. **线程安全**：`VertexBufferPool` 本身无锁，依赖 `IsRenderThread()` 保证单线程访问。如果引擎在非渲染线程调用 ReleaseVB，pooled buffer 可能被意外销毁
4. **签名脆弱性**：字节特征码绑定具体编译产物，游戏更新后可能失效。每次游戏更新需重新验证签名
5. **drainAll 时机**：目前没有调用 `drainAll()` 的时机（如场景切换、退出），pooled buffer 会一直存活直到进程结束
6. **macOS/Linux 未实现**：所有签名均为 `TODO_FILL_*_PATTERN`，仅 Windows 可运行
7. **ANGLE 兼容性**：Windows 版使用 ANGLE（EGL），pool 的 GL buffer 复用在 ANGLE 上的行为可能与原生 GL 不同
