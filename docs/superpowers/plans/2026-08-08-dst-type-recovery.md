# DST 核心类型布局恢复 (Type Recovery) 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 从旧版 macOS 32位有符号二进制 `dontstarve_steam`(base `0x1000`, i386)恢复核心游戏类型的二进制布局(struct 字段偏移),**产出物直接回写 Ghidra 内存布局(struct 数据类型)**,并辅以文档记录证据链。IDA (idalib-mcp) 与 Ghidra (ghidra-mcp) 双工具交叉验证,并利用 Ghidra 中已加载的 64位新版与 Android arm64 二进制做跨版本锚点。

**产出物:** 每个 Tier 产出 = (1) `docs/superpowers/type-recovery/tierN-*.md` 文档 (2) **回写 Ghidra struct**(`create_struct`/`add_struct_field`/`modify_struct_field`) (3) `evidence-chain.md` 证据链。流程:先出文档 → 回写 Ghidra 布局 → 再 review。

**Architecture:** 类型恢复分 5 个 Tier 切片。每个类型用「vtable → 构造/析构 this+off → 全局单例实例」三源交叉恢复;Ghidra 侧 Demangler 类型目录、模板符号上下文、反编译结果作为独立验证源。每切片产出 struct 定义 + 三源证据链,独立 review 后进入下一切片。

**重要前提(用户澄清):** Ghidra 与 IDA 中的现有 struct **不是引擎自动推导的**,而是用户使用 `tools/ghidra_plugin/` 插件(源码不在本仓库,build 目录为 gitignore 空壳)前期进行的一轮推导产物。因此:
- 现有字段名/偏移 = **插件先验**,置信度取决于插件推导质量,必须经独立验证
- 本计划的 IDA 反编译交叉验证 = **独立门禁**,用于确认/修正插件先验
- cEntity 39 成员等「已有定义」同样来自插件,非自动分析结果

**Tech Stack:** idalib-mcp (IDA) 会话 `255dac01`;ghidra-mcp 程序 `dontstarve_steam` (i386 32位, 23326 func, 143320 sym) + 对照 `dontstarve_steam_12527201` (x64) + `libDontStarve.so` (AArch64)。产出为 C 风格 struct 定义(IDA `create_struct`/`import_data_types` + Ghidra 结构体)。

## Global Constraints

- **Spec:** 本文档即设计 + 计划合一(用户直接要求做计划,无独立 spec;review 通过后按需拆 spec)
- **类型筛选已完成**(见「类型现状」):936 类型 = 103 已定义(多为系统类型) + 633 占位(仅名字)
- **Tier 4 明确跳过**:RakNet (180)、Bullet bt* (26)、FMOD (9)、eastl/std/boost (21)、103 个已定义系统类型 — 第三方开源库布局对照源码即可,不投入恢复
- **跨版本对照仅作锚点**:64位/arm64 指针宽度不同,偏移不得直接搬运,只用于确认成员存在性与语义
- **每类型三源交叉**:vtable(函数数/签名)、构造/析构(this+off)、单例实例(内存定型),任一源冲突 → 标疑点不强行定型
- **产出必须可验证**:每切片结束跑 ghidra-mcp `decompile` + idalib-mcp `decompile` 抽查字段引用,证据链记录进切片报告
- 中文注释 OK;commit message 英文 conventional
- 不修改二进制内容,只写 IDB/程序数据库中的类型定义

## 类型现状(已完成筛选)

### IDA 侧 (idalib-mcp, 会话 b2e7a79f)

| 类别 | 数量 | 说明 |
|---|---|---|
| 总类型 | 936 | |
| 有布局定义 | 103 | 绝大多数是系统/库类型(Darwin、GL、zlib、Mach-O、pthread 等) |
| 仅名字占位 | 633 | 从 mangled symbol 提取,无布局 — 游戏自有类型几乎全在这里 |

游戏相关**已定义**的 9 个(恢复基准):
- `cEntity` — 252B / **39 成员**(vft、guid、name、children、tagset、luaNetVarsMap 全有)→ 最高质量模板
- `cHashedString` — 8B / 2 成员,完整
- `TagSet` — 72B / 1 成员 `char[72]`,只有大小未拆字段
- `StdVectorEntityPtr` / `StdVectorComponentPtr` / `RbTreeFollowerComponents` / `RbTreeLuaNetVarsMap` / `RbTreeNodeBase` / `Vector3f` — eastl 容器模板,布局已知

633 占位按子系统分布(恢复重要性排序依据):

| 子系统 | 数量 | Tier |
|---|---|---|
| RakNet(网络库) | 180 | 4 跳过 |
| Rendering | 60 | 3 |
| Entity/Component | 46 | 2 |
| LuaProxy | 42 | 1 |
| Input/Event | 38 | 3 |
| Networking(游戏网络/Steam) | 33 | 3 |
| Physics(bt*) | 26 | 4 跳过 |
| Map/WorldGen | 21 | 3 |
| eastl/std/boost | 21 | 4 跳过 |
| KleiCore(cApplication/cGame/Util) | 18 | 0 |
| Audio(FMOD) | 9 | 4 跳过 |
| OTHER(cSimulation、cPrefab、MemoryManager、Thread 等) | 139 | 0-3 逐个筛 |

**多态锚点**:276 个 vtable 符号在 `__data`,其中 47 个与占位类型直接匹配(`cDontStarveSettings`、`cSimulation`、`cNetworkComponent`、全部 `*LuaProxy`…)→ 最高优先级,可从 vtable + 构造函数反推。

### Ghidra 侧 (ghidra-mcp, 当前程序 dontstarve_steam)

- 同一二进制(i386 32位),**23326 函数 / 143320 符号** — 分析比 IDA 激进,函数覆盖更全
- **`Demangler/` 类型目录按类名组织**:`cSpatialHash<cEntity>/sBucketHolder`、`Pool<cEntity,FakeLock>/sChunk` 等 — 模板实例化类型 IDA 没有
- mangled 符号带完整模板上下文(`cSpatialHash<cEntity>::sBucketHolder`、`std::vector<cEntity*,...>`)
- **对照二进制**:`dontstarve_steam_12527201`(x64 新版, 14176 func)+ `libDontStarve.so`(AArch64, 42075 func)— 跨版本/跨架构语义锚点
- **现有 struct(如 cSimulation 412B、cGame 304B、cEntityManager 309B、cNetworkComponent 684B)来自 `tools/ghidra_plugin/` 插件前期推导** — 作为先验基准,字段仍需 IDA 交叉验证

## 重要性分级(恢复顺序)

| Tier | 内容 | 数量(约) | 理由 |
|---|---|---|---|
| **Tier 0** | 核心运行时:`cSimulation`、`cGame`、`cApplication`、`cDontStarveSettings`、`cNetworkComponent`、Component 基类 + `EntityLuaProxy`/`ComponentLuaProxy` 家族、`cPrefab`、`cHashedStringLookup`、`cEntityManager` | ~15 | 注入器 hook 直接目标;单例+vtable 齐全,恢复最稳 |
| **Tier 1** | Lua 绑定层:42 个 `*LuaProxy` + `ComponentLuaProxy<T,P>` 模板实例 | ~45 | Lua↔C++ 边界,LuaJIT 注入核心;luaL_Reg 表 → 方法签名 → this+off |
| **Tier 2** | Entity/Component 体系:46 个 Component 子类 + `cEntityComponent` 基类、`cSpatialHash<cEntity>` | ~50 | cEntity 已定,其余通过 vtable 差分 + 构造/析构恢复 |
| **Tier 3** | 游戏功能:Rendering/Map/Input/Event/Networking/Steam | ~150 | 按需恢复,每个先标 tier 再定 |
| **Tier 4** | 跳过:RakNet/Bullet/FMOD/eastl/std + 系统类型 | ~240 | 第三方开源,对照源码 |

## 恢复方法(每类三源交叉 + Ghidra 独立验证)

对每个目标类型 `T`:

1. **vtable 源**:Ghidra `get_function_call_graph`/IDA 查 `__ZTV...T` 在 `__data` 的地址 → 读 vtable 槽位数 → 每槽指向的虚函数签名 → 类大小下限 + 虚函数序号
2. **构造/析构源**:`T::T()` / `T::~T()` 反编译(IDA `decompile` + Ghidra `decompile_function`)→ 收集所有 `this+off` 访问 → 字段候选(按偏移排序)
3. **单例源**:`Util::cSingleton<T>::mInstance`(存在时)→ 实例地址 → `read_memory`/`get_bytes` 定型字段类型(指针/数值/容器头)
4. **Ghidra 独立验证**:Demangler 目录中 T 的子类型/成员类名;模板实例化符号上下文;反编译结果与 IDA 交叉核对偏移
5. **跨版本锚点**(可选):64位/arm64 中同名类的 vtable 槽序、字段名(语义确认,不搬偏移)

**定型规则**:
- 字段偏移冲突 → 标记 `UNKNOWN_0xXX` + 疑点注释,不强行命名
- 指针字段在 i386 为 4B;容器字段按 eastl/std 已知布局展开
- 类大小 = 最大已定字段 offset + size,向上对齐到 4B(该二进制 i386,`alignof` 最大 4 的典型值,逐类核对)
- 每类记录:vtable 地址、构造/析构地址、证据链(哪个函数哪条指令定的哪个字段)

## File map

| 路径 | 职责 |
|---|---|
| `docs/superpowers/plans/2026-08-08-dst-type-recovery.md` | 本计划 |
| `docs/superpowers/type-recovery/tier0-core.md` | Tier 0 恢复报告 |
| `docs/superpowers/type-recovery/tier1-luaproxy.md` | Tier 1 报告 |
| `docs/superpowers/type-recovery/tier2-components.md` | Tier 2 报告 |
| `docs/superpowers/type-recovery/tier3-gamestuff.md` | Tier 3 报告 |
| `docs/superpowers/../3rd/dst/game_decompiler/types_common.h` | 聚合 C 头文件(回写来源) |
| `docs/superpowers/type-recovery/evidence-chain.md` | 逐类型三源证据链索引 |
| Ghidra 程序数据库 `dontstarve_steam` | **struct 回写目标**(`create_struct`/`add_struct_field`/`modify_struct_field`) |

## 回写机制(已验证可行, 2026-08-08)

ghidra-mcp 写入能力实测:
- `create_struct` — 可用;fields 传 JSON 数组字符串 `[{"name":"x","type":"int","offset":0},...]`;自动加 `n`/`p` 前缀
- `add_struct_field` — 可用;`struct_name` + `field_name` + `field_type` + 可选 `offset`
- `import_data_types` — **未实现**(`Import functionality not yet implemented`)— 不能整段 C 头导入,必须逐字段回写
- struct 存储在根路径 `/`(如 `/cSimulation`),非 Demangler 子目录
- 字段名自动规范化:`a` → `nA`、`b` → `pB`(按类型推断前缀)
- 先删后建:`delete_data_type` 可用,重建用 `create_struct` 全量替换

**回写流程(每类型)**:
1. 文档定型(字段名/偏移/类型,见 tierN 报告)
2. 若 struct 已存在且字段陈旧 → `delete_data_type` 删除
3. `create_struct` 按序创建字段(偏移精确,含 UNKNOWN 字段)
4. `get_struct_layout` 验证:偏移、大小、字段名与文档一致
5. 不一致 → `modify_struct_field`/`remove_struct_field` 修正

## 验证标准(成功标准映射)

| 标准 | 方法 | 通过条件 |
|---|---|---|
| 字段偏移双工具一致 | IDA decompile vs Ghidra decompile 同函数抽查 | 无冲突;冲突已标 UNKNOWN |
| vtable 完整性 | vtable 槽数 == 恢复的虚函数数 | 相等 |
| 类大小合理 | 与构造中最大偏移一致,对齐正确 | 一致 |
| 单例实例可定型 | read_memory 实例地址,字段值与语义相符 | 相符 |
| **Ghidra 回写成功** | `get_struct_layout` 与文档逐字段比对 | 偏移/大小/字段名全一致 |
| **Ghidra 可用性** | 回写后重反编译构造函数,字段名出现在伪代码中 | struct 被引用 |

---

## 状态: Tier 0 已完成(方法验证轮)

**2026-08-08 完成**:10 个核心类型恢复 + 双工具交叉验证。详见 `docs/superpowers/type-recovery/tier0-core.md`。

**方法验证结论**:
- 三源交叉(插件先验 struct + IDA ctor/dtor 反编译 + vtable 槽解析)可行
- cSimulation 7 个关键偏移 IDA/Ghidra 全部一致 → 插件先验质量高,IDA 门禁有效
- **关键洞见**:EntityLuaProxy 非 cEntity 头部复用,是独立 4 字段(指针+快照),CheckPointer 刷新 — LuaProxy 家族恢复方法以此为模板

### Task 1: Tier 0 — 核心运行时 ✅ 已完成

**成果:** cSimulation (412B)、cGame (304B)、cDontStarveSettings (8B+)、cNetworkComponent (684B)、cEntityComponent (16B)、cEntityManager (309B)、EntityLuaProxy (16B)、cPrefab (52B)、cHashedStringLookup (92B)、Mutex (56B)
**产出:** `tier0-core.md`、`types_common.h`(初版)、`evidence-chain.md`(Tier 0 部分)
**遗留:** cPrefab 0x00/0x04 hash 归属低置信;cGame 构造内联待反查;cEntityManager 内部待组件恢复验证

### Task 2: Tier 1 — Lua 绑定层 (~45 类型)

**Files:**
- Create: `docs/superpowers/type-recovery/tier1-luaproxy.md`

**Target types:** 42 个 `*LuaProxy` + `ComponentLuaProxy<T,P>` 模板实例(`AnimStateLuaProxy`、`MapLuaProxy`、`PhysicsLuaProxy`、`PathfinderLuaProxy` 等)

**Method 补充:** 每个 LuaProxy 的 luaL_Reg 方法表(字符串 xref 到 `luaL_register`/`luaL_setfuncs` 调用)→ 方法函数 → `lua_touserdata(L,1)` 后 `this+off` 访问 → 字段。**以 EntityLuaProxy 模板为参照**(非宿主头部复用,独立字段 + 失效刷新)

**Acceptance:**
- [ ] 每个 LuaProxy 恢复 userdata 指向的宿主类型指针字段(通常是 `Component*` 或 `cEntity*`)
- [ ] 方法表函数计数与 `luaL_Reg` 表项数一致
- [ ] `ComponentLuaProxy<T,P>` 基类布局一次恢复,子类只存增量
- [ ] 证据链 + IDA 抽查同 Task 1(插件先验 → IDA 门禁)

### Task 3: Tier 2 — Entity/Component 体系 (~50 类型)

**Files:**
- Create: `docs/superpowers/type-recovery/tier2-components.md`

**Target types:** 46 个 Component 子类(`cAnimStateComponent`、`cPhysicsComponent`、`cNetworkComponent` 等)+ `cSpatialHash<cEntity>`、`cEntityComponent` 基类、`Pool<T,FakeLock>` 模板

**Method 补充:** `cEntity::vec_components`(已定义)→ 组件注册函数 → 各 Component 构造;`Pool<T,FakeLock>` 由 Demangler 目录中 `sChunk` 展开

**Acceptance:**
- [ ] `cEntity` 39 成员中指向的所有类型布局闭合(components、tagset、worldNode)
- [ ] 组件间引用(如 `cAnimStateComponent` ↔ `EnvelopeComponent`)字段衔接
- [ ] `TagSet` 72B 拆出字段(至少通过 `tagset` 访问模式定偏移)
- [ ] 证据链 + Ghidra 抽查同 Task 1

## 状态: Tier 0/1/2/3 已完成

**2026-08-08**:Tier 0(核心运行时)、Tier 1(Lua 绑定)、Tier 2(Entity/Component 体系)、Tier 3(游戏功能,5 分片并发)全部完成并回写 Ghidra。

- Tier 3 并发执行:5 个只读子 agent 并行调查(Slice A-E),主 agent 统一回写 — 共 **125 类型**(107 新建 / 3 重建 / 8 验证通过 / 7 跳过)
- Tier 3 报告:`tier3-gamestuff.md`(聚合)+ `tier3-a..e-*.md`(分片)
- Tier 3 关键修正:std::string = 4B 旧 ABI、std::_Rb_tree 头 = 24B、cPrefab 字段归属修正、cInputEvent 不存在(基类 cGameEvent 8B)、SettingFile = CSimpleIniTempl 包装
- 聚合头文件 `types_common.h` 含全部 Tier 0-3 类型;`evidence-chain.md` 索引完整

### Task 5: 聚合与收尾 ✅ 已完成

- Tier 0 报告:`tier0-core.md`、`ghidra-writeback-tier0.md`
- Tier 1 报告:`tier1-luaproxy.md`
- Tier 2 报告:`tier2-components.md`
- Tier 2 关键成果:EnvelopeComponent 28B、cImageComponent 20B、cSoundEmitterComponent 84B、TagSet 拆字段(72B)、cSpatialHash<cEntity> 40B、Pool<T,FakeLock> 36B+sChunk 8B;cEntity 39 成员引用全部闭合
- 交叉验证亮点:Tier 1 CheckPointer `EntityByGUID+220` 与 Tier 2 cEntity `+0xDC pAnimStateComponent` 互证

### Task 4: Tier 3 — 游戏功能(并发执行, ~150 类型)

**Files:**
- Create: `docs/superpowers/type-recovery/tier3-gamestuff.md`(聚合报告)
- Create: `docs/superpowers/type-recovery/tier3-<slice>.md`(每个并发分片报告)

**Target types 按子系统分片(并发执行):**
- **Slice A — Rendering (~60)**:`BaseRenderer`、`BaseTexture`、`BitmapFont`、`BitmapFontManager`、`BitmapFontRenderer`、`Batcher`、`VertexDescription`、`Atlas`、`AtlasManager`、`HWRenderTarget`、`RenderTarget`、`RenderTargetManager`、`RenderState`、`UIRenderAssetManager`、`TextureNode`、`VideoNode`、`Effect`、`EffectManager`、`VFXEffect`、`VFXEffectEmitter`、`VFXEmitterManager`、`ParticleEmitter`、`PostProcessor`、`HWEffect`、`AutoShaderConstant`、`VertexElement`、`Parameter`、`ITextRenderer`、`BaseVertexDescription`、`RenderLayer`
- **Slice B — Map/WorldGen (~25)**:`MapComponent`、`MapComponentBase`、`MapGenSim`、`MapLayerManagerComponent`、`MapLayerRenderData`、`PathfinderComponent`、`AStarSearch<*,*>`、`Maze`、`sBuild`、`QuadTreeNode`、`MyQuadTree`、`cPrefab`(复查)、`WorldSim`、`cSpatialHash` 变体
- **Slice C — Input/Event (~40)**:`cInputKeyEvent`、`cInputEvent`、`DontStarveInputHandler`、`cLineEditor`、`WindowManager`、`cTextEditWidget`、`cTextWidget`、`cVideoWidget`、`TextEditWidgetProxy`、`TextWidgetProxy`、`VideoWidgetProxy`、`cInputGestureEvent`、`cInputMouseButtonEvent`、`cInputMouseMoveEvent`、`cFocusGainedEvent`、`cFocusLostEvent`、`WindowMoveEvent`、`ResizeEvent`、`cTogglePauseEvent`
- **Slice D — Networking/Steam (~35)**:`cShardManager`、`cShardBroadcast`、`cNatTraversal`、`cAccountManager`、`cTwitchManager`、`SteamWorkshop`、`LuaHttpQuery`、`CurlRequest`、`CurlRequestManager`、`GetURL`、`cCachedPingResults`、`cGiftingManager`、`DontStarveGameService`、`DontStarveSystemService`、`GameService`、`SystemService`、`cAccountCommunication`、`DatagramHeaderFormat`、`Socket`、`NodeAddress`
- **Slice E — 系统服务/杂项 (~30)**:`MemoryManager`、`Heap`、`Thread`、`Timer`、`Mutex`(复查)、`Semaphore`、`Process`、`ProcessId`、`FileManager`、`PersistentStorage`、`SettingFile`(精化)、`MultiFileSettings`(精化)、`Metrics`、`FrameProfiler`、`FrameProfilerSection`、`PerfIndicator`、`PerfPane`、`ProfileInfo`、`ZipSaver`、`Crc32Calculator`、`CSHA1`、`cStringBuilder`、`cReader`、`cWriter`、`cBaseFactory`、`IPCSignals`、`GoogleAnalyticsCookie`、`GoogleAnalyticsGenerator`、`MemoryCache`、`cTransformationHistory`

**并发执行协议(见下方「并发多 Agent 方案」)**

## 并发多 Agent 方案(Tier 3, 2026-08-08)

**验证结论**:子 agent 可通过 `xd://` 路由访问 ghidra-mcp + idalib-mcp 全部工具(McpProbe 实测 4/4 可调用)。

**分工原则(用户定)**:子 agent **只读调查、产出文档**;主 agent **统一回写 Ghidra**。避免回写冲突,回写串行化。

### 并行度与分片

| Slice | 子系统 | Agent 类型 |
|---|---|---|
| A | Rendering (~30) | task (只读) |
| B | Map/WorldGen (~25) | task (只读) |
| C | Input/Event (~20) | task (只读) |
| D | Networking/Steam (~20) | task (只读) |
| E | 系统服务/杂项 (~30) | task (只读) |

5 个并行只读 agent,每 agent 独立完成:调查 → IDA 交叉验证 → **产出分片报告文档**(不回写 Ghidra)。

### 并发约束(必须写入每个 agent 的 task)

1. **只读**:禁止 `create_struct`/`add_struct_field`/`delete_data_type`/`modify_struct_field`/`import_data_types` 等写入。只允许 `get_struct_layout`/`search_data_types`/`read_memory`/`decompile`/`func_query`/`server_health` 等只读调用。
2. **IDA 会话共享**:idalib-mcp 单 worker 会话 `f9cdc808`,并发 decompile 排队。每 agent 先 `server_health` 确认会话,失败则 `idb_open`。限制每类型 ≤3 次 decompile。
3. **报告文件独立**:每 agent 写 `docs/superpowers/type-recovery/tier3-<slice>.md`,禁止写其他文件。
4. **已有 struct 先验核对**:插件先验 struct 用 `get_struct_layout` 核对,一致则标注「已存在/验证通过」;不一致则在报告中列出修正字段(主 agent 回写时处理)。
5. **每类型产出**:vtable 地址 + ctor/dtor 地址 + 字段表 + 证据链 + 未知字段标 `UNKNOWN_0xXX` + 回写建议(新建/重建/跳过)。
6. **跳过**:RakNet/bt*/FMOD/eastl/std 类型(Tier 4),不投入。

### 主 agent 收尾

1. 收 5 个分片报告 → 合并 `tier3-gamestuff.md`
2. **统一回写 Ghidra**:按报告逐类型 `create_struct`(已存在且一致的跳过),每类型 `get_struct_layout` 验证
3. 更新 `evidence-chain.md` + `types_common.h`

### Task 5: 聚合与收尾

**Files:**
- Create: `docs/superpowers/../3rd/dst/game_decompiler/types_common.h`(聚合 C 头文件)
- Update: `docs/superpowers/type-recovery/evidence-chain.md`(最终索引)
- Update: 本计划末尾 spec 状态

**Acceptance:**
- [ ] 全部恢复类型按依赖顺序聚合进 `types_common.h`(基类在前)
- [ ] 头文件可被 IDA `import_data_types` 导入验证
- [ ] Ghidra 侧抽查导入或逐类型核对偏移一致
- [ ] 计划标记 Implemented;未完成类型列 residual

---

## 已知风险

| 风险 | 缓解 |
|---|---|
| 构造/析构被内联,this+off 分散 | 用 vtable 槽 + 反汇编(非反编译)收集偏移 |
| 单例模板 `cSingleton<T>` 多个实例共享布局 | 每个 T 独立定型;mInstance 只作锚点 |
| 32位 vs 64位语义偏差 | 跨版本只做语义确认,偏移不搬运 |
| Ghidra 反编译与 IDA 不一致 | 以反汇编为准,反编译作参考;冲突标 UNKNOWN |
| 恢复量大(633 占位) | Tier 4 跳过第三方;Tier 3 按需;核心只 3 个 Task |
