# Tier 3 — 游戏功能类型恢复报告(聚合)

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 执行:5 个并行只读调查 agent(Slice A-E)+ 主 agent 统一回写 Ghidra
> 分片报告:`tier3-a-rendering.md` / `tier3-b-map.md` / `tier3-c-input.md` / `tier3-d-network.md` / `tier3-e-system.md`

## 关键全局发现(跨分片)

1. **std::string = 4B 旧 ABI**(refcounted, `_S_empty_rep_storage+12` 表示空串)— 所有字符串字段按 4B 计,解决全部偏移歧义
2. **std::_Rb_tree 头 = 24B**(非 20B):`pad@0, color@4, parent@8, left@0xC, right@0x10, count@0x14` — 修正 MultiFileSettings 20B→24B、cDontStarveSettings 24B→28B
3. **容器判定规则**:map = `*(X+8)=*(X+12)=&this+X`;list = `*X=*(X+4)=&this+X`
4. **事件公共基类 = cGameEvent**(8B, 非 cInputEvent):`vptr@0, eGameEventType@4`
5. **LuaProxy 家族**:ComponentLuaProxy<T,P> 20B 模板(见 Tier 1);独立 LuaProxy(cNetworkLuaProxy/cShardLuaProxy)另行布局

## 回写统计

| 分片 | 类型数 | 新建 | 重建 | 验证通过 | 跳过 |
|---|---|---|---|---|---|
| A Rendering | 31 | 24 | 0 | 4 (Batcher/RenderState/UIRenderAssetManager/AutoShaderConstant) | 3 (TextureNode 不存在/枚举) |
| B Map | 20 | 17 | 1 (cPrefab) | 2 (sBuild/WorldSim) | 0 |
| C Input | 20 | 20 | 0 | 0 | 0 |
| D Network | 23 | 20 | 0 | 0 | 3 (GameService/SystemService 接口) |
| E System | 31 | 26 | 2 (SettingFile/MultiFileSettings) | 2 (cTransformationHistory/Cell) | 1 (MemoryManager 静态) |
| **合计** | **125** | **107** | **3** | **8** | **7** |

## 重要修正(相对 Tier 0-2 文档)

| 项 | 旧值 | 新值 | 证据 |
|---|---|---|---|
| cPrefab 布局 | nameHash@0x00 | **name@0x00, nameHash@0x08** | ctor 0xf5bf6 反汇编 + AddPrefab/AddAsset/AddDep |
| MultiFileSettings | 20B | **24B** | dtor 0x2850BC count@0x14 |
| cDontStarveSettings | 24B | **28B** | 连带修正 |
| SettingFile | 两 RBTree 头 | **CSimpleIniTempl 包装**(map@0x0C + list@0x24 + 配置字节 + 文件名@0x34) | ctor 0x285844 双源验证 |
| cInputEvent 基类 | 存在 | **不存在**(公共基类 cGameEvent 8B) | DispatchEvent 0xd810 |

## 分片摘要

### A — Rendering (31 类型)
- **cResourceManager<T,uint,FakeLock> 基类**(≈60B)是 BitmapFontManager/AtlasManager/FileManager 等管理器共享布局
- **FrameDelayedResourceManager<T>** = cResourceManager + CS@0x40 + vec@0x78 + pRenderer@0x90 = 148B(RenderTargetManager/EffectManager)
- 关键子类型:Glyph 32B、WorkingVB 64B、Attribute 12B、Region 24B、Shader 24B、HWEffect 160B、Effect 164B
- 已验证:Batcher 68B、RenderState 372B、UIRenderAssetManager 32B、AutoShaderConstant 9B
- TextureNode 二进制中不存在(服务器构建已移除)

### B — Map/WorldGen (20 类型)
- MapComponentBase 304B + MapComponent 400B(继承链)
- MapGenSim 92B(Pool 分块 0x5C 证实)、PathfinderComponent 104B + PathSearchRecord 144B
- AStarSearch 两个变体各 52B + sNode 24B/16B
- **cPrefab 重建**(字段归属修正,见上)
- 已验证:sBuild 76B、WorldSim 16B

### C — Input/Event (20 类型)
- 8 个事件类(cInputKeyEvent 0x10、MouseButton 0x18、MouseMove 0x10、Gesture 0x0C、Text 0x14、TogglePause 0x0C、FocusGained/Lost 0x08)+ WindowMove/Resize 0x10
- DontStarveInputHandler 720B(ControlMapper 516B + Control 16B 嵌套)
- cLineEditor 0x404(内联 0x3E8 缓冲)、WindowManager ≥0x88
- 事件 vtable 约定:对象 vptr = vtable_start+8

### D — Networking/Steam (23 类型)
- cShardManager 168B + tCheshireCat 64B、cShardBroadcast 4B、cAccountManager 80B、cTwitchManager 40B
- SteamWorkshop 456B(6×CCallResult 32B)、LuaHttpQuery 32B、CurlRequest 54B、CurlRequestManager 8B、GetURL 8B
- cNetworkLuaProxy 32B(独立 LuaProxy)、cShardLuaProxy 4B
- GameService/SystemService = 空接口(具体布局在 DontStarve* 子类)
- std::string 4B 旧 ABI 确认(解决全部字符串偏移)

### E — System (31 类型)
- Thread 248B(JobThread 派生 0x102)、Timer 8B、Semaphore 4B、Process 32B、ProcessId 4B
- Heap 92B + MemoryBlock、FrameProfiler 36B、PerfIndicator 1048B、PerfPane 64B
- Metrics 52B、MemoryCache 24B + CacheItem 272B、CSHA1 196B
- cStringBuilder 32B、cReader 20B、cWriter 16B、cBaseFactory 60B、IPCSignals 56B
- SettingFile/MultiFileSettings 精化(见上)
- MemoryManager = 纯静态(3 堆, stride 0x5C)

## 遗留 / 低置信

- 各分片报告尾部 UNKNOWN 标注(见各文件)
- cNetworkLuaProxy +0x08 容器语义、tClientProxy list 位置、cAccountManager vtable 槽2 不可读
- MapComponent +0x184/+0x188、PathfinderComponent map 键值语义
- RenderLayer::Type 枚举值、VertexElement/Parameter 枚举
- AstarParams boost 内部(Tier 4)
- 各事件类 vtable 槽异常(cInputMouseMoveEvent 指向常量池字符串)
