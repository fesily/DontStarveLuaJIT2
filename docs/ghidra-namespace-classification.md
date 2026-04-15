# Ghidra Namespace Classification — dontstarve_steam
> **二进制**: `dontstarve_steam` (macOS 32-bit, 带完整函数符号)
> **总函数数**: 23,326
> **分类日期**: 2026-04
---
## 概览
| 类别 | 函数数 | 占比 |
|------|--------|------|
| 游戏引擎 (有命名空间) | 9,368 | 40.2% |
| 第三方库 (有命名空间) | 7,648 | 32.8% |
| 全局函数 → 已分类 | 2,470 | 10.6% |
| 全局函数 → 未命名 FUN_* | 285 | 1.2% |
| 其他 (含编译器生成) | ~3,555 | 15.2% |
**全局函数清理**: 原始 2,755 个全局函数，经 4 轮分类后剩余 285 个未命名 FUN_*。
---
## 一、第三方库命名空间
### 1.1 已有命名空间 (分析前已存在)
| 命名空间 | 描述 | 函数数(估) |
|----------|------|-----------|
| `RakNet` | 网络库 (含 DataStructures, Lobby2, Clans 等子空间) | ~3,000 |
| `bt*` / Bullet | 物理引擎 (btCollisionWorld, btRigidBody, btDbvt 等80+类) | ~2,000 |
| `FMOD` | 音频引擎 | ~500 |
| `Steam*` / `CCallback` | Steam API | ~300 |
| `boost::*` | Boost 库模板实例化 | ~200 |
| `eastl` | EA STL | ~100 |
| `CSHA1` | SHA1 哈希 | ~10 |
| `CSimpleIniTempl` | INI 解析 | ~30 |
| `rapidxml` | XML 解析 | ~30 |
| `fastdelegate` | 委托模式 | ~20 |
| `GoogleAnalytics*` | Google Analytics | ~20 |
| `_Rb_tree` / STL | STL 模板实例化 (50+ 种) | ~500 |
### 1.2 Phase 1-3 创建的库命名空间 (从全局函数移入)
| 命名空间 | 函数数 | 来源 |
|----------|--------|------|
| `lua51` | ~559 | Lua 5.1 完整虚拟机 (C API, 辅助库, 标准库, 编译器, GC, 解析器) |
| `cxx_runtime` | ~532 | C++ 运行时 + C 标准库 + POSIX + macOS 系统调用 thunks |
| `vorbis` | ~161 | Vorbis 音频编解码 (含 MDCT, PSY, codebook 内部函数) |
| `jansson` | ~135 | JSON 解析库 (含 hashtable, strbuffer, lexer, parser) |
| `libzip` | ~124 | ZIP 文件库 |
| `theora` | ~110 | Theora 视频编解码 |
| `RakNet` (追加) | ~105 | RakNet 全局辅助函数 (MT随机数, SuperFastHash, 内存分配器等) |
| `btBulletPhysics` | ~89 | Bullet 全局辅助函数 |
| `zlib` | ~75 | zlib 压缩库 (含 inflate/deflate 内部函数) |
| `ogg` | 73 | OGG 容器格式 |
| `miniupnpc` | ~57 | UPnP 客户端 (含 XML 解析, SOAP, IGD) |
| `minizip` | ~50 | minizip (unzip/zip 文件操作) |
| `sdl2` | 44 | SDL 2.0 thunks |
| `opengl` | 30 | OpenGL 函数 thunks |
| `theoraplay` | ~21 | THEORAPLAY 视频播放 (帧转换, 工作线程) |
| `SteamAPI` (追加) | 19 | Steam API thunks |
| `curl` | 16 | libcurl HTTP 客户端 thunks |
| `twitch` | 16 | Twitch SDK (_TTV_*) thunks |
| `glew` | 10 | GLEW OpenGL 扩展加载 |
| `base64` | 5 | Base64 编解码 |
| `FMOD` (追加) | 1 | FMOD thunk |
---
## 二、游戏引擎命名空间
### 2.1 核心框架类
| 类 / 命名空间 | 描述 | 关键成员 |
|---------------|------|----------|
| `cApplication` | 应用程序基类 | 主循环, 初始化, 关闭 |
| `cDontStarveGame` | 游戏主类 (继承 cApplication) | 游戏逻辑入口 |
| `cEntity` | 实体基类 | 组件容器, Transform, 生命周期 |
| `cEntityComponent` | 组件基类 | 虚函数接口 |
| `cEntityManager` | 实体管理器 | 创建/销毁/查找实体 |
| `GameService` | 游戏服务基类 | |
| `DontStarveGameService` | DS 游戏服务 | |
| `DontStarveSystemService` | 系统服务 | |
| `DontStarveInputHandler` | 输入处理 | |
### 2.2 实体组件 (ECS 架构)
| 组件类 | 功能 |
|--------|------|
| `cAnimStateComponent` / `AnimStateComponent` | 动画状态机 |
| `cTransformComponent` | 空间变换 |
| `cPhysicsComponent` | 物理 |
| `cNetworkComponent` | 网络同步 |
| `cLightEmitterComponent` / `cLightWatcherComponent` | 光照 |
| `cSoundEmitterComponent` | 音效 |
| `cShardClientComponent` / `cShardNetworkComponent` | 分片网络 |
| `MapComponent` / `MapComponentBase` | 地图 |
| `MiniMapComponent` / `MiniMapEntityComponent` | 小地图 |
| `PathfinderComponent` | 寻路 |
| `PostProcessorComponent` | 后处理 |
| `GraphicsOptionsComponent` | 图形选项 |
| `AccountManagerComponent` | 账号管理 |
| `PurchasesManagerComponent` | 购买管理 |
| `TwitchComponent` | Twitch 集成 |
| `WaveComponent` | 波浪效果 |
| `EnvelopeComponent` | 包络线 |
| `FollowerComponent` | 跟随 |
| `FontComponent` | 字体 |
| `DebugRenderComponent` | 调试渲染 |
| `DynamicShadowComponent` / `StaticShadowComponent` | 阴影 |
| `ShadowManagerComponent` / `ShadowEntityComponent` | 阴影管理 |
| `MapLayerManagerComponent` | 地图图层 |
| `RoadManagerComponent` | 道路管理 |
| `GroundCreep` / `GroundCreepEntity` | 地面蔓延 |
| `ParticleEmitter` | 粒子发射 |
| `VFXEffect` | 视觉效果 |
### 2.3 Lua 代理系统
| 类 | 描述 |
|----|------|
| `EntityLuaProxy` | 实体 Lua 代理 |
| `SimLuaProxy` | 模拟器代理 |
| `SystemServiceLuaProxy` | 系统服务代理 |
| `LuaProxy` | 代理基类 |
| `ComponentLuaProxy<T,Proxy>` | 组件代理模板 (~30 实例化) |
| `Lunar<T>` | Lua 类型注册 (~50 实例化) |
### 2.4 渲染系统
| 类 | 描述 |
|----|------|
| `BaseRenderer` / `Renderer` | 渲染器基类 |
| `HWRenderer` | 硬件渲染器 |
| `GameRenderer` | 游戏渲染器 |
| `Batcher` | 批次处理 |
| `Effect` / `EffectManager` | 效果 / 效果管理 |
| `Shader` / `PixelShader` / `VertexShader` | 着色器 |
| `ShaderConstantSet` / `ShaderParameterData` | 着色器参数 |
| `Texture` / `TextureManager` | 纹理 / 纹理管理 |
| `RenderTarget` / `RenderTargetManager` | 渲染目标 |
| `RenderSettings` / `RenderState` | 渲染状态 |
| `IndexBuffer` / `VertexBuffer` (+Manager) | 缓冲区 |
| `VertexDescription` / `VertexDescriptionManager` / `HWVertexDescription` | 顶点描述 |
| `LightBuffer` | 光照缓冲 |
| `PostProcessor` | 后处理器 |
| `WallStencilBuffer` | 墙壁模板缓冲 |
| `SceneGraphNode` | 场景图节点 |
| `Region` / `UndergroundRegion` | 区域 |
| `MapRenderer` / `MiniMapRenderer` / `ShadowRenderer` | 专用渲染器 |
| `AnimNode` / `ImageNode` / `TextNode` / `VideoNode` | 渲染节点 |
| `Atlas` / `BitmapFont` / `Glyph` | 图集 / 位图字体 |
| `ParticleBuffer` / `ParticleBufferRenderer` | 粒子缓冲 |
| `TDataCache*` | 数据缓存 (~20 种) |
| `FrameDelayedResourceManager<T>` | 帧延迟资源管理 |
### 2.5 地图 / 世界生成
| 类 | 描述 |
|----|------|
| `MapComponent` / `MapComponentBase` | 地图组件 |
| `MapCell` / `MapCorner` | 地图单元 |
| `MapGenSim` | 地图生成模拟 |
| `MapLayerRenderData` | 图层渲染数据 |
| `Maze` | 迷宫生成 |
| `TileGrid` | 瓦片网格 |
| `VoronoiMap` | Voronoi 地图 |
| `QuadTreeNode` | 四叉树 |
| `WorldGen` / `WorldSim` / `WorldSimActual` | 世界生成/模拟 |
### 2.6 网络
| 类 | 描述 |
|----|------|
| `Connection_RM3` | RM3 连接 |
| `NetworkIDManager` / `NetworkIDObject` | 网络ID管理 |
| `NetworkSerializationHelper` | 序列化辅助 |
| `NetworkUtils` | 网络工具 |
| `SnapshotManager` | 快照管理 |
| `ClientThread` | 客户端线程 |
### 2.7 数据 / IO
| 类 | 描述 |
|----|------|
| `BinaryBufferReader` / `BinaryBufferWriter` | 二进制缓冲读写 |
| `EndianSwappedBinaryBufferReader` | 大小端转换读取 |
| `GrowableBinaryBufferWriter` | 可增长缓冲写入 |
| `Buffer` / `ByteQueue` / `CommandBuffer` | 缓冲区 |
| `MemoryBlock` / `MemoryCache` / `MemoryManager` | 内存管理 |
| `KleiFile` / `FileHandle` | 文件 |
| `FileManager` / `FileSystem` / `LocalFileSystem` / `ZipFileSystem` | 文件系统 |
| `FileUtil` / `DirectoryUtils` / `PersistentStorage` | 文件工具 |
| `ZipSaver` | ZIP 保存 |
### 2.8 输入
| 类 | 描述 |
|----|------|
| `ControlMapper` | 控制映射 |
| `DigitalControl` / `DigitalInput` / `DirectionalInput` | 输入抽象 |
| `SteamInputDevice` | Steam 手柄 |
### 2.9 线程
| 类 | 描述 |
|----|------|
| `Thread` / `SimThread` | 线程基类 |
| `JobThread<ThreadPhysics/Render/Update>` | 工作线程 |
| `CriticalRegion` / `CriticalSection` / `Mutex` / `Semaphore` / `SimpleMutex` | 同步原语 |
| `SignaledEvent` | 信号事件 |
### 2.10 对象池
| 池模板 | 管理对象 |
|--------|----------|
| `Pool<cEntity,FakeLock>` | 实体池 |
| `Pool<cAnimStateComponent,FakeLock>` | 动画组件池 |
| `Pool<cTransformComponent,FakeLock>` | 变换组件池 |
| `Pool<cPhysicsComponent,FakeLock>` | 物理组件池 |
| `Pool<cNetworkComponent,FakeLock>` | 网络组件池 |
| `Pool<KleiFile::FileHandle,FakeLock>` | 文件句柄池 |
| ... | (~30 种组件池) |
### 2.11 其他游戏类
| 类 | 描述 |
|----|------|
| `Colour` | 颜色 |
| `TagSet` | 标签集 |
| `Timer` | 计时器 |
| `ModInfo` | Mod 信息 |
| `Permission` | 权限 |
| `EnvelopeManager` / `EnvelopeTemplate<T>` | 包络线管理 |
| `CurlRequest` / `CurlRequestManager` | HTTP 请求 |
| `LuaHttpQuery` | Lua HTTP 查询 |
| `Inventory` | 库存 |
| `MOTDImageLoader` | 每日消息图片 |
| `PerfIndicator` / `PerfPane` | 性能指示器 |
| `Vibration` / `Vibrator` | 振动反馈 |
---
## 三、Phase 4 创建的游戏功能命名空间 (全局函数分类)
| 命名空间 | 函数数 | 代表函数 |
|----------|--------|----------|
| `LuaIntegration` | 38 | HandleLuaError, DoLuaFile, kleiloadlua, FormatStackTrace, luautf8*, PerlinLua |
| `WorldGen` | 39 | RunAiLife, convex_hull, RunDFS, RunGrowingTree, CleanTileMap, SetTileType |
| `KleiMath` | 29 | Build*Matrix (15种), sdnoise1-4, operator*, DistanceSq, lerp, fade |
| `Terrain` | 22 | InitializeMaskIndexMap, GetTileMask, UpdateTile, BuildRegionVB, DoMarch |
| `Rendering` | 20 | DrawQuad, GetLight, PointInTriStrip/List, CheckGLError, GetHWPixelFormat |
| `FileSystem` | 17 | GetUserHomeDir, GetDonotStarveDir, GetSaveDir, TruePath, fopen_UNICODE |
| `TwitchIntegration` | 12 | ChatStatusCallback 等6种回调, TwitchVerify, LoginCallback |
| `GameApp` | 11 | entry, Main, _main, InitSteam, ShutdownSteam, terminateSignalHandler |
| `Inventory` | 10 | PushItemIDString, WriteItemListing, HashMultiplicative, IsOpened/IsUnopened |
| `AudioSystem` | 9 | ERRCHECK, PrintGroupInfo, yield, IoFopenRead/Close, MovieAudioStream* |
| `GameUtil` | 9 | FileExists, LogError, CacheRenderAllocate, AssertFunc, ReadZippedFile |
| `NetworkUtil` | 8 | SanitizeString, CheckNetworkEntity, PushSnapshotsTable, Serialize/Deserialize* |
| `TextUtil` | 5 | ParseUnicodeCharacter, GetFEButtonTokenMap, matches, ischarspace |
| `Pathfinding` | 4 | FindTargetNodes, get_vertex, DrawPathThroughNode, DrawNodeInternalPath |
| `UPnPWrapper` | 4 | UPNPOpenWorker, UPNPOpenAsynch, UPNPProgressCallback, UPNPResultCallback |
| `PhysicsCallbacks` | 1 | myContactProcessedCallback_Threaded |
---
## 四、未分类函数
| 类别 | 数量 | 说明 |
|------|------|------|
| `FUN_*` 未命名 | 285 | 编译器生成或缺少符号的函数, 散布于各地址段 |
| `__GLOBAL__I_a` | ~120 | C++ 静态初始化器 |
| `___cxx_global_*` | ~若干 | C++ 全局析构 |
### FUN_* 地址分布 (供后续分析参考)
| 地址范围 | 数量(估) | 可能归属 |
|----------|---------|----------|
| 0x000-0x00F | ~80 | 游戏核心 |
| 0x01C-0x01D | ~15 | 渲染 |
| 0x0202-0x020B | ~97 | 世界生成 (瓦片模板, 间距 ~0xB0) |
| 0x025 | ~6 | 文件系统 |
| 0x026-0x027 | ~6 | 工具函数 |
| 0x02F | ~3 | 寻路 |
| 其他 | ~78 | 散布 |
---
## 五、核心类型内存分析准备
### 当前状态
所有游戏结构体类型 (cEntity, cEntityComponent, cApplication 等) 目前在 Ghidra 中均为 **Size: 1 的占位符** (Demangler 自动创建)。尚无任何字段布局被逆向。
### 优先分析目标
#### Tier 1 — 核心基础类型 (影响所有其他类型的理解)
1. **`cEntity`** — 实体基类, ECS 核心
   - 包含组件列表、Transform、标签等
   - 所有游戏对象的基础
   - Pool\<cEntity\> 可提供对象大小线索
2. **`cEntityComponent`** — 组件基类
   - 虚函数表 (vtable) 分析关键
   - 组件注册/生命周期接口
3. **`cApplication`** / **`cDontStarveGame`** — 应用主类
   - 包含全局管理器引用
   - 主循环结构
4. **`cEntityManager`** — 实体管理器
   - 实体创建/查找接口
   - 实体存储结构
#### Tier 2 — 高频组件
5. **`cTransformComponent`** — 空间变换 (位置/旋转/缩放)
6. **`cAnimStateComponent`** — 动画状态机
7. **`cPhysicsComponent`** — 物理
8. **`cNetworkComponent`** — 网络同步 (DST 核心)
9. **`cLightEmitterComponent`** — 光照
#### Tier 3 — 关键子系统
10. **`Renderer`** / **`HWRenderer`** — 渲染器
11. **`Batcher`** — 批次处理
12. **`MapComponent`** / **`TileGrid`** — 地图
13. **`Pool<T,FakeLock>`** — 对象池 (可推断对象大小)
### 分析方法
1. **从构造函数入手**: 构造函数中的 memset/字段初始化可揭示结构体大小和字段偏移
2. **vtable 分析**: 虚函数表可确定虚函数数量和继承关系
3. **Pool 分析**: Pool 模板的 slab 大小参数可揭示精确对象大小
4. **交叉引用二进制**: 使用 macOS 带符号二进制做参考, 服务器带符号二进制有部分内存布局
5. **Lua 代理分析**: ComponentLuaProxy 注册的方法名可帮助理解组件接口