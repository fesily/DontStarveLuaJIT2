# 剩余引擎类型恢复汇总 (2026-08-08)

> 5 个只读调查 agent(A-E)并行调查 + 主 agent 统一回写 Ghidra。
> 分片报告:remaining-a-render.md / remaining-b-input.md / remaining-c-kleifile.md / remaining-d-nested.md / remaining-e-tdatacache.md

## 恢复统计(107 类型)

| 分片 | 类型数 | 新建 | 已存在验证 | 跳过 |
|---|---|---|---|---|
| A Rendering | 30 | 27 | 1 (Renderer) | 2 (Parameter/VertexElement 枚举) |
| B Input | 17 | 16 | 0 | 1 (Input 命名空间) |
| C KleiFile | 17 | 13 | 2 (cReader/cWriter) | 2 (KleiFile/FileUtil/DirectoryUtils 静态) |
| D Nested | 20 | 20 | 0 | 0 |
| E TDataCache | 24 | 22 | 2 (TDataCacheAnimNode/SceneGraphNode) | 0 |
| **合计** | **108** | **98** | **5** | **5** |

## 关键成果

### A — Rendering(渲染内部类)
- **Renderer 家族布局**:cGame+0x30 = Renderer;Renderer+0x184..0x1A0 = 7 个管理器(ShaderConstantSet/Texture/VertexDesc/VertexBuffer/IndexBuffer/Effect/RenderTarget)
- HWBuffer 20B(VertexBuffer/IndexBuffer 基类)、Texture/HWTexture 40B(BaseTexture 基类)
- 场景图渲染器:ShadowRenderer 168B、GraphRenderer 88B、DebugRenderer 88B、MiniMapRenderer 228B、MapRenderer 28B
- 管理器:Index/Vertex/Texture/VertexDescription 均 148B(FrameDelayed 模板)

### B — Input 子系统
- **Input 是命名空间**(非类型);cGame+0x40 = SDLInputManager
- IInputDevice 1292B(基类,含 2×InputMapping 616B + Vibrator)
- SDLInputManager 2928B(Thread 基类 + 32 设备槽)
- KeyboardMouseDevice 1840B、SDLInputDevice 1500B、SteamInputDevice 1356B

### C — KleiFile 文件系统
- FileHandle 344B(Pool::sChunk new(0x158) 铁证)
- FileSystem 272B 抽象基类 + LocalFS/ZipFS 276B
- MemoryCache 20B(注意与已有 24B map 头 /MemoryCache 命名冲突)
- BinaryBufferReader/Writer + Growable/EndianSwapped 变体

### D — 嵌套子类型
- 3 个 tCheshireCat pimpl:Shard 64B / Network 352B / Twitch 1416B
- tServerListing 268B(13 string + 3 cNetID2)
- GameService PlayerId/AchievementId 36B、PlayerInfo 294B
- FileOpRequest 324B / FileOpResult 328B
- ControlMapper 516B、cMasterServerBroadcast 88B

### E — TDataCache 场景图缓存
- 公共头:vtable@0 + pOwner@4 + Matrix4@8(72B)
- TDataCacheGameRender 1264B、TDataCacheWorld 952B
- ImageNode 260B、TileGrid 28B、MyMotionState 80B、EnvelopeTemplate 16B
- 验证通过:TDataCacheAnimNode 248B、SceneGraphNode 145B

## 重要修正

- **RakNet::SystemAddress = 0x14(20B)** 非 tier3-d 记录的 24B(tCheshireCat 偏移闭合证明)
- KleiFile::MemoryCache 与 /MemoryCache(24B map 头)是**两个不同类型**,名字撞车
- Renderer 字段更名建议:dwField_194→pVertexBufferMgr、dwField_198→pIndexBufferMgr、dwResManager→pTextureManager、dwField_19C→pEffectMgr、dwField_1A0→pRenderTargetMgr

## 产出

- 5 份分片报告(remaining-a..e-*.md)
- Ghidra 98+ struct 回写
- types_common.h 待同步
