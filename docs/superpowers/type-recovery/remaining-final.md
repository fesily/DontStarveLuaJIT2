# 最后 50 类型恢复汇总 (2026-08-08)

> 4 个只读调查 agent(F1-F4)并行 + 主 agent 统一回写 Ghidra。
> 分片报告:remaining-f1-net.md / remaining-f2-render.md / remaining-f3-ui.md / remaining-f4-misc.md

## 恢复统计

| 分片 | 类型数 | 新建 | 跳过/已存在 |
|---|---|---|---|
| F1 网络层 | 15 | 14 | 1 (cNatTraversal 核对通过) |
| F2 渲染/场景 | 14 | 11 | 3 (GroundCreep/GroundCreepEntity/WorldSimActual 已存在) |
| F3 UI/系统 | 15 | 14 | 1 (cWorkshopModHelper 静态) |
| F4 杂项 | 9 | 6 | 3 (BugReporter 静态/GameService 接口/GetURL 等已存在) |
| **合计** | **53** | **45** | **8** |

## 关键成果

### F1 网络层
- **RakNet 基类大小铁证**:Replica3=0x158、Connection_RM3=0x2A0、NatPunchthroughClient=0x190、Lobby2=8B
- cNetworkConnection 676B(游戏仅 +0x2A0 int)、cNetworkReplica 356B(中间基类)
- cNetworkRPCManager 20B(29 RPC 槽)、cPendingConnection 112B(6 态状态机)
- cSteamAccountCommunication 284B(3×CCallback + 票证缓冲)、cSteamPunchthroughPlugin 196B(5×map)
- cSteamFriendsManager 32B(3×list<ull>)、cSteamRichPresence 84B

### F2 渲染/场景
- Buffer 12B(reader/writer 依赖接口)、cBBoxProvider 4B 接口
- cCameraInfo 192B(2×Matrix4 缓存)、cSimCamera 200B、cFreeCamera 336B(+sParams 24B + cPController×2)
- cFrameWalker 16B、RoadBuilder 44B(与 RoadManagerComponent+0xA4 闭合)
- VFXEmitterManager 4100B(512×8B 槽)、SimplexNoise 2052B、ShadowEntityComponent 28B

### F3 UI/系统
- cUIScreen 12B + cBootScreen/cGameScreen 继承
- cImageWidget/cVideoWidget 24B(双 vtable)、cTextWidget 20B、cTextEditWidget 0x422
- WindowManager 136B(vtable 修正为 0x457928)、cClientColourPicker 40B
- cConsoleInput 220B、cUnpackModThread 424B(Steam UGC 结果)
- cLuaNetworkVariable 16B、FontComponent 16B、PurchasesManagerComponent 16B

### F4 杂项
- CABody 48B(AABB + 2×TileGrid)、cDedicatedServerProcess 56B
- HttpClient2 4B(持有 CurlRequestManager*)、GameLibConfig 148B
- GameServiceImpl 308B、cPlayerSaveLocation 24B

## 重要修正

- **WindowManager vtable**:0x457C28(误,实为 RakNet Lobby2Callbacks)→ **0x457928**
- **GameService_PlayerInfo**:230B → **294B**(GameServiceImpl ctor memcpy 0x126 铁证)
- **cConsoleInput Mutex**:+0x9C → **+0xA4**(disasm 证实)
- cPController 28B 补建(cFreeCamera 依赖)

## 验证

- WindowManager 136B 抽查通过
- 依赖链闭合:cFreeCamera→cPController、RoadBuilder→RoadManagerComponent、cSteamAccountCommunication→cAccountCommunication、GameServiceImpl→PlayerInfo

## 产出

- 4 份分片报告(remaining-f1..f4-*.md)
- Ghidra 45+ struct 回写
- 剩余 50 类型全部处理完毕(新建/跳过/已存在验证)
