# 剩余 50 类型分批恢复计划

> 背景:633 占位类型中,已恢复 ~250 + Tier4 第三方跳过 235 + LuaProxy 子类(继承基类)35 + 枚举/静态/抽象 55 + 事件类 10 已分类。**真正未建 50 个**,本计划分批处理。
> 方法:沿用验证过的模式 — 只读调查 agent 分片 + 主 agent 统一回写 Ghidra + review。

## 类型清单(50)

### 分片 1 — 网络层(12)
`cNetworkConnection`、`cNetworkReplica`、`cNetworkRPCManager`、`cNetworkTileRegion`、`cNetworkVoiceManager`、`cNetworkClientObject2`、`cNetworkFileTransferCB`、`cPendingConnection`、`cNatTraversal`(+`cNatPunchthroughDebugInterfaceImpl`)、`cSteamAccountCommunication`、`cSteamPunchthrough`(+`cSteamPunchthroughPlugin`)、`cSteamFriendsManager`、`cSteamRichPresence`

### 分片 2 — 渲染/场景(12)
`Buffer`、`cBBoxProvider`、`cCameraInfo`、`cSimCamera`、`cFreeCamera`(+`sParams`)、`cFrameWalker`、`RoadBuilder`、`VFXEmitterManager`、`ShadowEntityComponent`、`GroundCreep`(+`GroundCreepEntity`)、`SimplexNoise`、`WorldSimActual`

### 分片 3 — UI/系统(14)
`cBootScreen`、`cGameScreen`、`cUIScreen`、`cConsoleInput`、`cImageWidget`、`cTextWidget`、`cTextEditWidget`、`cVideoWidget`、`WindowManager`、`cClientColourPicker`、`FontComponent`、`PurchasesManagerComponent`、`cLuaNetworkVariable`、`cUnpackModThread`、`cWorkshopModHelper`

### 分片 4 — 杂项(12)
`BugReporter`、`CABody`、`cDedicatedServerProcess`、`cPController`、`HttpClient2`、`GameLibConfig`、`GameService`(具体子类 `GameServiceImpl`)、`cPlayerSaveLocation`

## 执行方式

| 阶段 | 内容 | 工具 |
|---|---|---|
| 1. 调查 | 4 个只读 agent(每分片 1 个)反编译 ctor/dtor 定型字段 | ghidra-mcp + idalib-mcp 只读 |
| 2. 回写 | 主 agent 按报告 `create_struct` 统一写入 Ghidra | create_struct/add_struct_field |
| 3. 验证 | `get_struct_layout` 抽查关键类型 + 与报告比对 | get_struct_layout |
| 4. 文档 | 汇总 `remaining-final.md` + 更新 types_common.h | — |

## 约束

- 只读 agent 禁止写入;报告写 `remaining-f<slice>.md`
- 每类型 decompile ≤2 次(IDA 共享会话)
- 已有 struct 用 `get_struct_layout` 核对,一致标「已存在」跳过
- Tier 4 第三方(RakNet 基类等)跳过,只恢复游戏自有部分
- 事件类/枚举类(cNetworkDisconnectEvent 等)已验证分类,无需 struct

## 验收

- 50 个类型全部回写或明确标注跳过原因
- 关键类型(WindowManager、cTextWidget、GroundCreep、cNetworkConnection)抽查布局正确
- `remaining-final.md` + types_common.h 更新
