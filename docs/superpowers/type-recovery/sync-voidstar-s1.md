# void* 类型同步 — Slice 1 报告

日期:2026-08-12
目标文件:`3rd/dst/game_decompiler/types_common.h`(唯一写入文件;另有本报告)
Ghidra 程序:`dontstarve_steam`(i386,base 0x1000)—— `get_struct_layout` 均显式传 `program=dontstarve_steam`

## 摘要
Slice1 共 35 个 struct,对本分片全部调 `get_struct_layout` 对比:

- **更新 25 个 void* 字段 → Ghidra 具体类型**(涉及 11 个 struct)
- **保留 96 个 void* 字段**(Ghidra 本身仍为 `void*` / `byte[N]` / 泛型 `pointer`,无具体类型可同步)
- **注释 TODO 15 处**(Ghidra 有具体类型,但头文件尚未定义目标类型 → 保留 void* + `/* TODO: <Type>* */`)

所有改动只替换字段类型说明符:字段名、偏移、顺序、非 void* 字段、struct size 全部不变(与 Ghidra Layout 逐字段核对)。

## 更新的字段(25)

| Struct | 字段 | 新类型 |
|---|---|---|
| cNetworkManager | pNetworkRPCManager | `cNetworkRPCManager*` |
| cNetworkManager | pNetworkVoiceManager | `cNetworkVoiceManager*` |
| cNetworkManager | pNetworkReplicaManager | `cNetworkReplicaManager*` |
| cNetworkManager | pSteamFriendsManager | `cSteamFriendsManager*` |
| cNetworkManager | pAdditionalPlugin | `PluginInterface2*` |
| cNetworkManager | pMasterServer | `cMasterServer*` |
| cNetworkManager | pNatTraversal | `cNatTraversal*` |
| cNetworkManager | pClientColourPicker | `cClientColourPicker*` |
| cNetworkManager | pSimulation | `cSimulation*` |
| cNetworkManager | pSteamPunchthrough | `cSteamPunchthrough*` |
| cNetworkManager | pSteamRichPresence | `cSteamRichPresence*` |
| cNetworkManager | pDedicatedServerProcess1/2 | `cDedicatedServerProcess*` |
| cMasterServer | pRequest / pBroadcast | `cMasterServerRequest*` / `cMasterServerBroadcast*` |
| WorldSim | pSimThread | `SimThread*` |
| GetURL | pHttpClient2 | `HttpClient2*` |
| cMasterServerBroadcast | pMasterServer / pListing | `cMasterServer*` / `tServerListing*` |
| TDataCacheVFXParticleBufferRenderer | pOwner | `VFXParticleBufferRenderer*` |
| GraphRenderer | pGameRenderer | `GameRenderer*` |
| cUIScreen | pGame | `cGame*` |
| MapComponentBase | pMapRenderer | `MapRenderer*` |
| PerfIndicator | pGame | `cGame*` |
| HttpClient2 | pCurlRequestManager | `CurlRequestManager*` |

## TODO 注释(15,目标类型未在头文件定义 → 保留 void*)

| Struct | 字段 | TODO 类型 |
|---|---|---|
| cNetworkManager | pNetworkIDManager | `NetworkIDManager*`(RakNet) |
| cNetworkManager | pRakPeer | `RakPeerInterface*`(RakNet) |
| cNetworkManager | pDirectoryDeltaTransfer | `DirectoryDeltaTransfer*`(RakNet) |
| cNetworkManager | pFileListTransfer | `FileListTransfer*`(RakNet) |
| cNetworkManager | pIncrementalReadInterface | `IncrementalReadInterface*`(RakNet) |
| cNetworkManager | pReadyEvent | `ReadyEvent*` |
| cNetworkManager | pCheshireCat | `tCheshireCat_Network*` |
| cNetworkManager | pSnapshotManager | `SnapshotManager*` |
| cNetworkManager | pServerListingData | `ServerListingData*` |
| DontStarveInputHandler | pInputManager | `IInputManager*` |
| DontStarveInputHandler | pGameEventDispatcher | `cEventDispatcher*` |
| AStarSearch_PathNode | pParams | `PathfinderParams*` |
| BaseTexture | pMipData | `sMipDescription*` |
| RM3World | pNetworkIDManager | `NetworkIDManager*`(RakNet) |
| BinaryBufferWriter | pBuffer | `Buffer*` |

## 保留 void*(Ghidra 无具体类型,96 处)

Ghidra 字段类型仍为 `void*` / `byte[N]`(值字段、vector 三件套、list 节点)或泛型 `pointer`:

- **Ghidra 仍 void***:SettingFile(5: map 红黑树 parent/left/right + list next/prev)、ParticleBuffer(5)、cPlayerListingData(4: pRakStr + equip vector 三件套)、cGiftingManager(4: 两条 list)、Process(2: m_args list)、EnvelopeManager(3: vecEnvelopes 三件套)、cInputMouseButtonEvent(1: vptr)、cFocusGainedEvent(1: vptr)、NodeAddress(3: vector 三件套)、CacheItem(1: pData)、RenderTarget(1: vptr)、MiniMapComponent(4: vtable2 + map 节点)、SimplexNoise(1: vptr)、RoadBuilder(1: vptr)、PurchasesManagerComponent(1: vptr)、cNetworkManager(30: 接口 vtables、字符串指针、vector/list 容器、pVtableObject 等)
- **泛型 `pointer`(非具体类型)**:sAnim(pParent/pFrames/name 3 处)——非 void* 亦非具体类型,保持不动
- **Ghidra 为 `byte[N]` 非指针**:VideoNode.pSizeXY(Ghidra 为 byte[8],头文件以 void* + flSize[8] 表达且总尺寸 0x114 一致)——保持,避免改尺寸
- **头文件已类型化,无需改**:TDataCacheVideoNode.pOwner(`VideoNode*`)、cNetworkVoiceManager.pBitStream(`BitStream*`)

## 验证
- 逐字段与 get_struct_layout 输出比对;类型替换后 struct size 不变(头文件尾部 total 注释与 Ghidra Size 一致)
- `grep 'void\*'` 文件级计数与改动前 605(分片前快照)方向一致减少(`[INFERENCE]`:并发分片同时改写,文件级计数随其他分片持续变动,本分片自身 25 处已确认)
- 花括号平衡 277/277,块注释成对(本分片新增 15 处 `/* TODO: … */`,与先前分片既有约定一致)
- 只改了 `types_common.h` 与本报告

## 并发说明
其他 void* 同步分片(Slice 2+)在同一会话内并行改写同一头文件(不同 struct 集合,无重叠)。本分片字段在并发运行中复查:25 处类型 + 15 处 TODO 全部完整,未被覆盖。