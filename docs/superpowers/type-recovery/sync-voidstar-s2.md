# sync-voidstar-s2 — Slice2 void* → Ghidra 类型同步 (2026-08-12)

- program: `dontstarve_steam` (macOS i386, x86:LE:32)
- 目标文件: `3rd/dst/game_decompiler/types_common.h`(仅此文件)
- 分片: Slice2(37 struct,由主 agent 分配的 cEntityManager…FileSystem 清单)
- 方法: 逐 struct 调 `get_struct_layout` 取 Ghidra 当前布局 → 对比头文件 void* 字段 → 更新为目标类型
- 规则:
  - `X *` → `X*`;目标类型必须在头文件已定义,否则保留 `void*` + `/* TODO: X* */`
  - vector 三件套 / vtable / RB-tree 节点 / pad 保留 void*;不重排字段
  - Ghidra `pointer`/`dword`(未定型)= 无证据,保留 void*

## 统计

| 类别 | 数量 |
|---|---|
| 分片 struct 数 | 37 |
| 已定义类型 → 直接改写 | 12 字段 |
| 未定义类型 → void* + TODO | 7 字段 |
| Ghidra 仍 void*/未定型 → 保留 | 其余 |

## 改写字段(12)

| struct | 字段 | Ghidra 类型 | 改写后 |
|---|---|---|---|
| cEntityManager | pComponentFactory | cBaseFactory * | `cBaseFactory*` |
| NetworkIDObject | pParent | NetworkIDObject * | `NetworkIDObject*` |
| NetworkIDObject | pNextInstanceForNetworkIDManager | NetworkIDObject * | `NetworkIDObject*` |
| PerfPane | pGame | cGame * | `cGame*` |
| cDontStarveGame | pBootScreen | cBootScreen * | `cBootScreen*` |
| cDontStarveGame | pGameScreen | cGameScreen * | `cGameScreen*` |
| LastSerializationResult | pReplica | Replica3 * | `Replica3*` |
| LastSerializationResult | pLastSerializationResultBS | LastSerializationResultBS * | `LastSerializationResultBS*` |
| cSimCamera | pSimulation | cSimulation * | `cSimulation*` |
| TDataCacheSceneNode | pOwner | SceneGraphNode * | `SceneGraphNode*` |
| cPendingConnection | pServerListing | tServerListing * | `tServerListing*` |
| cTransformationHistory | pBuffer | cTransformationHistoryCell * | `cTransformationHistoryCell*` |

## 保留 void* + TODO(7,目标类型未在头文件定义)

| struct | 字段 | Ghidra 类型 |
|---|---|---|
| cEntityManager | pSpatialHash | cSpatialHash_cEntity * |
| NetworkIDObject | pNetworkIDManager | NetworkIDManager * |
| PluginInterface2 | pRakPeerInterface | RakPeerInterface * |
| PluginInterface2 | pTcpInterface | TCPInterface * |
| cTwitchManager | pCheshireCat | tCheshireCat_Twitch * |
| Semaphore | pSem | SDL_sem * |
| cUnpackModThread | pWorkshop | SteamWorkshop * |

## 保留 void*(Ghidra 仍 void*/pointer/dword,无证据)

- sBuild: pParent/pTexturesVec*/pTextureHandles*/pSymbols/pSymbolFrames/pVertexData*(Ghidra 全 `pointer` 未定型)
- TDataCacheRoadManagerNode: pVtable/pOwner/pStripData*/pAABB*(pRenderer 已是 GameRenderer*)
- TDataCacheParticleBufferRenderer: pData0..4(pOwner/pEmitter 已是具体类型)
- SceneGraphNode: vtable/pChildren_begin/end/pGame/pParentNode(Ghidra `pointer`)
- MultiFileSettings: pParent/pLeft/pRight(RB-tree 头)
- FileOpRequest: pVtable/pContext/pData
- cNetworkLuaProxy: pNetworkContext
- cWriter: m_buffer[3](vector)
- WorkingVB: pVertexData[4]/pCurVertex[4]
- TDataCacheWorld / TDataCacheMiniMapComponent: pOwner
- GrowableBinaryBufferWriter: pVec
- cDontStarveSettings: pVtable
- cInputMouseMoveEvent / cFocusLostEvent: vptr
- Maze: points[3]
- cStringBuilder: pBuffer/pWritePtr 已是 char*
- CSHA1: pWorkspace
- HWRenderTarget: pVtable
- cSimTime: pVtable
- TwitchComponent: pVtable2/pMap_parent/left/right
- cSteamFriendsManager: pVtable
- cSoundEmitterComponent: pEvents_begin
- FileSystem: pVtable

## 附带:新增前置声明

保持头文件可解析(目标类型定义在后,按既有 `struct ParticleBuffer;` 模式):

```
struct Replica3;
struct LastSerializationResultBS;
struct tServerListing;
struct cBootScreen;
struct cGameScreen;
```

## 验证

- 字段名/偏移/顺序/size 未变:改写仅替换类型 token,布局来自 Ghidra 原样
- 目标类型全部在头文件已有定义(见上表),无 `-BAD-` 情况
- 只修改了 `types_common.h` 一个文件
