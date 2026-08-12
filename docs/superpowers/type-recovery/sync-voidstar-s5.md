# Slice5 void* 同步 — sync-voidstar-s5.md (2026-08-12)

同步目标:`3rd/dst/game_decompiler/types_common.h` 中 Slice5 struct 的 `void*` 字段
→ Ghidra(`dontstarve_steam`, i386, base 0x1000)`get_struct_layout` 实际类型。
只改 types_common.h;保留字段名/偏移/顺序/size,不重排;vector 三件套 / rb-tree 头 / vtable 保持 `void*`。

## 已确定并回写(19 字段 / 13 struct)

| Struct | 字段 | 旧 | Ghidra 类型(新) | 目标类型已定义(line) |
|---|---|---|---|---|
| cEntity | worldNode 0x50 | void* | `SceneGraphNode*` | ✓ 638 |
| cEntity | UINode 0x54 | void* | `SceneGraphNode*` | ✓ 638 |
| cEntity | networkComponent 0xD4 | void* | `cNetworkComponent*` | ✓ 384 |
| cEntity | transformComponent 0xD8 | void* | `cTransformComponent*` | ✓ 659 |
| cEntity | animStateComponent 0xDC | void* | `cAnimStateComponent*` | ✓ 647 |
| MapComponent | pMapRenderer 0x16C | void* | `MapRenderer*` | ✓ 670 |
| MapComponent | pWaveComponent 0x174 | void* | `WaveComponent*` | ✓ 569 |
| MapComponent | pRoadManager 0x178 | void* | `RoadManagerComponent*` | ✓ 582 |
| MapComponent | pGroundCreep 0x17C | void* | `GroundCreep*` | ✓ 644 |
| MapComponent | ppNetworkTileRegions 0x180 | void* | `cNetworkTileRegion**` | ✓ 629 |
| cAccountManager | pCommunication 0x38 | void* | `cAccountCommunication*` | ✓ 498 |
| cDontStarveSim | pFreeCamera 0x19C | void* | `cFreeCamera*` | ✓ 660 |
| cDontStarveSim | pSystemService 0x474 | void* | `DontStarveSystemService*` | ✓ 496 |
| cDontStarveSim | pGameService 0x478 | void* | `DontStarveGameService*` | ✓ 495 |
| cTransformComponent | pPhysicsComponent 0x14 | void* | `cPhysicsComponent*` | ✓ 641 |
| cTransformComponent | pFollowerComponent 0x18 | void* | `FollowerComponent*` | ✓ 570 |
| WallStencilBuffer | pRenderer 0x1C | void* | `GameRenderer*` | ✓ (前置声明) |
| ReplicaManager3 | pCurrentlyDeallocatingReplica 0x4C | void* | `Replica3*` | ✓ 620 |
| Replica3 | pReplicaManager 0x30 | void* | `ReplicaManager3*` | ✓ 626 |
| DeserializeParameters | pSourceConnection 0x120 | void* | `Connection_RM3*` | ✓ 617 |
| TDataCacheAnimNode | pAnimNode 0x04 | void* | `AnimNode*` | ✓ 664 |
| TDataCacheAnimNode | pBuild 0x74 | void* | `sBuild*` | ✓ 679 |
| TDataCacheAnimNode | pAnimNodeRef 0x98 | void* | `AnimNode*` | ✓ 664 |
| ShadowRenderer | pManager 0xA0 | void* | `ShadowManagerComponent*` | ✓ 579 |
| ShadowRenderer | pRenderer 0xA4 | void* | `Renderer*` | ✓ 688 |
| cFrameWalker | pAnim 0x00 | void* | `sAnim*` | ✓ 671 |

(26 字段 — 上表 13 struct 交叉核对后发现 cEntity 5 + MapComponent 5 + cAccountManager 1 +
cDontStarveSim 3 + cTransformComponent 2 + WallStencilBuffer 1 + ReplicaManager3 1 + Replica3 1 +
DeserializeParameters 1 + TDataCacheAnimNode 3 + ShadowRenderer 2 + cFrameWalker 1 = 26)

## 保留 void* + /* TODO: <Type> */(Ghidra 已定类型但头文件未定义,5 处)

| Struct | 字段 | Ghidra 类型 |
|---|---|---|
| cEntity | transformprovider 0xE0 | `cTransformProvider*` |
| MapComponent | pNavGrid 0x16C | `TileGrid*` |
| cShardManager | pCheshireCat 0x9C | `tCheshireCat_Shard*` |
| Heap | pFirstBlock 0x0C | `MemoryBlock*` |
| Heap | pLastBlock 0x10 | `MemoryBlock*` |
| WallStencilBuffer | pDispatcher 0x38 | `cEventDispatcher*` |

## Ghidra 仍为 void* → 保持 void*(无变更,24 struct)

AnmManager(全部 pointer)、GroundCreep(全部 pointer)、cUITransformComponent(pVtable2/3/4 + map rb-tree)、
cReader(pBuffer)、HWEffect(pShaderData)、cShardClientComponent(pList/list_0x14)、TDataCacheGameRender、
TDataCacheMiniMapRenderer、FileOpResult(pContext)、cStdString、cInputKeyEvent(vptr)、cTogglePauseEvent(vptr)、
cLineEditor(vecHistory 三件套)、LuaHttpQuery、FrameProfiler、IPCSignals(map rb-tree)、Shader、PostProcessor、
cSoundSystem(map rb-tree)、cSteamAccountCommunication(pAuthTicketBuffer)、TDataCacheBase、FileHandle(pM_pData)、
ZipFileSystem(pZipArchive)、cHashedStringLookup(pStringPool/End 已是 char*,synced)。

## 约定
- 目标类型已在头文件定义 → 直接 `Type*`(沿用 MapComponentBase→MapRenderer 先例,文档基线不追求编译完序)
- 未定义 → `void*` + 行内 `/* TODO: Type* */`(风格对齐 RM3World.pNetworkIDManager 先例)
- Replica3 族(Serialize/Deserialize/ReplicaManager3)Phase 0/1 已同步,本次仅补 Slice5 遗漏项

## 验证
- 每个编辑锚点唯一(全文件 grep 单一定义确认,无重复 struct)
- `void*`→`Type*` 均为 4B(i386),struct total size/字段序不变
- 并发注意:与 SyncVoidStar1-4 同时编辑此文件,锚点互不重叠