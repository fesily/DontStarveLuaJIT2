# Inferred Types Audit (Ghidra existence)

Program: `dontstarve_steam`
Source audits: `audit-s1-net.md`, `audit-s2-entity.md`, `audit-s3-render.md`, `audit-s4-ui.md`, `audit-s5-misc.md`

Legend:
- **EXISTS(size=N)**: real layout size>1 (not a demangler Size=1 stub)
- **PLACEHOLDER**: type name present but Size=1 demangler/empty stub
- **MISSING**: type name not found in Ghidra data type manager

Categories: PLATFORM / BULLET / RAKNET / GAME / STRING

Decision aid for main agent:
- EXISTS → 可直接回写指针类型
- PLACEHOLDER → 可先建真实布局/占位后回写,或保持 void* 待调查
- MISSING → 需引入/建模后再回写

---

## AstarParams*
category: GAME
ghidra: PLACEHOLDER
note: Demangler size=1; no real layout
fields: AStarSearch_ulong.pParams

## BoostMap*
category: GAME
ghidra: PLACEHOLDER
note: Demangler size=1
fields: WorldSimActual.pBoostMap

## btBroadphaseInterface*
category: BULLET
ghidra: PLACEHOLDER
note: Demangler size=1
fields: cBPWorld.pBroadphase

## btCollisionDispatcher*
category: BULLET
ghidra: PLACEHOLDER
note: Demangler size=1
fields: MapGenSim.pDispatcher, cBPWorld.pDispatcher

## btCollisionShape*
category: BULLET
ghidra: PLACEHOLDER
note: Demangler size=1
fields: cPhysicsComponent.pCollisionShape, cBPWorld.pGroundShape

## btCompoundShape*
category: BULLET
ghidra: PLACEHOLDER
note: Demangler size=1
fields: cPhysicsComponent.pCompoundShape

## btConvex2dShape*
category: BULLET
ghidra: PLACEHOLDER
note: Demangler size=1
fields: MapGenSim.pShapeBox, MapGenSim.pShapeTri, MapGenSim.pShapeCylinder

## btDbvtBroadphase*
category: BULLET
ghidra: PLACEHOLDER
note: Demangler size=1
fields: MapGenSim.pBroadphase

## btDefaultCollisionConfiguration*
category: BULLET
ghidra: PLACEHOLDER
note: Demangler size=1
fields: MapGenSim.pConfig, cBPWorld.pConfig

## btDiscreteDynamicsWorld*
category: BULLET
ghidra: PLACEHOLDER
note: Demangler size=1
fields: MapGenSim.pWorld, cBPWorld.pWorld

## btRigidBody*
category: BULLET
ghidra: PLACEHOLDER
note: Demangler size=1
fields: cPhysicsComponent.pRigidBody, cBPWorld.pGroundBody

## btSequentialImpulseConstraintSolver*
category: BULLET
ghidra: PLACEHOLDER
note: Demangler size=1
fields: MapGenSim.pSolver, cBPWorld.pSolver

## Buffer*
category: GAME
ghidra: EXISTS(size=12)
note: real struct /Buffer with 3 fields
fields: BinaryBufferWriter.pBuffer

## cBaseFactory*
category: GAME
ghidra: EXISTS(size=60)
note: real struct /cBaseFactory
fields: cEntityManager.pComponentFactory

## cEventDispatcher_cGameEvent*
category: GAME
ghidra: MISSING
note: underscore form absent; cEventDispatcher<cGameEvent> Demangler size=1 only
fields: cGame.pGameEventDispatcher

## cEventDispatcher_SystemEvent*
category: GAME
ghidra: MISSING
note: underscore form absent; cEventDispatcher<SystemEvent> Demangler size=1 only
fields: cGame.pSystemEventDispatcher

## cEventDispatcher*
category: GAME
ghidra: PLACEHOLDER
note: Demangler size=1
fields: WallStencilBuffer.pDispatcher

## cEventDispatcher<cGameEvent>*
category: GAME
ghidra: PLACEHOLDER
note: Demangler size=1
fields: DontStarveInputHandler.pGameEventDispatcher

## ClientThread*
category: GAME
ghidra: PLACEHOLDER
note: Demangler /CurlRequestManager/ClientThread size=1
fields: CurlRequestManager.pClientThread

## cNetworkManager::ServerListingData*
category: GAME
ghidra: EXISTS(size=27)
note: qualified name missing; recovered as /ServerListingData size=27 (Demangler nested size=1)
fields: cNetworkManager.pServerListingData

## cNetworkManager::tCheshireCat*
category: GAME
ghidra: EXISTS(size=352)
note: Demangler nested size=1; recovered as /tCheshireCat_Network size=352
fields: cNetworkManager.pCheshireCat

## cShardManager::tCheshireCat*
category: GAME
ghidra: EXISTS(size=64)
note: Demangler nested size=1; recovered as /tCheshireCat_Shard size=64
fields: cShardManager.pCheshireCat

## cSimulation*
category: GAME
ghidra: EXISTS(size=412)
note: real struct /cSimulation
fields: cNetworkLuaProxy.pNetworkContext

## cSpatialHash_cEntity*
category: GAME
ghidra: EXISTS(size=40)
note: real struct /cSpatialHash_cEntity
fields: cEntityManager.pSpatialHash

## cTransformProvider*
category: GAME
ghidra: PLACEHOLDER
note: Demangler size=1
fields: cEntity.pTransformprovider

## cTwitchManager::tCheshireCat*
category: GAME
ghidra: EXISTS(size=1409)
note: Demangler nested size=1; recovered as /tCheshireCat_Twitch size=1409
fields: cTwitchManager.pCheshireCat

## curl_slist*
category: PLATFORM
ghidra: MISSING
note: no curl types in program
fields: CurlRequest.pCurlSlist

## CURL*
category: PLATFORM
ghidra: MISSING
note: no curl types in program
fields: CurlRequest.pCurlEasy

## CURLM*
category: PLATFORM
ghidra: MISSING
note: no curl types in program
fields: CurlRequest.pCurlMulti

## cVideoPlayer*
category: GAME
ghidra: MISSING
note: no cVideoPlayer/VideoPlayer; only cVideoWidget size=24
fields: cVideoWidget.pVideoObj

## DirectoryDeltaTransfer*
category: RAKNET
ghidra: PLACEHOLDER
note: Demangler/RakNet size=1
fields: cNetworkManager.pDirectoryDeltaTransfer

## FileListTransfer*
category: RAKNET
ghidra: PLACEHOLDER
note: Demangler/RakNet size=1
fields: cNetworkManager.pFileListTransfer

## FileManager*
category: GAME
ghidra: PLACEHOLDER
note: Demangler size=1
fields: cGame.pFileManager

## IInputManager*
category: GAME
ghidra: PLACEHOLDER
note: Demangler size=1; concrete Input_SDLInputManager EXISTS size=2916
fields: DontStarveInputHandler.pInputManager, ControlMapper.pInputManager2

## IncrementalReadInterface*
category: RAKNET
ghidra: PLACEHOLDER
note: Demangler/RakNet size=1
fields: cNetworkManager.pIncrementalReadInterface

## InputManager*
category: GAME
ghidra: MISSING
note: no InputManager; IInputManager placeholder; Input_SDLInputManager size=2916
fields: cGame.pInputManager

## lua_State*
category: PLATFORM
ghidra: PLACEHOLDER
note: Demangler size=1
fields: cSimulation.pLuaState, DontStarveInputHandler.pLuaState, SimThread.pLuaState

## MapLayerManagerComponent*
category: GAME
ghidra: EXISTS(size=84)
note: real struct /MapLayerManagerComponent
fields: MapRenderer.pLayerMgr

## MemoryBlock*
category: GAME
ghidra: PLACEHOLDER
note: Demangler size=1
fields: Heap.pFirstBlock, Heap.pLastBlock

## MOTDImageLoader*
category: GAME
ghidra: EXISTS(size=16)
note: real struct /MOTDImageLoader
fields: cGame.pMOTDImageLoader

## NetworkIDManager*
category: RAKNET
ghidra: PLACEHOLDER
note: Demangler/RakNet size=1
fields: cNetworkManager.pNetworkIDManager, NetworkIDObject.pNetworkIDManager, RM3World.pNetworkIDManager

## PathfinderParams*
category: GAME
ghidra: PLACEHOLDER
note: Demangler size=1
fields: AStarSearch_PathNode.pParams

## PluginInterface2*
category: RAKNET
ghidra: EXISTS(size=12)
note: real struct /PluginInterface2 (vtable+RakPeer+TCP)
fields: cNetworkManager.pAdditionalPlugin

## pthread_t
category: PLATFORM
ghidra: EXISTS(size=4)
note: /_pthread_t.h/pthread_t
fields: Thread.pThread

## RakPeerInterface*
category: RAKNET
ghidra: PLACEHOLDER
note: Demangler/RakNet size=1; ptr type size=4
fields: cNetworkManager.pRakPeer, cSteamPunchthrough.pRakPeer, PluginInterface2.pRakPeerInterface

## ReadyEvent*
category: RAKNET
ghidra: MISSING
note: no ReadyEvent type found
fields: cNetworkManager.pReadyEvent

## RPC4*
category: RAKNET
ghidra: PLACEHOLDER
note: Demangler/RakNet size=1
fields: cNetworkRPCManager.pRPC4

## SDL_sem*
category: PLATFORM
ghidra: MISSING
note: no SDL_sem; only SDL_Event/_SDL_Joystick demangler stubs
fields: Semaphore.pSem

## sMipDescription*
category: GAME
ghidra: PLACEHOLDER
note: /BaseTexture/sMipDescription size=1
fields: BaseTexture.pMipData

## SnapshotManager*
category: RAKNET
ghidra: PLACEHOLDER
note: Demangler size=1
fields: cNetworkManager.pSnapshotManager

## SoundProjectManager*
category: GAME
ghidra: EXISTS(size=64)
note: real struct /SoundProjectManager
fields: cGame.pSoundProjectManager

## std::string
category: STRING
ghidra: MISSING
note: no usable std::string layout; bare string size=-1; only demangler container refs
fields: cAnimStateComponent.pAnimStr, cAnimStateComponent.pBankStr, cAnimStateComponent.pBuildStr, cAnimStateComponent.pSkinStr, cAnimStateComponent.pOverrideBuildStr

## std::string*
category: STRING
ghidra: MISSING
note: same as std::string — no real string layout
fields: cNetworkManager.pStrServerName, cNetworkManager.pStrServerDescription, cNetworkManager.pStrClanInfo, cNetworkManager.pStrServerIntention, cNetworkManager.pStrServerPassword, cNetworkManager.pStrGameMode, cNetworkManager.pStrServerTags, cNetworkManager.pStrField_0x1A0, cNetworkManager.pStrField_0x1B0, cNetworkManager.pStrField_0x1B4, cNetworkManager.pStrField_0x1F8, cNetworkManager.pStrDisconnectReason, cNetworkManager.pStrPopupReason, cNetworkManager.pStrPopupDialog, cSimulation.pStrScenarioScript

## SteamWorkshop*
category: GAME
ghidra: PLACEHOLDER
note: Demangler size=1
fields: cUnpackModThread.pWorkshop

## TCPInterface*
category: RAKNET
ghidra: PLACEHOLDER
note: Demangler/RakNet size=1
fields: PluginInterface2.pTcpInterface

## Thread*
category: GAME
ghidra: EXISTS(size=248)
note: real struct /Thread
fields: cSimulation.pPhysicsThread

## TileGrid*
category: GAME
ghidra: EXISTS(size=28)
note: real struct /TileGrid
fields: cNetworkTileRegion.pTileGrid, WorldSimActual.pTileGrid, MapComponent.pNavGrid

## uint16_t*
category: PLATFORM
ghidra: MISSING
note: uint16_t name absent; use ushort/undefined2 (size=2) for pointed-to
fields: cNetworkTileRegion.pTileData, cNetworkTileRegion.pTileDataPtr

## uint8_t*
category: PLATFORM
ghidra: MISSING
note: uint8_t name absent; use byte/undefined1 (size=1) for pointed-to
fields: cNetworkClientObject2.pNetStats, cSteamAccountCommunication.pAuthTicketBuffer

---

## Summary table

| 类型 | 分类 | Ghidra 状态 | 引用字段数 |
|------|------|-------------|------------|
| `AstarParams*` | GAME | PLACEHOLDER | 1 |
| `BoostMap*` | GAME | PLACEHOLDER | 1 |
| `btBroadphaseInterface*` | BULLET | PLACEHOLDER | 1 |
| `btCollisionDispatcher*` | BULLET | PLACEHOLDER | 2 |
| `btCollisionShape*` | BULLET | PLACEHOLDER | 2 |
| `btCompoundShape*` | BULLET | PLACEHOLDER | 1 |
| `btConvex2dShape*` | BULLET | PLACEHOLDER | 3 |
| `btDbvtBroadphase*` | BULLET | PLACEHOLDER | 1 |
| `btDefaultCollisionConfiguration*` | BULLET | PLACEHOLDER | 2 |
| `btDiscreteDynamicsWorld*` | BULLET | PLACEHOLDER | 2 |
| `btRigidBody*` | BULLET | PLACEHOLDER | 2 |
| `btSequentialImpulseConstraintSolver*` | BULLET | PLACEHOLDER | 2 |
| `Buffer*` | GAME | EXISTS(size=12) | 1 |
| `cBaseFactory*` | GAME | EXISTS(size=60) | 1 |
| `cEventDispatcher_cGameEvent*` | GAME | MISSING | 1 |
| `cEventDispatcher_SystemEvent*` | GAME | MISSING | 1 |
| `cEventDispatcher*` | GAME | PLACEHOLDER | 1 |
| `cEventDispatcher<cGameEvent>*` | GAME | PLACEHOLDER | 1 |
| `ClientThread*` | GAME | PLACEHOLDER | 1 |
| `cNetworkManager::ServerListingData*` | GAME | EXISTS(size=27) | 1 |
| `cNetworkManager::tCheshireCat*` | GAME | EXISTS(size=352) | 1 |
| `cShardManager::tCheshireCat*` | GAME | EXISTS(size=64) | 1 |
| `cSimulation*` | GAME | EXISTS(size=412) | 1 |
| `cSpatialHash_cEntity*` | GAME | EXISTS(size=40) | 1 |
| `cTransformProvider*` | GAME | PLACEHOLDER | 1 |
| `cTwitchManager::tCheshireCat*` | GAME | EXISTS(size=1409) | 1 |
| `curl_slist*` | PLATFORM | MISSING | 1 |
| `CURL*` | PLATFORM | MISSING | 1 |
| `CURLM*` | PLATFORM | MISSING | 1 |
| `cVideoPlayer*` | GAME | MISSING | 1 |
| `DirectoryDeltaTransfer*` | RAKNET | PLACEHOLDER | 1 |
| `FileListTransfer*` | RAKNET | PLACEHOLDER | 1 |
| `FileManager*` | GAME | PLACEHOLDER | 1 |
| `IInputManager*` | GAME | PLACEHOLDER | 2 |
| `IncrementalReadInterface*` | RAKNET | PLACEHOLDER | 1 |
| `InputManager*` | GAME | MISSING | 1 |
| `lua_State*` | PLATFORM | PLACEHOLDER | 3 |
| `MapLayerManagerComponent*` | GAME | EXISTS(size=84) | 1 |
| `MemoryBlock*` | GAME | PLACEHOLDER | 2 |
| `MOTDImageLoader*` | GAME | EXISTS(size=16) | 1 |
| `NetworkIDManager*` | RAKNET | PLACEHOLDER | 3 |
| `PathfinderParams*` | GAME | PLACEHOLDER | 1 |
| `PluginInterface2*` | RAKNET | EXISTS(size=12) | 1 |
| `pthread_t` | PLATFORM | EXISTS(size=4) | 1 |
| `RakPeerInterface*` | RAKNET | PLACEHOLDER | 3 |
| `ReadyEvent*` | RAKNET | MISSING | 1 |
| `RPC4*` | RAKNET | PLACEHOLDER | 1 |
| `SDL_sem*` | PLATFORM | MISSING | 1 |
| `sMipDescription*` | GAME | PLACEHOLDER | 1 |
| `SnapshotManager*` | RAKNET | PLACEHOLDER | 1 |
| `SoundProjectManager*` | GAME | EXISTS(size=64) | 1 |
| `std::string` | STRING | MISSING | 5 |
| `std::string*` | STRING | MISSING | 15 |
| `SteamWorkshop*` | GAME | PLACEHOLDER | 1 |
| `TCPInterface*` | RAKNET | PLACEHOLDER | 1 |
| `Thread*` | GAME | EXISTS(size=248) | 1 |
| `TileGrid*` | GAME | EXISTS(size=28) | 3 |
| `uint16_t*` | PLATFORM | MISSING | 2 |
| `uint8_t*` | PLATFORM | MISSING | 2 |

## Counts

- Total unique target types: **59**
- By category: PLATFORM=8, BULLET=10, RAKNET=10, GAME=29, STRING=2
- By Ghidra status: EXISTS=15, PLACEHOLDER=31, MISSING=13

## Action buckets (for main agent)

### Direct rewrite candidates (EXISTS)
- `Buffer*` (GAME, refs=1)
- `cBaseFactory*` (GAME, refs=1)
- `cNetworkManager::ServerListingData*` (GAME, refs=1)
- `cNetworkManager::tCheshireCat*` (GAME, refs=1)
- `cShardManager::tCheshireCat*` (GAME, refs=1)
- `cSimulation*` (GAME, refs=1)
- `cSpatialHash_cEntity*` (GAME, refs=1)
- `cTwitchManager::tCheshireCat*` (GAME, refs=1)
- `MapLayerManagerComponent*` (GAME, refs=1)
- `MOTDImageLoader*` (GAME, refs=1)
- `PluginInterface2*` (RAKNET, refs=1)
- `pthread_t` (PLATFORM, refs=1)
- `SoundProjectManager*` (GAME, refs=1)
- `Thread*` (GAME, refs=1)
- `TileGrid*` (GAME, refs=3)

### Need real layout / placeholder rebuild (PLACEHOLDER)
- `AstarParams*` (GAME, refs=1)
- `BoostMap*` (GAME, refs=1)
- `btBroadphaseInterface*` (BULLET, refs=1)
- `btCollisionDispatcher*` (BULLET, refs=2)
- `btCollisionShape*` (BULLET, refs=2)
- `btCompoundShape*` (BULLET, refs=1)
- `btConvex2dShape*` (BULLET, refs=3)
- `btDbvtBroadphase*` (BULLET, refs=1)
- `btDefaultCollisionConfiguration*` (BULLET, refs=2)
- `btDiscreteDynamicsWorld*` (BULLET, refs=2)
- `btRigidBody*` (BULLET, refs=2)
- `btSequentialImpulseConstraintSolver*` (BULLET, refs=2)
- `cEventDispatcher*` (GAME, refs=1)
- `cEventDispatcher<cGameEvent>*` (GAME, refs=1)
- `ClientThread*` (GAME, refs=1)
- `cTransformProvider*` (GAME, refs=1)
- `DirectoryDeltaTransfer*` (RAKNET, refs=1)
- `FileListTransfer*` (RAKNET, refs=1)
- `FileManager*` (GAME, refs=1)
- `IInputManager*` (GAME, refs=2)
- `IncrementalReadInterface*` (RAKNET, refs=1)
- `lua_State*` (PLATFORM, refs=3)
- `MemoryBlock*` (GAME, refs=2)
- `NetworkIDManager*` (RAKNET, refs=3)
- `PathfinderParams*` (GAME, refs=1)
- `RakPeerInterface*` (RAKNET, refs=3)
- `RPC4*` (RAKNET, refs=1)
- `sMipDescription*` (GAME, refs=1)
- `SnapshotManager*` (RAKNET, refs=1)
- `SteamWorkshop*` (GAME, refs=1)
- `TCPInterface*` (RAKNET, refs=1)

### Need investigation / import (MISSING)
- `cEventDispatcher_cGameEvent*` (GAME, refs=1)
- `cEventDispatcher_SystemEvent*` (GAME, refs=1)
- `curl_slist*` (PLATFORM, refs=1)
- `CURL*` (PLATFORM, refs=1)
- `CURLM*` (PLATFORM, refs=1)
- `cVideoPlayer*` (GAME, refs=1)
- `InputManager*` (GAME, refs=1)
- `ReadyEvent*` (RAKNET, refs=1)
- `SDL_sem*` (PLATFORM, refs=1)
- `std::string` (STRING, refs=5)
- `std::string*` (STRING, refs=15)
- `uint16_t*` (PLATFORM, refs=2)
- `uint8_t*` (PLATFORM, refs=2)
