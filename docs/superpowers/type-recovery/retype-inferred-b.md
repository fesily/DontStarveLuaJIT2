# Phase 2 Inferred B Retype — 建缺失类型 + 回写推断字段报告

> 输入: task-inferred-b-brief.md(3 步:建真实类型 3 个 → 建不透明占位 32 个 → 回写 52 项推断字段)
> 操作: ghidra-mcp create_struct / delete_data_type / modify_struct_field,dontstarve_steam(macOS i386)
> 验证: 全部 20 个涉及 struct 的 get_struct_layout 复核 — 类型已变、字段名保留、size 未变
> 注: 两段式同 retype-inferred-a — 先按字段名改类型(会清空字段名),再以 `field_name:"offset:0xN"` + new_name 重新落名。

## 第一步:建真实布局类型(3 个,全部成功)

| 类型 | 大小 | 字段(offset: type name) |
|------|------|------|
| cEventDispatcher | 24B (0x18) | 0x00 int nColor;0x04 void* pHeader;0x08 void* pRoot;0x0C void* pLeftmost;0x10 void* pRightmost;0x14 uint dwNodeCount |
| sMipDescription | 16B (0x10) | 0x00 ushort wWidth;0x02 ushort wHeight;0x04 ushort wField_0x04;0x06 byte[2] pPad;0x08 uint dwDataSize;0x0C uint dwDataOffset |
| ReadyEvent | 8B (0x8) | 0x00 void* pVtable;0x04 int nChannel |

- 均先 delete_data_type 删除 demangler 1B 占位(/Demangler/cEventDispatcher、/BaseTexture/sMipDescription),再 create_struct。
- cEventDispatcher 模板实例(cEventDispatcher<GameEvent>/<SystemEvent>)共用此名,未单独建。
- 注:字段名由工具自动规范化(nNodeCount→dwNodeCount、abPad→pPad),偏移与类型完全符合 brief。

## 第二步:建不透明占位(32 个,全部成功)

对每个类型:删除 1B demangler 占位(如有)→ create_struct 4B 单字段 `{void* pVtable}`。

### Bullet (10)
btBroadphaseInterface ✓ btCollisionDispatcher ✓ btCollisionShape ✓ btCompoundShape ✓ btConvex2dShape ✓ btDbvtBroadphase ✓ btDefaultCollisionConfiguration ✓ btDiscreteDynamicsWorld ✓ btRigidBody ✓ btSequentialImpulseConstraintSolver ✓

### RakNet (7)
DirectoryDeltaTransfer ✓ FileListTransfer ✓ IncrementalReadInterface ✓ NetworkIDManager ✓ RakPeerInterface ✓ RPC4 ✓ TCPInterface ✓

### 游戏 PLACEHOLDER (10)
AstarParams ✓ BoostMap ✓ ClientThread ✓ cTransformProvider ✓ FileManager ✓ IInputManager ✓ MemoryBlock ✓ PathfinderParams ✓ SnapshotManager ✓ SteamWorkshop ✓
(跳过:cEventDispatcher_GameEvent — cEventDispatcher 已建;cSpatialHash — cSpatialHash_cEntity 已 EXISTS)

### 平台 (5)
curl_slist ✓ CURL ✓ CURLM ✓ SDL_sem ✓ lua_State ✓

> uint8_t*/uint16_t*:直接沿用 byte/ushort,未建类型。

## 第三步:回写推断字段(52 项)

### 成功 (49/52)

| # | struct.field | 新类型 | 偏移 |
|------|------|------|------|
| 1 | cGame.pGameEventDispatcher | cEventDispatcher * | 0x60 |
| 2 | cGame.pSystemEventDispatcher | cEventDispatcher * | 0x128 |
| 3 | DontStarveInputHandler.pGameEventDispatcher | cEventDispatcher * | 0xC |
| 4 | WallStencilBuffer.pDispatcher | cEventDispatcher * | 0x38 |
| 5 | BaseTexture.pMipData | sMipDescription * | 0x4 |
| 6 | cNetworkManager.pReadyEvent | ReadyEvent * | 0x114 |
| 7 | cVideoWidget.pVideoObj | VideoNode * | 0x14 |
| 8 | cGame.pInputManager | Input_SDLInputManager * | 0x40 |
| 9 | DontStarveInputHandler.pInputManager | IInputManager * | 0x8 |
| 10 | ControlMapper.pInputManager2 | IInputManager * | 0x1C |
| 11 | cBPWorld.pBroadphase | btBroadphaseInterface * | 0x4 |
| 12 | cBPWorld.pConfig | btDefaultCollisionConfiguration * | 0x8 |
| 13 | cBPWorld.pDispatcher | btCollisionDispatcher * | 0xC |
| 14 | cBPWorld.pSolver | btSequentialImpulseConstraintSolver * | 0x10 |
| 15 | cBPWorld.pWorld | btDiscreteDynamicsWorld * | 0x14 |
| 16 | cBPWorld.pGroundShape | btCollisionShape * | 0x18 |
| 17 | cBPWorld.pGroundBody | btRigidBody * | 0x1C |
| 18 | MapGenSim.pWorld | btDiscreteDynamicsWorld * | 0x10 |
| 19 | MapGenSim.pBroadphase | btDbvtBroadphase * | 0x28 |
| 20 | MapGenSim.pDispatcher | btCollisionDispatcher * | 0x2C |
| 21 | MapGenSim.pSolver | btSequentialImpulseConstraintSolver * | 0x30 |
| 22 | MapGenSim.pConfig | btDefaultCollisionConfiguration * | 0x34 |
| 23 | MapGenSim.pShapeBox / pShapeTri / pShapeCylinder | btConvex2dShape * ×3 | 0x44/0x48/0x4C |
| 24 | cPhysicsComponent.pCollisionShape | btCollisionShape * | 0x4C |
| 25 | cPhysicsComponent.pCompoundShape | btCompoundShape * | 0x50 |
| 26 | cPhysicsComponent.pRigidBody | btRigidBody * | 0x48 |
| 27 | cNetworkManager.pNetworkIDManager | NetworkIDManager * | 0xDC |
| 28 | cNetworkManager.pRakPeer | RakPeerInterface * | 0xE0 |
| 29 | cNetworkManager.pDirectoryDeltaTransfer | DirectoryDeltaTransfer * | 0xE4 |
| 30 | cNetworkManager.pFileListTransfer | FileListTransfer * | 0xE8 |
| 31 | cNetworkManager.pIncrementalReadInterface | IncrementalReadInterface * | 0xEC |
| 32 | cNetworkManager.pSnapshotManager | SnapshotManager * | 0x1AC |
| 33 | cNetworkRPCManager.pRPC4 | RPC4 * | 0x0 |
| 34 | PluginInterface2.pRakPeerInterface | RakPeerInterface * | 0x4 |
| 35 | PluginInterface2.pTcpInterface | TCPInterface * | 0x8 |
| 36 | cSteamPunchthrough.pRakPeer | RakPeerInterface * | 0x8 |
| 37 | NetworkIDObject.pNetworkIDManager | NetworkIDManager * | 0xC |
| 38 | RM3World.pNetworkIDManager | NetworkIDManager * | 0x1C |
| 39 | WorldSimActual.pBoostMap | BoostMap * | 0x4 |
| 40 | AStarSearch_ulong.pParams | AstarParams * | 0x20 |
| 41 | AStarSearch_PathNode.pParams | PathfinderParams * | 0x20 |
| 43 | cEntity.pTransformprovider | cTransformProvider * | 0xE0 |
| 45 | cUnpackModThread.pWorkshop | SteamWorkshop * | 0x1A4 |
| 46 | Heap.pFirstBlock / pLastBlock | MemoryBlock * ×2 | 0xC/0x10 |
| 47 | Semaphore.pSem | SDL_sem * | 0x0 |
| 48 | CurlRequest.pCurlMulti / pCurlEasy / pCurlSlist | CURLM * / CURL * / curl_slist * | 0x1C/0x20/0x24 |
| 49 | cGame.pFileManager | FileManager * | 0x48 |
| 51 | cSimulation.pLuaState | lua_State * | 0x58 |
| 52 | SimThread.pLuaState | lua_State * | 0x78 |

### 跳过 (3/52,Phase A 已回写,复核通过)
- 42: cEntityManager.pComponentFactory@0x88 → cBaseFactory *(Phase A 已写)
- 44: cEntityManager.pSpatialHash@0xF8 → cSpatialHash_cEntity *(Phase A 已写)
- 50: cGame.pSoundProjectManager@0x50 → SoundProjectManager *(Phase A 已写)

### 失败清单
无(FAIL_FIELD: 0 / FAIL_TYPE: 0)

## 别名/决策说明
- cVideoPlayer → VideoNode*(EXISTS 276B),未建第二份。
- InputManager → Input_SDLInputManager*(EXISTS 2916B)用于 cGame.pInputManager;DontStarveInputHandler/ControlMapper 接口字段用 IInputManager*(新建 4B 占位)。
- lua_State 建 4B 占位并回写 cSimulation.pLuaState / SimThread.pLuaState。
- cEventDispatcher 模板实例共用 cEventDispatcher 一个名字。

## 抽查结果(20 struct,全部 get_struct_layout 复核)

| struct | size(改前/改后) | 关键字段确认 |
|------|------|------|
| cGame | 304 / 304 | pInputManager=Input_SDLInputManager*;pFileManager=FileManager*;pGameEventDispatcher=cEventDispatcher*;pSystemEventDispatcher=cEventDispatcher* |
| cNetworkManager | 5048 / 5048 | pReadyEvent=ReadyEvent*;pNetworkIDManager=NetworkIDManager*;pRakPeer=RakPeerInterface*;pDirectoryDeltaTransfer=DirectoryDeltaTransfer*;pFileListTransfer=FileListTransfer*;pIncrementalReadInterface=IncrementalReadInterface*;pSnapshotManager=SnapshotManager* |
| cBPWorld | 52 / 52 | 7 个 Bullet 指针全部就位 |
| MapGenSim | 92 / 92 | pWorld=btDiscreteDynamicsWorld*;pBroadphase=btDbvtBroadphase*;pShapeBox/Tri/Cylinder=btConvex2dShape*×3 |
| cPhysicsComponent | 108 / 108 | pRigidBody=btRigidBody*;pCollisionShape=btCollisionShape*;pCompoundShape=btCompoundShape* |
| CurlRequest | 54 / 54 | pCurlMulti=CURLM*;pCurlEasy=CURL*;pCurlSlist=curl_slist* |
| Heap | 92 / 92 | pFirstBlock/pLastBlock=MemoryBlock* |
| Semaphore | 4 / 4 | pSem=SDL_sem* |
| PluginInterface2 | 12 / 12 | pRakPeerInterface=RakPeerInterface*;pTcpInterface=TCPInterface* |
| cSteamPunchthrough | 70 / 70 | pRakPeer=RakPeerInterface* |
| BaseTexture | 20 / 20 | pMipData=sMipDescription* |
| ControlMapper | 520 / 520 | pInputManager2=IInputManager* |
| DontStarveInputHandler | 720 / 720 | pInputManager=IInputManager*;pGameEventDispatcher=cEventDispatcher* |
| cNetworkRPCManager | 17 / 17 | pRPC4=RPC4* |
| WallStencilBuffer | 61 / 61 | pDispatcher=cEventDispatcher* |
| cVideoWidget | 24 / 24 | pVideoObj=VideoNode* |
| NetworkIDObject | 24 / 24 | pNetworkIDManager=NetworkIDManager* |
| RM3World | 32 / 32 | pNetworkIDManager=NetworkIDManager* |
| WorldSimActual | 36 / 36 | pBoostMap=BoostMap* |
| AStarSearch_ulong / AStarSearch_PathNode | 52 / 52 | pParams=AstarParams*/PathfinderParams* |
| cEntity | 252 / 252 | pTransformprovider=cTransformProvider* |
| cUnpackModThread | 424 / 424 | pWorkshop=SteamWorkshop* |
| cSimulation / SimThread | 412 / 412, 140 / 140 | pLuaState=lua_State*×2 |

结论:建类型 35 个(3 真实 + 32 占位),回写成功 49 项、跳过 3 项(Phase A 已写)、失败 0。已 save_program。
