# Phase 0.6 sync — S3 void* → Ghidra 类型 (sync-voidstar-s3)

> program: `dontstarve_steam` (macOS i386, gcc)
> tool: ghidra-mcp `get_struct_layout` (read-only)
> date: 2026-08-12
> shard: Slice3 (37 struct)
> summary: processed=37 typed=17 kept=20; 字段类型同步 55 处,新增 TODO 标记 20 处
> 规则: `X *` → `X*`(类型须在 types_common.h 已定义); `-BAD-`/`void *`/vector 三件套/rb-tree → 保留 void*; 未定义类型 → void* + `/* TODO: T* */`

## 已同步(struct + 字段)

### cGame(重点核对,35 字段行)
- `pPostProcessor` → `PostProcessor*`; `pRenderer` → `Renderer*`; `pVFXEmitterManager` → `VFXEmitterManager*`
- `pQuadTreeNode` → `QuadTreeNode*`; `pSceneGraphNode` → `SceneGraphNode*`; `pAnimManager` → `AnimManager*`
- `pAtlasManager` → `AtlasManager*`; `pEnvelopeManager` → `EnvelopeManager*`; `pSoundSystem` → `cSoundSystem*`
- `pStrInstanceSettings` → `cStdString`(Ghidra 按值,4B); `pStrPurchases` → `cStdString`
- `pRenderTargetA/B` → `RenderTarget*`; `pPersistentStorage` → `PersistentStorage*`
- `pSystemService` → `DontStarveSystemService*`; `pGameService` → `DontStarveGameService*`
- `pPerf[19]` → 展开 19 具名字段:15× `PerfIndicator*`(pPerfSimTime..pPerfActualSent)+ 4× `PerfPane*`(pPerfPaneAvgTime..pPerfPanePing)
- TODO: `pInputManager`(Input_SDLInputManager*)、`pFileManager`(FileManager*)、`pSoundProjectManager`(SoundProjectManager*)、`pMOTDImageLoader`(MOTDImageLoader*)、`pGameEventDispatcher`/`pSystemEventDispatcher`(cEventDispatcher*)
- 保留 void*: pVtable、pBaseEventListenerVtable、pRbTreeParent/Left/Right、pWindowManager(-BAD-)、pField_0x5C、pStrUnknown68、pVecPrefabs_{begin,end,cap}(vector)

### cBPWorld
- `pSimulation` → `cSimulation*`
- TODO: pBroadphase(btBroadphaseInterface*)、pConfig(btDefaultCollisionConfiguration*)、pDispatcher(btCollisionDispatcher*)、pSolver(btSequentialImpulseConstraintSolver*)、pWorld(btDiscreteDynamicsWorld*)、pGroundShape(btCollisionShape*)、pGroundBody(btRigidBody*)

### cPhysicsComponent
- `pTransformComponent` → `cTransformComponent*`; `pPhysicsWorldSim` → `cBPWorld*`; `pMotionState` → `MyMotionState*`
- TODO: pRigidBody(btRigidBody*)、pCollisionShape(btCollisionShape*)、pCompoundShape(btCompoundShape*)

### cNetworkTileRegion
- `pMapComponent` → `MapComponent*`
- TODO: pTileGrid(TileGrid*); 保留 void*: pNetworkManager(-BAD-)、pTileData、pTileDataPtr

### BitmapFontRenderer
- `pRenderer` → `GameRenderer*`; `pFontManager` → `BitmapFontManager*`

### WorldSimActual
- 保留 void*: pLunarBase(Ghidra void*)
- TODO: pBoostMap(BoostMap*)、pTileGrid(TileGrid*)

### SimThread
- `pSimulation` → `cSimulation*`; `pStrResult` → `char*`
- TODO: pLuaState(lua_State*)

### BitmapFontManager
- `pRenderer` → `GameRenderer*`

### cLuaNetworkVariable
- `pEntity` → `cEntity*`

### TDataCacheShadowRenderer
- `pOwner` → `ShadowRenderer*`

### TDataCacheMapComponent
- `pOwner` → `SceneGraphNode*`

### ParticleBufferRenderer
- `pRenderer` → `GameRenderer*`; `pEmitter` → `ParticleEmitter*`

### cMasterServerRequest
- `pMasterServer` → `cMasterServer*`

### QuadTreeNode_Node
- `pChild[4]` → `QuadTreeNode_Node* pChild[4]`(自引用)

### cImageComponent
- `pTexture` → `Texture*`

### VFXParticleBufferRenderer
- `pEmitter` → `VFXEffectEmitter*`

### cGameScreen
- `pGame` → `cGame*`

## 已核对无需修改(20)
- **Ghidra 仍 void*/pointer**: AnimNode(pAnimFile/pBuild/hiddenLayers_*/hiddenSymbols_*/rbTree_hdr_* 均 pointer)、ParticleEmitter(pVec_component/pEntity/pNode)、WindowManager(pSDLWindow/pGLContext/pEventDispatcher; pRenderer 已 Renderer*)、cNetworkReplicaManager(pVecReplicas_* vector)、CurlRequestManager、cAccountCommunication(pAccountManager)、GoogleAnalyticsCookie(m_args vector)、cImageWidget(pImageObj -BAD-)、cGameEvent/cInputGestureEvent/WindowMoveEvent(vptr)、PersistentStorage、ZipSaver、BaseVertexDescription、VFXEffect、cLoggerImplementation、RakNetList、cSteamPunchthroughPlugin、Connection_RM3、cSteamRichPresence

## 未定义类型清单(需后续建类型)
`Input_SDLInputManager`、`FileManager`、`SoundProjectManager`、`MOTDImageLoader`、`cEventDispatcher`、`TileGrid`、`BoostMap`、`lua_State`、`btBroadphaseInterface`、`btDefaultCollisionConfiguration`、`btCollisionDispatcher`、`btSequentialImpulseConstraintSolver`、`btDiscreteDynamicsWorld`、`btCollisionShape`、`btRigidBody`、`btCompoundShape`
→ 均已在头文件标 `/* TODO: X* */`,与 voidstar-audit.md「推断 94」一致

## 验证
- 全部变更保持字段名/偏移/顺序/size(指针 4B、cStdString 4B、perf 19×4B=76B)
- cGame total 仍 0x130=304;单行 struct 尾部 size 注释未动
- 参照类型全部在 types_common.h 已定义(文档基线,非编译单元;同既有 cDontStarveSim→cFreeCamera 前向引用惯例)
