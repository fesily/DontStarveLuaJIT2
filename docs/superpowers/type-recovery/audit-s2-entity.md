# Phase 0.5 — S2 Entity/Scene void* 纠正表

> 只读审计, 不写 Ghidra。
> 输入: `sync-s2-entity.md` + `types_common.h` + tier0/2/3 + remaining-f2-render.md
> 规则: 确定=语义明确且类型在 types_common.h; 推断=语义明确但类型缺失(需建); 待定=无证据; 跳过=vector/vtable/rbtree/pad

## cEntity
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| p__vft | 0x0 | void * | void * | 跳过 (vtable) |
| pParentEntity | 0x24 | void * | cEntity* | 确定 (evidence: types_common.h: parentEntity 声明为 cEntity*; tier2-components.md cEntity 引用闭合) |
| pSimulation | 0x40 | void * | cSimulation* | 确定 (evidence: types_common.h: simulation 声明为 cSimulation*; tier0-core.md / tier2-components.md) |
| pWorldNode | 0x50 | void * | SceneGraphNode* | 确定 (evidence: types_common.h 注释 // 0x50 SceneGraphNode*; SceneGraphNode 已定义; tier3-b-map.md SceneGraphNode 基类) |
| pUINode | 0x54 | void * | SceneGraphNode* | 确定 (evidence: types_common.h UINode 与 worldNode 并列; UI 场景图节点, SceneGraphNode 已定义) |
| pField_0xa8 | 0xa8 | void * | void * | 跳过 (pad/unknown) |
| pNetworkComponent | 0xd4 | void * | cNetworkComponent* | 确定 (evidence: types_common.h 注释 // 0xD4 cNetworkComponent*; 类型已定义; tier0-core.md) |
| pTransformComponent | 0xd8 | void * | cTransformComponent* | 确定 (evidence: types_common.h 注释 // 0xD8 cTransformComponent*; 类型已定义; tier2-components.md) |
| pAnimStateComponent | 0xdc | void * | cAnimStateComponent* | 确定 (evidence: types_common.h 注释 // 0xDC cAnimStateComponent*; 类型已定义; tier2-components.md) |
| pTransformprovider | 0xe0 | void * | cTransformProvider* | 推断 (evidence: types_common.h 注释 // 0xE0 cTransformProvider*; 语义明确但头文件无 cTransformProvider 定义(需建类型)) |

## cEntityManager
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pP__vft | 0x0 | void * | void * | 跳过 (vtable) |
| pServerGuidCounter | 0x8 | void * | int32_t* | 待定 (字段名暗示服务端 GUID 计数器指针, 无明确类型证据, 保持 void*) |
| pComponentFactory | 0x88 | void * | cBaseFactory* | 推断 (evidence: tier0-core.md +0x88 pComponentFactory; cBaseFactory 已定义, 专用 ComponentFactory 类型未建(可暂用 cBaseFactory*)) |
| pSpatialHash | 0xf8 | void * | cSpatialHash_cEntity* | 推断 (evidence: types_common.h 注释 // 0xF8 cSpatialHash<cEntity>*; tier2-components.md 恢复 cSpatialHash<cEntity> 40B, 头文件无该 typedef/struct 名(需建)) |
| pEntityPositionMap_parent | 0x118 | void * | void * | 跳过 (rb-tree) |
| pEntityPositionMap_left | 0x11c | void * | void * | 跳过 (rb-tree) |
| pEntityPositionMap_right | 0x120 | void * | void * | 跳过 (rb-tree) |

## cSimulation
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable_cGameEventListener | 0x0 | void * | void * | 跳过 (vtable) |
| pRbTreeGameEvent_parent | 0xc | void * | void * | 跳过 (rb-tree) |
| pRbTreeGameEvent_left | 0x10 | void * | void * | 跳过 (rb-tree) |
| pRbTreeGameEvent_right | 0x14 | void * | void * | 跳过 (rb-tree) |
| pVtable_cSystemEventListener | 0x1c | void * | void * | 跳过 (vtable) |
| pRbTreeSysEvent_parent | 0x28 | void * | void * | 跳过 (rb-tree) |
| pRbTreeSysEvent_left | 0x2c | void * | void * | 跳过 (rb-tree) |
| pRbTreeSysEvent_right | 0x30 | void * | void * | 跳过 (rb-tree) |
| pEntityManager | 0x40 | void * | cEntityManager* | 确定 (evidence: types_common.h 已声明 cEntityManager*; tier0-core.md 0x40 new(0x138)) |
| pSimTime_vtable | 0x48 | void * | void * | 跳过 (vtable) |
| pLuaState | 0x58 | void * | lua_State* | 推断 (evidence: types_common.h 注释 // 0x58 lua_State*; 语义明确, 头文件无 lua_State 定义(需引入/前向声明)) |
| pGame | 0x5c | void * | cGame* | 确定 (evidence: types_common.h: struct cGame* pGame; tier0-core.md) |
| pWorldSim | 0x60 | void * | WorldSim* | 确定 (evidence: types_common.h 注释 // 0x60 WorldSim*; WorldSim 已定义; tier3-b-map.md) |
| pMainCamera | 0x64 | void * | cSimCamera* | 确定 (evidence: 字段名 MainCamera; remaining-f2-render.md DoReset new(200) 主相机 cSimCamera; cSimCamera 已定义) |
| pStrScenarioScript | 0x68 | void * | std::string* | 推断 (evidence: types_common.h 注释 // 0x68 std::string*; 旧 ABI string, 头文件无 std::string 类型定义(需约定)) |
| pDebugCamera | 0x70 | void * | cSimCamera* | 确定 (evidence: 字段名 DebugCamera; remaining-f2-render.md SetDebugCamera; cSimCamera 已定义) |
| pVecQueuedSysEvents_begin | 0x88 | void * | void * | 跳过 (vector 三件套) |
| pVecQueuedSysEvents_end | 0x8c | void * | void * | 跳过 (vector 三件套) |
| pVecQueuedSysEvents_cap | 0x90 | void * | void * | 跳过 (vector 三件套) |
| pVecQueuedGameEvents_begin | 0xcc | void * | void * | 跳过 (vector 三件套) |
| pVecQueuedGameEvents_end | 0xd0 | void * | void * | 跳过 (vector 三件套) |
| pVecQueuedGameEvents_cap | 0xd4 | void * | void * | 跳过 (vector 三件套) |
| pStrJsonSettings | 0x168 | void * | std::string* | 待定 (Str 前缀暗示字符串, 无注释/tier 类型证据, 保持 void*) |
| pStrPurchases | 0x16c | void * | std::string* | 待定 (Str 前缀暗示字符串, 无类型证据, 保持 void*) |
| pBPWorld | 0x170 | void * | cBPWorld* | 确定 (evidence: 字段名 pBPWorld; cBPWorld 已定义; tier0-core.md 依赖 cBPWorld (0x34 alloc)) |
| pVecUnknown17C_begin | 0x17c | void * | void * | 跳过 (vector 三件套) |
| pVecUnknown17C_end | 0x180 | void * | void * | 跳过 (vector 三件套) |
| pVecUnknown17C_cap | 0x184 | void * | void * | 跳过 (vector 三件套) |
| pPhysicsThread | 0x190 | void * | Thread* | 推断 (evidence: 字段名 PhysicsThread; Thread 基类已定义, 专用 PhysicsThread 类型未建; tier0 提及 gUseThreadedPhysics) |

## cGame
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 (vtable) |
| pBaseEventListenerVtable | 0x4 | void * | void * | 跳过 (vtable) |
| pRbTreeParent | 0x10 | void * | void * | 跳过 (rb-tree) |
| pRbTreeLeft | 0x14 | void * | void * | 跳过 (rb-tree) |
| pRbTreeRight | 0x18 | void * | void * | 跳过 (rb-tree) |
| pSimulation | 0x20 | void * | cSimulation* | 确定 (evidence: types_common.h: struct cSimulation* pSimulation @0x20; tier0-core.md) |
| pWindowManager | 0x28 | void * | WindowManager* | 确定 (evidence: 字段名 + WindowManager 已定义; tier0-core.md 管理器指针列表) |
| pPostProcessor | 0x2c | void * | PostProcessor* | 确定 (evidence: 字段名 + PostProcessor 已定义; tier3-a-rendering.md PostProcessor 136B) |
| pRenderer | 0x30 | void * | Renderer* | 确定 (evidence: 字段名 + Renderer 已定义; tier0-core.md / tier3-a-rendering.md (GameRenderer 为具体实现)) |
| pVFXEmitterManager | 0x34 | void * | VFXEmitterManager* | 确定 (evidence: 字段名 + VFXEmitterManager 已定义; tier3-a-rendering.md / remaining-f2-render.md) |
| pQuadTreeNode | 0x38 | void * | QuadTreeNode* | 确定 (evidence: 字段名 + QuadTreeNode 已定义; tier3-b-map.md) |
| pSceneGraphNode | 0x3c | void * | SceneGraphNode* | 确定 (evidence: 字段名 + SceneGraphNode 已定义; tier3-b-map.md) |
| pInputManager | 0x40 | void * | InputManager* | 推断 (evidence: 字段名明确, 头文件无 InputManager 定义(需建); tier0-core.md 列出该管理器) |
| pAnimManager | 0x44 | void * | AnimManager* | 确定 (evidence: 字段名 + AnimManager 已定义; tier0-core.md) |
| pFileManager | 0x48 | void * | FileManager* | 推断 (evidence: 字段名明确, 头文件无 FileManager(仅有 FileSystem)(需建); tier0-core.md) |
| pAtlasManager | 0x4c | void * | AtlasManager* | 确定 (evidence: 字段名 + AtlasManager 已定义; tier3-a-rendering.md) |
| pSoundProjectManager | 0x50 | void * | SoundProjectManager* | 推断 (evidence: 字段名明确, 头文件无该类型(需建); tier0-core.md) |
| pEnvelopeManager | 0x54 | void * | EnvelopeManager* | 确定 (evidence: 字段名 + EnvelopeManager 已定义; tier0-core.md / types_common.h) |
| pMOTDImageLoader | 0x58 | void * | MOTDImageLoader* | 推断 (evidence: 字段名明确, 头文件无该类型(需建); tier0-core.md) |
| pField_0x5C | 0x5c | void * | void * | 跳过 (pad/unknown) |
| pGameEventDispatcher | 0x60 | void * | cEventDispatcher_cGameEvent* | 推断 (evidence: tier0-core.md: pGameEventDispatcher → cEventDispatcher<cGameEvent>; 头文件无 cEventDispatcher 定义(需建)) |
| pSoundSystem | 0x64 | void * | cSoundSystem* | 确定 (evidence: 字段名 + cSoundSystem 已定义; types_common.h) |
| pStrUnknown68 | 0x68 | void * | void * | 跳过 (pad/unknown) |
| pVecPrefabs_begin | 0x80 | void * | void * | 跳过 (vector 三件套) |
| pVecPrefabs_end | 0x84 | void * | void * | 跳过 (vector 三件套) |
| pVecPrefabs_capacity | 0x88 | void * | void * | 跳过 (vector 三件套) |
| pStrInstanceSettings | 0x94 | void * | std::string* | 待定 (Str 前缀, 无类型证据, 保持 void*) |
| pRenderTargetA | 0xa4 | void * | RenderTarget* | 确定 (evidence: 字段名 RenderTarget + RenderTarget 已定义; tier3-a-rendering.md; types_common.h @0xA4) |
| pRenderTargetB | 0xa8 | void * | RenderTarget* | 确定 (evidence: 同上 @0xA8) |
| pPersistentStorage | 0xac | void * | PersistentStorage* | 确定 (evidence: 字段名 + PersistentStorage 已定义; types_common.h) |
| pSystemService | 0xb0 | void * | DontStarveSystemService* | 确定 (evidence: 字段名 SystemService + DontStarveSystemService 已定义; types_common.h cApplication.mSystemService 对照) |
| pGameService | 0xb4 | void * | DontStarveGameService* | 确定 (evidence: 字段名 GameService + DontStarveGameService 已定义; types_common.h) |
| pStrPurchases | 0xc4 | void * | std::string* | 待定 (Str 前缀, 无类型证据, 保持 void*) |
| pPerfSimTime | 0xdc | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfLuaTime | 0xe0 | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfPhysicsTime | 0xe4 | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfRenderTime | 0xe8 | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfFPSAvg | 0xec | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfPing | 0xf0 | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfLUAAvg | 0xf4 | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfSimAvg | 0xf8 | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfPhysicsAvg | 0xfc | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfRenderAvg | 0x100 | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfPushed | 0x104 | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfSent | 0x108 | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfResent | 0x10c | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfProcessed | 0x110 | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfActualSent | 0x114 | void * | PerfIndicator* | 确定 (evidence: types_common.h pPerf[19] @0xDC..0x124; PerfIndicator 已定义 (含 pGame); tier0-core.md Perf* 指针块) |
| pPerfPaneAvgTime | 0x118 | void * | PerfPane* | 确定 (evidence: 字段名 PerfPane* + PerfPane 已定义; types_common.h perf 指针块尾部; tier0-core.md) |
| pPerfPaneInstTime | 0x11c | void * | PerfPane* | 确定 (evidence: 字段名 PerfPane* + PerfPane 已定义; types_common.h perf 指针块尾部; tier0-core.md) |
| pPerfPaneNetwork | 0x120 | void * | PerfPane* | 确定 (evidence: 字段名 PerfPane* + PerfPane 已定义; types_common.h perf 指针块尾部; tier0-core.md) |
| pPerfPanePing | 0x124 | void * | PerfPane* | 确定 (evidence: 字段名 PerfPane* + PerfPane 已定义; types_common.h perf 指针块尾部; tier0-core.md) |
| pSystemEventDispatcher | 0x128 | void * | cEventDispatcher_SystemEvent* | 推断 (evidence: tier0-core.md: pSystemEventDispatcher → cEventDispatcher<SystemEvent>; 头文件无定义(需建)) |

## cDontStarveSim
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pFreeCamera | 0x19c | void * | cFreeCamera* | 确定 (evidence: 字段名 + cFreeCamera 已定义; remaining-f2-render.md DoReset new(0x150); types_common.h) |
| pSystemService | 0x474 | void * | DontStarveSystemService* | 确定 (evidence: 字段名 + DontStarveSystemService 已定义; types_common.h cDontStarveSim) |
| pGameService | 0x478 | void * | DontStarveGameService* | 确定 (evidence: 字段名 + DontStarveGameService 已定义; types_common.h) |

## cDontStarveGame
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pBootScreen | 0x130 | void * | cBootScreen* | 确定 (evidence: 字段名 + cBootScreen 已定义; types_common.h) |
| pGameScreen | 0x134 | void * | cGameScreen* | 确定 (evidence: 字段名 + cGameScreen 已定义; types_common.h) |
| pSoundFEV | 0x138 | void * | void* | 待定 (FMOD FEV 工程句柄语义可疑, 无明确类型证据, 保持 void*) |

## cPrefab
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVecAssets_begin | 0x14 | void * | void * | 跳过 (vector 三件套) |
| pVecAssets_end | 0x18 | void * | void * | 跳过 (vector 三件套) |
| pVecAssets_cap | 0x1c | void * | void * | 跳过 (vector 三件套) |
| pGame | 0x24 | void * | cGame* | 确定 (evidence: types_common.h: struct cGame* pGame @0x24; tier0-core.md / tier3-b-map.md) |
| pVecDeps_begin | 0x28 | void * | void * | 跳过 (vector 三件套) |
| pVecDeps_end | 0x2c | void * | void * | 跳过 (vector 三件套) |
| pVecDeps_cap | 0x30 | void * | void * | 跳过 (vector 三件套) |

## cHashedStringLookup
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 (vtable) |
| pLookupVec_begin | 0x3c | void * | void * | 跳过 (vector 三件套) |
| pLookupVec_end | 0x40 | void * | void * | 跳过 (vector 三件套) |
| pLookupVec_cap | 0x44 | void * | void * | 跳过 (vector 三件套) |

## WorldSim
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pCallbackObj | 0x0 | void * | void* | 待定 (FastDelegate 三件套之一, 无更具体类型, 保持 void*) |
| pCallbackFunc | 0x4 | void * | void* | 待定 (FastDelegate 成员函数指针槽, 保持 void*) |
| pSimThread | 0xc | void * | SimThread* | 确定 (evidence: 字段名 + SimThread 已定义; tier3-b-map.md WorldSim::SimThread; types_common.h) |

## WorldSimActual
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pLunarBase | 0x0 | void * | void* | 待定 (Lunar 绑定基座, 无独立类型定义, 保持 void*) |
| pBoostMap | 0x4 | void * | BoostMap* | 推断 (evidence: remaining-f2-render.md / tier3-b-map.md: BoostMap* (new BoostMap 8B); 头文件无 BoostMap(需建)) |
| pTileGrid | 0x8 | void * | TileGrid* | 推断 (evidence: remaining-f2-render.md / tier3-b-map.md: TileGrid* new(0x1C); 头文件无 TileGrid(需建)) |

## MapComponentBase
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pMapRenderer | 0x114 | void * | MapRenderer* | 确定 (evidence: 字段名 + MapRenderer 已定义; tier3-b-map.md +0x114) |
| pMapTileCount_parent | 0x124 | void * | void * | 跳过 (rb-tree) |
| pMapTileCount_left | 0x128 | void * | void * | 跳过 (rb-tree) |
| pMapTileCount_right | 0x12c | void * | void * | 跳过 (rb-tree) |

## MapComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pNavGrid | 0x16c | void * | TileGrid* | 推断 (evidence: tier3-b-map.md +0x16C pNavGrid = TileGrid* (SetNavSize new TileGrid); 头文件无 TileGrid(需建)) |
| pMapRenderer | 0x170 | void * | MapRenderer* | 确定 (evidence: tier3-b-map.md +0x170 MapRenderer*; 类型已定义) |
| pWaveComponent | 0x174 | void * | WaveComponent* | 确定 (evidence: tier3-b-map.md +0x174 GetComponent<WaveComponent>; WaveComponent 已定义) |
| pRoadManager | 0x178 | void * | RoadManagerComponent* | 确定 (evidence: tier3-b-map.md +0x178 RoadManagerComponent*; 类型已定义) |
| pGroundCreep | 0x17c | void * | GroundCreep* | 确定 (evidence: tier3-b-map.md +0x17C GroundCreep*; 类型已定义) |
| pNetworkTileRegions | 0x180 | void * | cNetworkTileRegion** | 确定 (evidence: tier3-b-map.md +0x180 ppNetworkTileRegions = cNetworkTileRegion**; 类型已定义) |

## MapGenSim
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pWorld | 0x10 | void * | btDiscreteDynamicsWorld* | 推断 (evidence: tier3-b-map.md InitPhysics new btDiscreteDynamicsWorld → +0x10; 头文件无 Bullet 类型(需建/引入)) |
| pCollObjs | 0x20 | void * | void** | 待定 (tier3-b-map.md void** 对齐分配数组, 元素为 btCollisionObject* 但证据写 void**; 保持 void* 或记 void**) |
| pBroadphase | 0x28 | void * | btDbvtBroadphase* | 推断 (evidence: tier3-b-map.md +0x28; 需建/引入 Bullet 类型) |
| pDispatcher | 0x2c | void * | btCollisionDispatcher* | 推断 (evidence: tier3-b-map.md +0x2C; 需建/引入) |
| pSolver | 0x30 | void * | btSequentialImpulseConstraintSolver* | 推断 (evidence: tier3-b-map.md +0x30; 需建/引入) |
| pConfig | 0x34 | void * | btDefaultCollisionConfiguration* | 推断 (evidence: tier3-b-map.md +0x34; 需建/引入) |
| pVecNodes_begin | 0x38 | void * | void * | 跳过 (vector 三件套) |
| pVecNodes_end | 0x3c | void * | void * | 跳过 (vector 三件套) |
| pVecNodes_cap | 0x40 | void * | void * | 跳过 (vector 三件套) |
| pShapeBox | 0x44 | void * | btConvex2dShape* | 推断 (evidence: tier3-b-map.md +0x44 btBoxShape+convex2d; 需建/引入) |
| pShapeTri | 0x48 | void * | btConvex2dShape* | 推断 (evidence: tier3-b-map.md +0x48; 需建/引入) |
| pShapeCylinder | 0x4c | void * | btConvex2dShape* | 推断 (evidence: tier3-b-map.md +0x4C; 需建/引入) |

## Maze
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pPoints_begin | 0x10 | void * | void * | 跳过 (vector 三件套) |
| pPoints_end | 0x14 | void * | void * | 跳过 (vector 三件套) |
| pPoints_cap | 0x18 | void * | void * | 跳过 (vector 三件套) |

## QuadTreeNode
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pRootNode | 0x94 | void * | QuadTreeNode_Node* | 确定 (evidence: tier3-b-map.md +0x94 QuadTreeNode::Node*; QuadTreeNode_Node 已定义) |
| pSet_parent | 0xa4 | void * | void * | 跳过 (rb-tree) |
| pSet_left | 0xa8 | void * | void * | 跳过 (rb-tree) |
| pSet_right | 0xac | void * | void * | 跳过 (rb-tree) |

## QuadTreeNode_Node
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pChild0 | 0x10 | void * | QuadTreeNode_Node* | 确定 (evidence: tier3-b-map.md pChild[4] RecCreate; QuadTreeNode_Node 已定义) |
| pChild1 | 0x14 | void * | QuadTreeNode_Node* | 确定 (evidence: 同上) |
| pChild2 | 0x18 | void * | QuadTreeNode_Node* | 确定 (evidence: 同上) |
| pChild3 | 0x1c | void * | QuadTreeNode_Node* | 确定 (evidence: 同上) |
| pSet_parent | 0x2c | void * | void * | 跳过 (rb-tree) |
| pSet_left | 0x30 | void * | void * | 跳过 (rb-tree) |
| pSet_right | 0x34 | void * | void * | 跳过 (rb-tree) |

## AStarSearch_PathNode
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 (vtable) |
| pParams | 0x20 | void * | PathfinderParams* | 推断 (evidence: tier3-b-map.md +0x20 PathfinderParams*; 头文件无定义(需建)) |

## AStarSearch_ulong
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 (vtable) |
| pParams | 0x20 | void * | AstarParams* | 推断 (evidence: tier3-b-map.md +0x20 AstarParams*; 头文件无定义(需建)) |

## PathfinderComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pMap1_parent | 0x24 | void * | void * | 跳过 (rb-tree) |
| pMap1_left | 0x28 | void * | void * | 跳过 (rb-tree) |
| pMap1_right | 0x2c | void * | void * | 跳过 (rb-tree) |
| pMap2_parent | 0x3c | void * | void * | 跳过 (rb-tree) |
| pMap2_left | 0x40 | void * | void * | 跳过 (rb-tree) |
| pMap2_right | 0x44 | void * | void * | 跳过 (rb-tree) |
| pSearches_parent | 0x54 | void * | void * | 跳过 (rb-tree) |
| pSearches_left | 0x58 | void * | void * | 跳过 (rb-tree) |
| pSearches_right | 0x5c | void * | void * | 跳过 (rb-tree) |

## RoadBuilder
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 (vtable) |

## EnvelopeManager
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 (vtable) |
| pVecEnvelopes_begin | 0x4 | void * | void * | 跳过 (vector 三件套) |
| pVecEnvelopes_end | 0x8 | void * | void * | 跳过 (vector 三件套) |
| pVecEnvelopes_cap | 0xc | void * | void * | 跳过 (vector 三件套) |

## MiniMapComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable2 | 0x10 | void * | void * | 跳过 (vtable) |
| pMap_parent | 0x20 | void * | void * | 跳过 (rb-tree) |
| pMap_left | 0x24 | void * | void * | 跳过 (rb-tree) |
| pMap_right | 0x28 | void * | void * | 跳过 (rb-tree) |

## TwitchComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable2 | 0x10 | void * | void * | 跳过 (vtable) |
| pMap_parent | 0x20 | void * | void * | 跳过 (rb-tree) |
| pMap_left | 0x24 | void * | void * | 跳过 (rb-tree) |
| pMap_right | 0x28 | void * | void * | 跳过 (rb-tree) |

## cUITransformComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable2 | 0x10 | void * | void * | 跳过 (vtable) |
| pVtable3 | 0x14 | void * | void * | 跳过 (vtable) |
| pMap1_parent | 0x24 | void * | void * | 跳过 (rb-tree) |
| pMap1_left | 0x28 | void * | void * | 跳过 (rb-tree) |
| pMap1_right | 0x2c | void * | void * | 跳过 (rb-tree) |
| pVtable4 | 0x30 | void * | void * | 跳过 (vtable) |
| pMap2_parent | 0x40 | void * | void * | 跳过 (rb-tree) |
| pMap2_left | 0x44 | void * | void * | 跳过 (rb-tree) |
| pMap2_right | 0x48 | void * | void * | 跳过 (rb-tree) |

## cShardClientComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pList | 0x10 | void * | void* | 待定 (list 头指针, 无元素类型, 保持 void*) |
| pList_0x14_next | 0x14 | void * | void* | 待定 (list 链接节点, 保持 void*) |
| pList_0x14_prev | 0x18 | void * | void* | 待定 (list 链接节点, 保持 void*) |

## cTransformComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pTransformProviderVtable | 0x10 | void * | void * | 跳过 (vtable) |
| pPhysicsComponent | 0x14 | void * | cPhysicsComponent* | 确定 (evidence: 字段名 + cPhysicsComponent 已定义; types_common.h cTransformComponent) |
| pFollowerComponent | 0x18 | void * | FollowerComponent* | 确定 (evidence: 字段名 + FollowerComponent 已定义; types_common.h) |
| pPredictionHistory | 0x16c | void * | void* | 待定 (types_common.h 有 pPredictionHistory/pTransformHistory 仍为 void*; 无具体类型名, 保持 void*) |

## cPhysicsComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pTransformComponent | 0x10 | void * | cTransformComponent* | 确定 (evidence: 字段名 + cTransformComponent 已定义; types_common.h) |
| pPhysicsWorldSim | 0x24 | void * | void* | 待定 (名暗示物理世界/sim, 无 tier 明确类型, 保持 void*) |
| pRigidBody | 0x48 | void * | btRigidBody* | 推断 (evidence: tier2-components.md +72 起 btRigidBody 等; 头文件无 Bullet 类型(需建/引入)) |
| pCollisionShape | 0x4c | void * | btCollisionShape* | 推断 (evidence: tier2-components.md dtor 释放对象指针; 需建/引入) |
| pCompoundShape | 0x50 | void * | btCompoundShape* | 推断 (evidence: 字段名 CompoundShape; Bullet 复合形状, 需建/引入) |
| pMotionState | 0x54 | void * | MyMotionState* | 确定 (evidence: 字段名 MotionState + MyMotionState 已定义; types_common.h / S2 dump 含 MyMotionState) |

## cAnimStateComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pBBoxProviderVtable | 0x10 | void * | void * | 跳过 (vtable) |
| pAnimStr | 0x20 | void * | std::string | 推断 (evidence: types_common.h pAnimStr 与 dwAnimHash 并列; 旧 ABI 4B string 槽, 头文件无 std::string(需约定); tier2 PlayAnimation 写 hash+str) |
| pBankStr | 0x28 | void * | std::string | 推断 (evidence: 同上 bank 字符串槽) |
| pBuildStr | 0x30 | void * | std::string | 推断 (evidence: 同上 build 字符串槽) |
| pSkinStr | 0x38 | void * | std::string | 推断 (evidence: 同上 skin 字符串槽) |
| pOverrideBuildStr | 0x40 | void * | std::string | 推断 (evidence: 同上 override build 字符串槽) |
| pAnimNode | 0x94 | void * | AnimNode* | 确定 (evidence: 字段名 + AnimNode 已定义; types_common.h) |
| pVecAnimQueue_begin | 0x98 | void * | void * | 跳过 (vector 三件套) |
| pVecAnimQueue_end | 0x9c | void * | void * | 跳过 (vector 三件套) |
| pVecAnimQueue_cap | 0xa0 | void * | void * | 跳过 (vector 三件套) |
| pAnimBankResource | 0xa8 | void * | void* | 待定 (资源句柄/指针语义不明, 保持 void*) |
| pUITransformComponent | 0xac | void * | cUITransformComponent* | 确定 (evidence: 字段名 + cUITransformComponent 已定义; types_common.h) |
| pSymbolExchangeTree | 0xcc | void * | void* | 待定 (符号交换树根, 无具体节点类型, 保持 void*) |

## EnvelopeComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVecEnvelopes_begin | 0x10 | void * | void * | 跳过 (vector 三件套) |
| pVecEnvelopes_end | 0x14 | void * | void * | 跳过 (vector 三件套) |
| pVecEnvelopes_cap | 0x18 | void * | void * | 跳过 (vector 三件套) |

## cSoundEmitterComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x10 | void * | void * | 跳过 (vtable) |

## cImageComponent
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pTexture | 0x10 | void * | Texture* | 确定 (evidence: 字段名 + Texture 已定义; tier2-components.md dtor vtable+24 释放 Texture*; types_common.h) |

## cSimCamera
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 (vtable) |
| pSimulation | 0x4 | void * | cSimulation* | 确定 (evidence: 字段名 + cSimulation 已定义; remaining-f2-render.md; types_common.h) |

## cFrameWalker
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pAnim | 0x0 | void * | sAnim* | 确定 (evidence: remaining-f2-render.md const sAnim* pAnim; sAnim 已定义; types_common.h) |

## SimplexNoise
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 (vtable) |

## VFXEmitterManager
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 (vtable) |

---

## 汇总

| 判定 | 数量 |
|------|------|
| 确定 | 75 |
| 推断 | 33 |
| 待定 | 17 |
| 跳过 | 104 |
| **void* 总计** | **229** |

### 确定清单
- cEntity.pParentEntity
- cEntity.pSimulation
- cEntity.pWorldNode
- cEntity.pUINode
- cEntity.pNetworkComponent
- cEntity.pTransformComponent
- cEntity.pAnimStateComponent
- cSimulation.pEntityManager
- cSimulation.pGame
- cSimulation.pWorldSim
- cSimulation.pMainCamera
- cSimulation.pDebugCamera
- cSimulation.pBPWorld
- cGame.pSimulation
- cGame.pWindowManager
- cGame.pPostProcessor
- cGame.pRenderer
- cGame.pVFXEmitterManager
- cGame.pQuadTreeNode
- cGame.pSceneGraphNode
- cGame.pAnimManager
- cGame.pAtlasManager
- cGame.pEnvelopeManager
- cGame.pSoundSystem
- cGame.pRenderTargetA
- cGame.pRenderTargetB
- cGame.pPersistentStorage
- cGame.pSystemService
- cGame.pGameService
- cGame.pPerfSimTime
- cGame.pPerfLuaTime
- cGame.pPerfPhysicsTime
- cGame.pPerfRenderTime
- cGame.pPerfFPSAvg
- cGame.pPerfPing
- cGame.pPerfLUAAvg
- cGame.pPerfSimAvg
- cGame.pPerfPhysicsAvg
- cGame.pPerfRenderAvg
- cGame.pPerfPushed
- cGame.pPerfSent
- cGame.pPerfResent
- cGame.pPerfProcessed
- cGame.pPerfActualSent
- cGame.pPerfPaneAvgTime
- cGame.pPerfPaneInstTime
- cGame.pPerfPaneNetwork
- cGame.pPerfPanePing
- cDontStarveSim.pFreeCamera
- cDontStarveSim.pSystemService
- cDontStarveSim.pGameService
- cDontStarveGame.pBootScreen
- cDontStarveGame.pGameScreen
- cPrefab.pGame
- WorldSim.pSimThread
- MapComponentBase.pMapRenderer
- MapComponent.pMapRenderer
- MapComponent.pWaveComponent
- MapComponent.pRoadManager
- MapComponent.pGroundCreep
- MapComponent.pNetworkTileRegions
- QuadTreeNode.pRootNode
- QuadTreeNode_Node.pChild0
- QuadTreeNode_Node.pChild1
- QuadTreeNode_Node.pChild2
- QuadTreeNode_Node.pChild3
- cTransformComponent.pPhysicsComponent
- cTransformComponent.pFollowerComponent
- cPhysicsComponent.pTransformComponent
- cPhysicsComponent.pMotionState
- cAnimStateComponent.pAnimNode
- cAnimStateComponent.pUITransformComponent
- cImageComponent.pTexture
- cSimCamera.pSimulation
- cFrameWalker.pAnim

### 推断清单(需建类型)
- cEntity.pTransformprovider
- cEntityManager.pComponentFactory
- cEntityManager.pSpatialHash
- cSimulation.pLuaState
- cSimulation.pStrScenarioScript
- cSimulation.pPhysicsThread
- cGame.pInputManager
- cGame.pFileManager
- cGame.pSoundProjectManager
- cGame.pMOTDImageLoader
- cGame.pGameEventDispatcher
- cGame.pSystemEventDispatcher
- WorldSimActual.pBoostMap
- WorldSimActual.pTileGrid
- MapComponent.pNavGrid
- MapGenSim.pWorld
- MapGenSim.pBroadphase
- MapGenSim.pDispatcher
- MapGenSim.pSolver
- MapGenSim.pConfig
- MapGenSim.pShapeBox
- MapGenSim.pShapeTri
- MapGenSim.pShapeCylinder
- AStarSearch_PathNode.pParams
- AStarSearch_ulong.pParams
- cPhysicsComponent.pRigidBody
- cPhysicsComponent.pCollisionShape
- cPhysicsComponent.pCompoundShape
- cAnimStateComponent.pAnimStr
- cAnimStateComponent.pBankStr
- cAnimStateComponent.pBuildStr
- cAnimStateComponent.pSkinStr
- cAnimStateComponent.pOverrideBuildStr

### 待定清单
- cEntityManager.pServerGuidCounter
- cSimulation.pStrJsonSettings
- cSimulation.pStrPurchases
- cGame.pStrInstanceSettings
- cGame.pStrPurchases
- cDontStarveGame.pSoundFEV
- WorldSim.pCallbackObj
- WorldSim.pCallbackFunc
- WorldSimActual.pLunarBase
- MapGenSim.pCollObjs
- cShardClientComponent.pList
- cShardClientComponent.pList_0x14_next
- cShardClientComponent.pList_0x14_prev
- cTransformComponent.pPredictionHistory
- cPhysicsComponent.pPhysicsWorldSim
- cAnimStateComponent.pAnimBankResource
- cAnimStateComponent.pSymbolExchangeTree

### 跳过清单
- cEntity.p__vft
- cEntity.pField_0xa8
- cEntityManager.pP__vft
- cEntityManager.pEntityPositionMap_parent
- cEntityManager.pEntityPositionMap_left
- cEntityManager.pEntityPositionMap_right
- cSimulation.pVtable_cGameEventListener
- cSimulation.pRbTreeGameEvent_parent
- cSimulation.pRbTreeGameEvent_left
- cSimulation.pRbTreeGameEvent_right
- cSimulation.pVtable_cSystemEventListener
- cSimulation.pRbTreeSysEvent_parent
- cSimulation.pRbTreeSysEvent_left
- cSimulation.pRbTreeSysEvent_right
- cSimulation.pSimTime_vtable
- cSimulation.pVecQueuedSysEvents_begin
- cSimulation.pVecQueuedSysEvents_end
- cSimulation.pVecQueuedSysEvents_cap
- cSimulation.pVecQueuedGameEvents_begin
- cSimulation.pVecQueuedGameEvents_end
- cSimulation.pVecQueuedGameEvents_cap
- cSimulation.pVecUnknown17C_begin
- cSimulation.pVecUnknown17C_end
- cSimulation.pVecUnknown17C_cap
- cGame.pVtable
- cGame.pBaseEventListenerVtable
- cGame.pRbTreeParent
- cGame.pRbTreeLeft
- cGame.pRbTreeRight
- cGame.pField_0x5C
- cGame.pStrUnknown68
- cGame.pVecPrefabs_begin
- cGame.pVecPrefabs_end
- cGame.pVecPrefabs_capacity
- cPrefab.pVecAssets_begin
- cPrefab.pVecAssets_end
- cPrefab.pVecAssets_cap
- cPrefab.pVecDeps_begin
- cPrefab.pVecDeps_end
- cPrefab.pVecDeps_cap
- cHashedStringLookup.pVtable
- cHashedStringLookup.pLookupVec_begin
- cHashedStringLookup.pLookupVec_end
- cHashedStringLookup.pLookupVec_cap
- MapComponentBase.pMapTileCount_parent
- MapComponentBase.pMapTileCount_left
- MapComponentBase.pMapTileCount_right
- MapGenSim.pVecNodes_begin
- MapGenSim.pVecNodes_end
- MapGenSim.pVecNodes_cap
- Maze.pPoints_begin
- Maze.pPoints_end
- Maze.pPoints_cap
- QuadTreeNode.pSet_parent
- QuadTreeNode.pSet_left
- QuadTreeNode.pSet_right
- QuadTreeNode_Node.pSet_parent
- QuadTreeNode_Node.pSet_left
- QuadTreeNode_Node.pSet_right
- AStarSearch_PathNode.pVtable
- AStarSearch_ulong.pVtable
- PathfinderComponent.pMap1_parent
- PathfinderComponent.pMap1_left
- PathfinderComponent.pMap1_right
- PathfinderComponent.pMap2_parent
- PathfinderComponent.pMap2_left
- PathfinderComponent.pMap2_right
- PathfinderComponent.pSearches_parent
- PathfinderComponent.pSearches_left
- PathfinderComponent.pSearches_right
- RoadBuilder.pVtable
- EnvelopeManager.pVtable
- EnvelopeManager.pVecEnvelopes_begin
- EnvelopeManager.pVecEnvelopes_end
- EnvelopeManager.pVecEnvelopes_cap
- MiniMapComponent.pVtable2
- MiniMapComponent.pMap_parent
- MiniMapComponent.pMap_left
- MiniMapComponent.pMap_right
- TwitchComponent.pVtable2
- TwitchComponent.pMap_parent
- TwitchComponent.pMap_left
- TwitchComponent.pMap_right
- cUITransformComponent.pVtable2
- cUITransformComponent.pVtable3
- cUITransformComponent.pMap1_parent
- cUITransformComponent.pMap1_left
- cUITransformComponent.pMap1_right
- cUITransformComponent.pVtable4
- cUITransformComponent.pMap2_parent
- cUITransformComponent.pMap2_left
- cUITransformComponent.pMap2_right
- cTransformComponent.pTransformProviderVtable
- cAnimStateComponent.pBBoxProviderVtable
- cAnimStateComponent.pVecAnimQueue_begin
- cAnimStateComponent.pVecAnimQueue_end
- cAnimStateComponent.pVecAnimQueue_cap
- EnvelopeComponent.pVecEnvelopes_begin
- EnvelopeComponent.pVecEnvelopes_end
- EnvelopeComponent.pVecEnvelopes_cap
- cSoundEmitterComponent.pVtable
- cSimCamera.pVtable
- SimplexNoise.pVtable
- VFXEmitterManager.pVtable

---

## 需建/引入类型(由「推断」汇总)

| 目标类型 | 出现字段 | 证据来源 |
|----------|----------|----------|
| cTransformProvider | cEntity.pTransformprovider | types_common.h 注释 |
| cSpatialHash_cEntity / cSpatialHash<cEntity> | cEntityManager.pSpatialHash | tier2-components.md; types_common 注释 |
| lua_State (前向声明) | cSimulation.pLuaState | types_common.h 注释 |
| std::string (旧 ABI 4B 约定) | cSimulation.pStrScenarioScript; cAnimStateComponent.*Str | types_common 注释 / tier2 |
| InputManager | cGame.pInputManager | tier0-core.md |
| FileManager | cGame.pFileManager | tier0-core.md |
| SoundProjectManager | cGame.pSoundProjectManager | tier0-core.md |
| MOTDImageLoader | cGame.pMOTDImageLoader | tier0-core.md |
| cEventDispatcher<cGameEvent> | cGame.pGameEventDispatcher | tier0-core.md |
| cEventDispatcher<SystemEvent> | cGame.pSystemEventDispatcher | tier0-core.md |
| BoostMap | WorldSimActual.pBoostMap | remaining-f2-render.md / tier3-b-map.md |
| TileGrid | WorldSimActual.pTileGrid; MapComponent.pNavGrid | tier3-b-map.md / remaining-f2-render.md |
| PathfinderParams | AStarSearch_PathNode.pParams | tier3-b-map.md |
| AstarParams | AStarSearch_ulong.pParams | tier3-b-map.md |
| Bullet 物理类型 (btRigidBody 等) | MapGenSim.*; cPhysicsComponent.pRigidBody/pCollisionShape/pCompoundShape | tier3-b-map.md / tier2-components.md |
| cComponentFactory (或复用 cBaseFactory) | cEntityManager.pComponentFactory | tier0-core.md |
| PhysicsThread (或复用 Thread) | cSimulation.pPhysicsThread | tier0-core.md |
