# Phase 1 S2 Retype — Entity/Scene void* 回写报告

> 输入: audit-s2-entity.md 的「确定」判定(75 个)
> 操作: ghidra-mcp modify_struct_field 写回 dontstarve_steam(macOS i386)
> 验证: 每个 struct get_struct_layout 复核 — 类型已变、字段名保留、size 未变
> 注: modify_struct_field 单独调用会把字段名清空(显示 unnamed),已用 offset:0xN 定位 + new_name 两段式恢复(S1 同法),最终布局字段名与 audit 表一致。

## 成功 (75/75)

### cEntity (7)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pParentEntity | cEntity * | 0x24 |
| pSimulation | cSimulation * | 0x40 |
| pWorldNode | SceneGraphNode * | 0x50 |
| pUINode | SceneGraphNode * | 0x54 |
| pNetworkComponent | cNetworkComponent * | 0xD4 |
| pTransformComponent | cTransformComponent * | 0xD8 |
| pAnimStateComponent | cAnimStateComponent * | 0xDC |

### cSimulation (6)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pEntityManager | cEntityManager * | 0x40 |
| pGame | cGame * | 0x5C |
| pWorldSim | WorldSim * | 0x60 |
| pMainCamera | cSimCamera * | 0x64 |
| pDebugCamera | cSimCamera * | 0x70 |
| pBPWorld | cBPWorld * | 0x170 |

### cGame (35)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pSimulation | cSimulation * | 0x20 |
| pWindowManager | WindowManager * | 0x28 |
| pPostProcessor | PostProcessor * | 0x2C |
| pRenderer | Renderer * | 0x30 |
| pVFXEmitterManager | VFXEmitterManager * | 0x34 |
| pQuadTreeNode | QuadTreeNode * | 0x38 |
| pSceneGraphNode | SceneGraphNode * | 0x3C |
| pAnimManager | AnimManager * | 0x44 |
| pAtlasManager | AtlasManager * | 0x4C |
| pEnvelopeManager | EnvelopeManager * | 0x54 |
| pSoundSystem | cSoundSystem * | 0x64 |
| pRenderTargetA | RenderTarget * | 0xA4 |
| pRenderTargetB | RenderTarget * | 0xA8 |
| pPersistentStorage | PersistentStorage * | 0xAC |
| pSystemService | DontStarveSystemService * | 0xB0 |
| pGameService | DontStarveGameService * | 0xB4 |
| pPerfSimTime | PerfIndicator * | 0xDC |
| pPerfLuaTime | PerfIndicator * | 0xE0 |
| pPerfPhysicsTime | PerfIndicator * | 0xE4 |
| pPerfRenderTime | PerfIndicator * | 0xE8 |
| pPerfFPSAvg | PerfIndicator * | 0xEC |
| pPerfPing | PerfIndicator * | 0xF0 |
| pPerfLUAAvg | PerfIndicator * | 0xF4 |
| pPerfSimAvg | PerfIndicator * | 0xF8 |
| pPerfPhysicsAvg | PerfIndicator * | 0xFC |
| pPerfRenderAvg | PerfIndicator * | 0x100 |
| pPerfPushed | PerfIndicator * | 0x104 |
| pPerfSent | PerfIndicator * | 0x108 |
| pPerfResent | PerfIndicator * | 0x10C |
| pPerfProcessed | PerfIndicator * | 0x110 |
| pPerfActualSent | PerfIndicator * | 0x114 |
| pPerfPaneAvgTime | PerfPane * | 0x118 |
| pPerfPaneInstTime | PerfPane * | 0x11C |
| pPerfPaneNetwork | PerfPane * | 0x120 |
| pPerfPanePing | PerfPane * | 0x124 |

### cDontStarveSim (3)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pFreeCamera | cFreeCamera * | 0x19C |
| pSystemService | DontStarveSystemService * | 0x474 |
| pGameService | DontStarveGameService * | 0x478 |

### cDontStarveGame (2)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pBootScreen | cBootScreen * | 0x130 |
| pGameScreen | cGameScreen * | 0x134 |

### cPrefab (1)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pGame | cGame * | 0x24 |

### WorldSim (1)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pSimThread | SimThread * | 0xC |

### MapComponentBase (1)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pMapRenderer | MapRenderer * | 0x114 |

### MapComponent (5)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pMapRenderer | MapRenderer * | 0x170 |
| pWaveComponent | WaveComponent * | 0x174 |
| pRoadManager | RoadManagerComponent * | 0x178 |
| pGroundCreep | GroundCreep * | 0x17C |
| pNetworkTileRegions | cNetworkTileRegion * * | 0x180 |

### QuadTreeNode (1)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pRootNode | QuadTreeNode_Node * | 0x94 |

### QuadTreeNode_Node (4)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pChild0 | QuadTreeNode_Node * | 0x10 |
| pChild1 | QuadTreeNode_Node * | 0x14 |
| pChild2 | QuadTreeNode_Node * | 0x18 |
| pChild3 | QuadTreeNode_Node * | 0x1C |

### cTransformComponent (2)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pPhysicsComponent | cPhysicsComponent * | 0x14 |
| pFollowerComponent | FollowerComponent * | 0x18 |

### cPhysicsComponent (2)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pTransformComponent | cTransformComponent * | 0x10 |
| pMotionState | MyMotionState * | 0x54 |

### cAnimStateComponent (2)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pAnimNode | AnimNode * | 0x94 |
| pUITransformComponent | cUITransformComponent * | 0xAC |

### cImageComponent (1)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pTexture | Texture * | 0x10 |

### cSimCamera (1)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pSimulation | cSimulation * | 0x4 |

### cFrameWalker (1)
| 字段 | 新类型 | 偏移 |
|------|------|------|
| pAnim | sAnim * | 0x0 |

## 失败清单

无(SKIP_NEED_TYPE: 0 / FAIL_SPACE: 0 / FAIL_FIELD: 0)

## 类型预检

写前 search_data_types 确认全部 43 个目标类型已存在于 dontstarve_steam(/ 根类别, 非仅 /Demangler 占位):
cEntity, cSimulation(412B), SceneGraphNode(145B), cNetworkComponent(684B), cTransformComponent(380B), cAnimStateComponent(208B), cEntityManager(309B), cGame(304B), WorldSim(16B), cSimCamera(200B), cBPWorld(52B), WindowManager(136B), PostProcessor(136B), Renderer(564B), VFXEmitterManager(4100B), QuadTreeNode(176B), AnimManager(116B), AtlasManager(64B), EnvelopeManager(24B), cSoundSystem(56B), RenderTarget(4B), PersistentStorage(8B), DontStarveSystemService(164B), DontStarveGameService(36B), PerfIndicator(1048B), PerfPane(64B), cFreeCamera(332B), cBootScreen(12B), cGameScreen(16B), SimThread(140B), MapRenderer(28B), WaveComponent(144B), RoadManagerComponent(248B), GroundCreep(213B), cNetworkTileRegion(388B), QuadTreeNode_Node(56B), cPhysicsComponent(108B), FollowerComponent(66B), MyMotionState(80B), AnimNode(348B), cUITransformComponent(388B), Texture(40B), sAnim(36B)

## 抽查结果(21 struct, 全部 get_struct_layout 复核)

| struct | size(改前/改后) | 关键字段确认 |
|------|------|------|
| cEntity | 252 / 252 | 7 字段全部变更为具体指针类型,名字保留;pField_0xa8/pTransformprovider 未动 |
| cSimulation | 412 / 412 | pEntityManager/pGame/pWorldSim/pMainCamera/pDebugCamera/pBPWorld |
| cGame | 304 / 304 | 35 字段:11 管理器 + RenderTargetA/B + PersistentStorage + SystemService/GameService + PerfIndicator×15 + PerfPane×4;pInputManager/pFileManager 等推断字段未动 |
| cDontStarveSim | 1148 / 1148 | pFreeCamera = cFreeCamera *;pSystemService/pGameService |
| cDontStarveGame | 316 / 316 | pBootScreen/pGameScreen;pSoundFEV 未动 |
| cPrefab | 52 / 52 | pGame = cGame * |
| WorldSim | 16 / 16 | pSimThread = SimThread * |
| MapComponentBase | 304 / 304 | pMapRenderer = MapRenderer * |
| MapComponent | 400 / 400 | pMapRenderer/pWaveComponent/pRoadManager/pGroundCreep/pNetworkTileRegions = cNetworkTileRegion * *;pNavGrid 未动 |
| QuadTreeNode | 176 / 176 | pRootNode = QuadTreeNode_Node * |
| QuadTreeNode_Node | 56 / 56 | pChild0-3 = QuadTreeNode_Node * |
| cTransformComponent | 380 / 380 | pPhysicsComponent/pFollowerComponent;pPredictionHistory 未动 |
| cPhysicsComponent | 108 / 108 | pTransformComponent/pMotionState = MyMotionState *;pRigidBody 等推断字段未动 |
| cAnimStateComponent | 208 / 208 | pAnimNode = AnimNode *;pUITransformComponent;pAnimStr 等推断字段未动 |
| cImageComponent | 20 / 20 | pTexture = Texture * |
| cSimCamera | 200 / 200 | pSimulation = cSimulation * |
| cFrameWalker | 16 / 16 | pAnim = sAnim * |

结论:75 个「确定」字段全部成功回写;「推断(33)/待定(17)/跳过(104)」未触碰。已 save_program。
