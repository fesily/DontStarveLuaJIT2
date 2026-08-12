# Phase 0 sync-s2-entity — layout dump (dontstarve_steam)

- program: `dontstarve_steam` (macOS i386)
- shard: S2 entity/scene
- processed: 62
- exists: 62
- missing: 0
- source: ghidra-mcp get_struct_layout (read-only)

---

### cEntity
size: 252 (hex 0xfc)
exists: true
layout:
  0 | void * | p__vft
  4 | uint | dwGuid
  8 | char * | pName
  12 | char * | pPrefab
  16 | cHashedString | prefabNameHash
  24 | byte[12] | pChildren
  36 | void * | pParentEntity
  40 | byte[24] | pFollowerComponents
  64 | void * | pSimulation
  68 | byte[12] | pVec_components
  80 | void * | pWorldNode
  84 | void * | pUINode
  88 | byte | bVisible
  89 | byte | bUnknown_0x59
  90 | byte[2] | p_pad5a
  92 | uint | dwGameStep
  96 | byte[72] | pTagset
  168 | void * | pField_0xa8
  172 | byte[24] | pLuaNetVarsMap
  196 | uint | dwDirty_flags
  200 | byte | bSleeping
  201 | byte | bUnknown_0xc9
  202 | byte | bUnknown_0xca
  203 | byte | bUnknown_0xcb
  204 | byte | bUnknown_0xcc
  205 | byte | bInWorld
  206 | byte | bInHud
  207 | byte | bUnknown_0xcf
  208 | byte | bIsPredictingMovement
  209 | byte[3] | p_padd1
  212 | void * | pNetworkComponent
  216 | void * | pTransformComponent
  220 | void * | pAnimStateComponent
  224 | void * | pTransformprovider
  228 | uint | dwField_0xe4
  232 | byte[12] | pWorldposition
  244 | byte | bDisableUnregisterLuaNetVars
  245 | byte[3] | p_padf5
  248 | uint | dwField_0xf8

### cEntityManager
size: 309 (hex 0x135)
exists: true
layout:
  0 | void * | pP__vft
  4 | int | nLocalGuidCounter
  8 | void * | pServerGuidCounter
  12 | cSimulation * | pSimulation
  20 | dword | dwComponentLists_end
  24 | dword | dwComponentLists_endcap
  28 | dword | dwWallUpdateTypes_begin
  32 | dword | dwWallUpdateTypes_end
  36 | dword | dwWallUpdateTypes_endcap
  40 | dword | dwUpdateTypes_begin
  44 | dword | dwUpdateTypes_end
  48 | dword | dwUpdateTypes_endcap
  52 | dword | dwPostUpdateTypes_begin
  56 | dword | dwPostUpdateTypes_end
  60 | dword | dwPostUpdateTypes_endcap
  64 | dword | dwDebugUpdateTypes_begin
  68 | dword | dwDebugUpdateTypes_end
  72 | dword | dwDebugUpdateTypes_endcap
  76 | dword | dwAllEntities_begin
  80 | dword | dwAllEntities_end
  84 | dword | dwAllEntities_endcap
  88 | dword | dwDestroyQueue_begin
  92 | dword | dwDestroyQueue_end
  96 | dword | dwDestroyQueue_endcap
  100 | dword | dwNewEntities_begin
  104 | dword | dwNewEntities_end
  108 | dword | dwNewEntities_endcap
  112 | dword | dwAwakeEntities_begin
  116 | dword | dwAwakeEntities_end
  120 | dword | dwAwakeEntities_endcap
  124 | dword | dwPendingComponentAdditions_begin
  128 | dword | dwPendingComponentAdditions_end
  132 | dword | dwPendingComponentAdditions_endcap
  136 | void * | pComponentFactory
  140 | Mutex | (unnamed)
  196 | int | nField_0xc4
  200 | int | nField_0xc8
  204 | int | nField_0xcc
  208 | byte[40] | pEntityPool
  248 | void * | pSpatialHash
  252 | int | nUiRootGuid
  256 | int | nIsBeingDestroyed
  260 | float | flLastCameraPosition_x
  264 | float | flLastCameraPosition_y
  268 | float | flLastCameraPosition_z
  272 | byte[4] | pPadding_110
  276 | int | nEntityPositionMap_color
  280 | void * | pEntityPositionMap_parent
  284 | void * | pEntityPositionMap_left
  288 | void * | pEntityPositionMap_right
  292 | int | nEntityPositionMap_nodeCount
  296 | int | nDestroyedEntityPositions_begin
  300 | int | nDestroyedEntityPositions_end
  304 | int | nDestroyedEntityPositions_endcap
  308 | byte | bIsProcessingNewEntities

### cSimulation
size: 412 (hex 0x19c)
exists: true
layout:
  0 | void * | pVtable_cGameEventListener
  4 | int | nRbTreeGameEvent_comparator
  8 | int | nRbTreeGameEvent_color
  12 | void * | pRbTreeGameEvent_parent
  16 | void * | pRbTreeGameEvent_left
  20 | void * | pRbTreeGameEvent_right
  24 | int | nRbTreeGameEvent_count
  28 | void * | pVtable_cSystemEventListener
  32 | int | nRbTreeSysEvent_comparator
  36 | int | nRbTreeSysEvent_color
  40 | void * | pRbTreeSysEvent_parent
  44 | void * | pRbTreeSysEvent_left
  48 | void * | pRbTreeSysEvent_right
  52 | int | nRbTreeSysEvent_count
  56 | byte | bPostUpdateTriggered
  57 | byte | bPad_0x39
  58 | byte | bPad_0x3A
  59 | byte | bPad_0x3B
  60 | float | flTimeScale
  64 | void * | pEntityManager
  68 | int | nSimStep
  72 | void * | pSimTime_vtable
  76 | uint | dwSimTime_nTick
  80 | float | flSimTime_fRemainder
  84 | byte | bPhysicsDebugRender
  85 | byte | bPad_0x55
  86 | byte | bPad_0x56
  87 | byte | bPad_0x57
  88 | void * | pLuaState
  92 | void * | pGame
  96 | void * | pWorldSim
  100 | void * | pMainCamera
  104 | void * | pStrScenarioScript
  108 | float | flTimeStep
  112 | void * | pDebugCamera
  116 | int | nField_0x74
  120 | float | flElapsedUpdateTime
  124 | float | flPhysicsTime
  128 | float | flLuaTime
  132 | byte | bLogAllocations
  133 | byte | bTrackAllocsEnabled
  134 | byte | bTrackAllocsActive
  135 | byte | bPad_0x87
  136 | void * | pVecQueuedSysEvents_begin
  140 | void * | pVecQueuedSysEvents_end
  144 | void * | pVecQueuedSysEvents_cap
  148 | Mutex | mutexSysEvents
  204 | void * | pVecQueuedGameEvents_begin
  208 | void * | pVecQueuedGameEvents_end
  212 | void * | pVecQueuedGameEvents_cap
  216 | Mutex | mutexGameEvents
  272 | byte[24] | pMapHashedStringUint
  296 | int | nRefPushEntityEvent
  300 | int | nRefRemoveEntity
  304 | int | nRefUpdate
  308 | int | nRefPostUpdate
  312 | int | nRefWallUpdate
  316 | int | nRefTraceback
  320 | int | nRefOnInputKey
  324 | int | nRefOnInputText
  328 | int | nRefOnMouseButton
  332 | int | nRefOnPhysicsCollision
  336 | int | nRefOnGesture
  340 | int | nRefOnFocusLost
  344 | int | nRefOnFocusGained
  348 | int | nStepsThisFrame
  352 | byte[4] | pRgbAmbientColor
  356 | byte[4] | pRgbaColor2
  360 | void * | pStrJsonSettings
  364 | void * | pStrPurchases
  368 | void * | pBPWorld
  372 | byte | bAbortSim
  373 | byte | bPad_0x175
  374 | byte | bPad_0x176
  375 | byte | bPad_0x177
  376 | float | flAccumulatedSimTime
  380 | void * | pVecUnknown17C_begin
  384 | void * | pVecUnknown17C_end
  388 | void * | pVecUnknown17C_cap
  392 | int | nGCThreshold
  396 | byte | bSkipSim
  397 | byte | bPad_0x18D
  398 | byte | bPad_0x18E
  399 | byte | bPad_0x18F
  400 | void * | pPhysicsThread
  404 | byte | bUseThreadedPhysics
  405 | byte | bPad_0x195
  406 | byte | bPad_0x196
  407 | byte | bPad_0x197
  408 | float | flProfilerTime

### cGame
size: 304 (hex 0x130)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pBaseEventListenerVtable
  8 | int | nRbTreeComparator
  12 | int | nRbTreeColor
  16 | void * | pRbTreeParent
  20 | void * | pRbTreeLeft
  24 | void * | pRbTreeRight
  28 | int | nPauseState
  32 | void * | pSimulation
  36 | byte | bField_0x24
  37 | byte | bPad_0x25
  38 | byte | bPad_0x26
  39 | byte | bPad_0x27
  40 | void * | pWindowManager
  44 | void * | pPostProcessor
  48 | void * | pRenderer
  52 | void * | pVFXEmitterManager
  56 | void * | pQuadTreeNode
  60 | void * | pSceneGraphNode
  64 | void * | pInputManager
  68 | void * | pAnimManager
  72 | void * | pFileManager
  76 | void * | pAtlasManager
  80 | void * | pSoundProjectManager
  84 | void * | pEnvelopeManager
  88 | void * | pMOTDImageLoader
  92 | void * | pField_0x5C
  96 | void * | pGameEventDispatcher
  100 | void * | pSoundSystem
  104 | void * | pStrUnknown68
  108 | byte | bRestarting
  109 | byte | bShutdownRequested
  110 | byte | bField_0x6E
  111 | byte | bPad_0x6F
  112 | uint | dwCurrentTimeMS
  116 | float | flRenderTime
  120 | int | nField_0x78
  124 | byte | bInitializedOnMainThread
  125 | byte | bPad_0x7D
  126 | byte | bPad_0x7E
  127 | byte | bPad_0x7F
  128 | void * | pVecPrefabs_begin
  132 | void * | pVecPrefabs_end
  136 | void * | pVecPrefabs_capacity
  140 | byte | bDebugRender
  141 | byte | bDebugCamera
  142 | byte | bPlaying
  143 | byte | bPad_0x8F
  144 | int | nField_0x90
  148 | void * | pStrInstanceSettings
  152 | uint | dwTexture
  156 | uint | dwRenderBufferA
  160 | uint | dwRenderBufferB
  164 | void * | pRenderTargetA
  168 | void * | pRenderTargetB
  172 | void * | pPersistentStorage
  176 | void * | pSystemService
  180 | void * | pGameService
  184 | int | nEnvelopeColour
  188 | int | nEnvelopeVector2
  192 | uint | dwRenderTarget
  196 | void * | pStrPurchases
  200 | float | flInputScale
  204 | byte | bNetbookMode
  205 | byte | bPad_0xCD
  206 | byte | bPad_0xCE
  207 | byte | bPad_0xCF
  208 | float | flInputScaleDefault
  212 | int | nField_0xD4
  216 | byte | bPerfIndicatorsInitialized
  217 | byte | bPad_0xD9
  218 | byte | bPad_0xDA
  219 | byte | bPad_0xDB
  220 | void * | pPerfSimTime
  224 | void * | pPerfLuaTime
  228 | void * | pPerfPhysicsTime
  232 | void * | pPerfRenderTime
  236 | void * | pPerfFPSAvg
  240 | void * | pPerfPing
  244 | void * | pPerfLUAAvg
  248 | void * | pPerfSimAvg
  252 | void * | pPerfPhysicsAvg
  256 | void * | pPerfRenderAvg
  260 | void * | pPerfPushed
  264 | void * | pPerfSent
  268 | void * | pPerfResent
  272 | void * | pPerfProcessed
  276 | void * | pPerfActualSent
  280 | void * | pPerfPaneAvgTime
  284 | void * | pPerfPaneInstTime
  288 | void * | pPerfPaneNetwork
  292 | void * | pPerfPanePing
  296 | void * | pSystemEventDispatcher
  300 | float | flSmoothFPS

### cDontStarveSim
size: 1148 (hex 0x47c)
exists: true
layout:
  0 | -BAD- | base_cSimulation
  412 | void * | pFreeCamera
  416 | float | flLastCameraRotation
  420 | byte[720] | pInputHandler
  1140 | void * | pSystemService
  1144 | void * | pGameService

### cDontStarveGame
size: 316 (hex 0x13c)
exists: true
layout:
  0 | cGame | base_cGame
  304 | void * | pBootScreen
  308 | void * | pGameScreen
  312 | void * | pSoundFEV

### cPrefab
size: 52 (hex 0x34)
exists: true
layout:
  0 | char * | pName
  4 | int | nFlags
  8 | uint | dwNameHash_dwHash
  12 | char * | pNameHash_pCstr
  16 | char * | pSName2
  20 | void * | pVecAssets_begin
  24 | void * | pVecAssets_end
  28 | void * | pVecAssets_cap
  32 | int | nField_0x20
  36 | void * | pGame
  40 | void * | pVecDeps_begin
  44 | void * | pVecDeps_end
  48 | void * | pVecDeps_cap

### cHashedString
size: 8 (hex 0x8)
exists: true
layout:
  0 | uint | dwHash
  4 | char * | pBuf

### cHashedStringCSL
size: 8 (hex 0x8)
exists: true
layout:
  0 | uint | dwHash
  4 | char * | pCstr

### cHashedStringLookup
size: 84 (hex 0x54)
exists: true
layout:
  0 | void * | pVtable
  4 | Mutex | criticalSection
  60 | void * | pLookupVec_begin
  64 | void * | pLookupVec_end
  68 | void * | pLookupVec_cap
  72 | char * | pStringPool
  76 | char * | pStringPoolEnd
  80 | int | nStringPoolSize

### EntityLuaProxy
size: 16 (hex 0x10)
exists: true
layout:
  0 | -BAD- | pEntity
  4 | -BAD- | pSimulation
  8 | uint | dwGuid
  12 | int | nVersionSnapshot

### WorldSim
size: 16 (hex 0x10)
exists: true
layout:
  0 | void * | pCallbackObj
  4 | void * | pCallbackFunc
  8 | int | nCallbackAdjust
  12 | void * | pSimThread

### WorldSimActual
size: 36 (hex 0x24)
exists: true
layout:
  0 | void * | pLunarBase
  4 | void * | pBoostMap
  8 | void * | pTileGrid
  12 | byte[24] | pLunarMetadata

### SceneGraphNode
size: 145 (hex 0x91)
exists: true
layout:
  0 | pointer | vtable
  4 | ushort | wFlags
  6 | ushort | wPad6
  8 | float | flMatrix0
  12 | float | flMatrix1
  16 | float | flMatrix2
  20 | float | flMatrix3
  24 | float | flMatrix4
  28 | float | flMatrix5
  32 | float | flMatrix6
  36 | float | flMatrix7
  40 | float | flMatrix8
  44 | float | flMatrix9
  48 | float | flMatrix10
  52 | float | flMatrix11
  56 | float | flMatrix12
  60 | float | flMatrix13
  64 | float | flMatrix14
  68 | float | flMatrix15
  72 | uint | dwRenderFlags
  76 | byte | bFlag4C
  77 | byte | bPad4D
  78 | ushort | wField4E
  80 | pointer | pChildren_begin
  84 | pointer | pChildren_end
  90 | ushort | wField5A
  92 | pointer | pGame
  96 | uint | dwNameHash0
  100 | uint | dwNameHash1
  104 | pointer | pParentNode
  108 | uint | dwField6C
  112 | float | flSortDepth
  116 | uint | dwField74
  120 | float | flAabb_min_x
  124 | float | flAabb_min_y
  128 | float | flAabb_min_z
  132 | float | flAabb_max_x
  136 | float | flAabb_max_y
  140 | float | flAabb_max_z
  144 | byte | bAABBDirty

### MapComponentBase
size: 304 (hex 0x130)
exists: true
layout:
  0 | cEntityComponent | base
  16 | byte[232] | pUNKNOWN_0x10
  248 | byte[12] | pVecRenderLayers
  260 | byte[12] | pVecTiles
  272 | byte | bUndergroundLayer
  276 | void * | pMapRenderer
  284 | int | nMapTileCount_pad
  288 | int | nMapTileCount_color
  292 | void * | pMapTileCount_parent
  296 | void * | pMapTileCount_left
  300 | void * | pMapTileCount_right

### MapComponent
size: 400 (hex 0x190)
exists: true
layout:
  0 | MapComponentBase | base
  304 | int | nNumWalkableTiles
  308 | int | nNumUndergroundTiles
  312 | byte[16] | pMMat4_0
  328 | byte[16] | pMMat4_1
  344 | float[4] | pColorScale
  360 | byte | bInitialized
  364 | void * | pNavGrid
  368 | void * | pMapRenderer
  372 | void * | pWaveComponent
  376 | void * | pRoadManager
  380 | void * | pGroundCreep
  384 | void * | pNetworkTileRegions
  388 | int | nField_0x184
  392 | float | flField_0x188
  396 | byte | bFinalized
  397 | byte[3] | p_pad

### MapGenSim
size: 92 (hex 0x5c)
exists: true
layout:
  0 | cEntityComponent | base
  16 | void * | pWorld
  20 | int | nField_0x14
  24 | int | nCollObjCount
  28 | int | nCollObjCap
  32 | void * | pCollObjs
  36 | byte | bAlignedAlloc
  40 | void * | pBroadphase
  44 | void * | pDispatcher
  48 | void * | pSolver
  52 | void * | pConfig
  56 | void * | pVecNodes_begin
  60 | void * | pVecNodes_end
  64 | void * | pVecNodes_cap
  68 | void * | pShapeBox
  72 | void * | pShapeTri
  76 | void * | pShapeCylinder
  80 | byte[12] | pVecConstraints

### Maze
size: 44 (hex 0x2c)
exists: true
layout:
  0 | float | flBounds_minx
  4 | float | flBounds_miny
  8 | float | flBounds_maxx
  12 | float | flBounds_maxy
  16 | void * | pPoints_begin
  20 | void * | pPoints_end
  24 | void * | pPoints_cap
  28 | int | nEMazeType
  32 | int | nField_0x20
  36 | int | nGroundType
  40 | int | nFloorType

### QuadTreeNode
size: 176 (hex 0xb0)
exists: true
layout:
  0 | byte[148] | pBase
  148 | void * | pRootNode
  156 | int | nSet_pad
  160 | int | nSet_color
  164 | void * | pSet_parent
  168 | void * | pSet_left
  172 | void * | pSet_right

### QuadTreeNode_Node
size: 56 (hex 0x38)
exists: true
layout:
  0 | float | flBounds_minx
  4 | float | flBounds_miny
  8 | float | flBounds_maxx
  12 | float | flBounds_maxy
  16 | void * | pChild0
  20 | void * | pChild1
  24 | void * | pChild2
  28 | void * | pChild3
  32 | int | nField_0x20
  36 | int | nSet_pad
  40 | int | nSet_color
  44 | void * | pSet_parent
  48 | void * | pSet_left
  52 | void * | pSet_right

### AStarSearch_PathNode
size: 52 (hex 0x34)
exists: true
layout:
  0 | void * | pVtable
  4 | int | nStatus
  8 | byte[12] | pOpenSet
  20 | byte[12] | pClosedSet
  32 | void * | pParams
  36 | byte[12] | pPath
  48 | float | flSearchTime

### AStarSearch_ulong
size: 52 (hex 0x34)
exists: true
layout:
  0 | void * | pVtable
  4 | int | nStatus
  8 | byte[12] | pOpenSet
  20 | byte[12] | pClosedSet
  32 | void * | pParams
  36 | int | nField_0x24
  40 | int | nField_0x28
  44 | int | nField_0x2C
  48 | float | flSearchTime

### PathfinderComponent
size: 104 (hex 0x68)
exists: true
layout:
  0 | cEntityComponent | base
  16 | int | nField_0x10
  20 | int | nField_0x14
  24 | int | nField_0x18
  28 | int | nMap1_pad
  32 | int | nMap1_color
  36 | void * | pMap1_parent
  40 | void * | pMap1_left
  44 | void * | pMap1_right
  48 | int | nMap1_count
  52 | int | nMap2_pad
  56 | int | nMap2_color
  60 | void * | pMap2_parent
  64 | void * | pMap2_left
  68 | void * | pMap2_right
  72 | int | nMap2_count
  76 | int | nSearches_pad
  80 | int | nSearches_color
  84 | void * | pSearches_parent
  88 | void * | pSearches_left
  92 | void * | pSearches_right
  96 | int | nSearches_count
  100 | int | nNextSearchId

### RoadBuilder
size: 44 (hex 0x2c)
exists: true
layout:
  0 | void * | pVtable
  4 | byte[12] | pVecControlPoints
  16 | int | nRoadCount
  20 | byte[12] | pVecVisibility
  32 | byte[12] | pVecGenerated

### GroundCreep
size: 213 (hex 0xd5)
exists: true
layout:
  0 | byte[16] | base_cEntityComponent
  16 | byte[148] | sceneGraphNode
  164 | float | fAccumTime
  168 | float | field_0xA8
  172 | float | fUpdateInterval
  176 | pointer | pTileGrid1
  180 | pointer | pTileGrid2
  184 | pointer | pByteArray
  188 | pointer | pListBegin
  192 | pointer | pListEnd
  196 | dword | field_0xC4
  200 | pointer | pMapLayerManagerCmp
  204 | pointer | pMapRenderer
  208 | pointer | strEncodedData
  212 | byte | bVBsDirty

### GroundCreepEntity
size: 24 (hex 0x18)
exists: true
layout:
  0 | byte[16] | base_cEntityComponent
  16 | byte | nFlags
  17 | byte[3] | _pad11
  20 | float | fRadius

### MyMotionState
size: 80 (hex 0x50)
exists: true
layout:
  0 | uint | dwField_0x00
  4 | byte[76] | pUNKNOWN

### EnvelopeTemplate
size: 16 (hex 0x10)
exists: true
layout:
  0 | uint | dwField_0x00
  4 | uint | dwField_0x04
  8 | uint | dwField_0x08
  12 | uint | dwField_0x0C

### EnvelopeManager
size: 24 (hex 0x18)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pVecEnvelopes_begin
  8 | void * | pVecEnvelopes_end
  12 | void * | pVecEnvelopes_cap
  16 | byte[8] | pIndexManager

### WaveComponent
size: 144 (hex 0x90)
exists: true
layout:
  0 | cEntityComponent | base
  16 | int | nField_0x10
  20 | int | nField_0x14
  24 | int | nField_0x18
  28 | int | nField_0x1C
  32 | int | nField_0x20
  36 | int | nField_0x24
  40 | int | nField_0x28
  44 | int | nField_0x2C
  48 | int | nField_0x30
  52 | int | nField_0x34
  56 | int | nField_0x38
  60 | int | nField_0x3C
  64 | int | nField_0x40
  68 | int | nField_0x44
  72 | int | nField_0x48
  76 | int | nField_0x4C
  80 | int | nField_0x50
  84 | int | nField_0x54
  88 | int | nField_0x58
  92 | int | nField_0x5C
  96 | int | nField_0x60
  100 | byte[12] | pVec_0x64
  112 | int | nField_0x70
  116 | int | nField_0x74
  120 | int | nField_0x78
  124 | int | nField_0x7C
  128 | int | nField_0x80
  132 | int | nField_0x84
  136 | byte | bField_0x88
  140 | int | nField_0x8C

### FollowerComponent
size: 66 (hex 0x42)
exists: true
layout:
  0 | cEntityComponent | base
  16 | int | nField_0x10
  20 | byte[4] | pSName
  24 | byte[12] | pVec_0x18
  36 | byte[12] | pVec_0x24
  48 | int | nField_0x30
  52 | int | nField_0x34
  56 | byte | bField_0x38
  60 | int | nField_0x3C
  64 | ushort | wField_0x40

### cLabelComponent
size: 20 (hex 0x14)
exists: true
layout:
  0 | cEntityComponent | base
  16 | int | nField_0x10

### cLightEmitterComponent
size: 41 (hex 0x29)
exists: true
layout:
  0 | cEntityComponent | base
  16 | byte[16] | pVecColour_0x10
  32 | int | nColour_0x20
  36 | int | nField_0x24
  40 | byte | bField_0x28

### cLightWatcherComponent
size: 62 (hex 0x3e)
exists: true
layout:
  0 | cEntityComponent | base
  16 | byte | bField_0x10
  20 | int | nField_0x14
  24 | int | nField_0x18
  28 | cSimTime | simTime
  40 | int | nField_0x28
  52 | float | flField_0x34
  56 | float | flField_0x38
  60 | ushort | wField_0x3C

### MiniMapComponent
size: 96 (hex 0x60)
exists: true
layout:
  0 | cEntityComponent | base
  16 | void * | pVtable2
  24 | int | nMap_pad
  28 | int | nMap_color
  32 | void * | pMap_parent
  36 | void * | pMap_left
  40 | void * | pMap_right
  44 | int | nField_0x2C
  48 | int | nField_0x30
  52 | int | nField_0x34
  56 | int | nField_0x38
  60 | int | nField_0x3C
  64 | int | nField_0x40
  68 | int | nField_0x44
  72 | int | nField_0x48
  76 | byte | bField_0x4C
  77 | byte | bField_0x4D
  80 | int | nField_0x50
  84 | int | nField_0x54
  88 | int | nField_0x58
  92 | int | nField_0x5C

### MiniMapEntityComponent
size: 33 (hex 0x21)
exists: true
layout:
  0 | cEntityComponent | base
  16 | int | nField_0x10
  20 | int | nField_0x14
  24 | byte[4] | pSName
  28 | int | nField_0x1C
  32 | byte | bField_0x20

### DebugRenderComponent
size: 232 (hex 0xe8)
exists: true
layout:
  0 | cEntityComponent | base
  16 | byte[148] | pSceneGraphNode
  164 | int | nField_0xA4
  168 | byte | bField_0xA8
  172 | int | nField_0xAC
  176 | int | nField_0xB0
  180 | int | nField_0xB4
  184 | int | nField_0xB8
  188 | int | nField_0xBC
  192 | int | nField_0xC0
  196 | int | nField_0xC4
  200 | int | nField_0xC8
  204 | int | nField_0xCC
  208 | int | nField_0xD0
  212 | int | nField_0xD4
  216 | int | nField_0xD8
  220 | int | nField_0xDC
  224 | int | nField_0xE0
  228 | int | nField_0xE4

### DynamicShadowComponent
size: 36 (hex 0x24)
exists: true
layout:
  0 | cEntityComponent | base
  16 | int | nField_0x10
  20 | int | nField_0x14
  24 | int | nField_0x18
  28 | int | nField_0x1C
  32 | int | nField_0x20

### StaticShadowComponent
size: 36 (hex 0x24)
exists: true
layout:
  0 | cEntityComponent | base
  16 | int | nField_0x10
  20 | int | nField_0x14
  24 | int | nField_0x18
  28 | int | nField_0x1C
  32 | int | nField_0x20

### ShadowManagerComponent
size: 32 (hex 0x20)
exists: true
layout:
  0 | cEntityComponent | base
  16 | int | nField_0x10
  20 | int | nField_0x14
  24 | int | nField_0x18
  28 | int | nField_0x1C

### GraphicsOptionsComponent
size: 16 (hex 0x10)
exists: true
layout:
  0 | cEntityComponent | base

### PostProcessorComponent
size: 16 (hex 0x10)
exists: true
layout:
  0 | cEntityComponent | base

### RoadManagerComponent
size: 248 (hex 0xf8)
exists: true
layout:
  0 | cEntityComponent | base
  16 | byte[148] | pSceneGraphNode
  164 | byte[44] | pRoadBuilder
  208 | int | nField_0xD0
  212 | int | nField_0xD4
  216 | int | nField_0xD8
  220 | int | nField_0xDC
  224 | int | nField_0xE0
  228 | int | nField_0xE4
  232 | int | nField_0xE8
  236 | int | nField_0xEC
  240 | int | nField_0xF0
  244 | int | nField_0xF4

### TwitchComponent
size: 48 (hex 0x30)
exists: true
layout:
  0 | cEntityComponent | base
  16 | void * | pVtable2
  24 | int | nMap_pad
  28 | int | nMap_color
  32 | void * | pMap_parent
  36 | void * | pMap_left
  40 | void * | pMap_right
  44 | int | nField_0x2C

### cUITransformComponent
size: 388 (hex 0x184)
exists: true
layout:
  0 | cEntityComponent | base
  16 | void * | pVtable2
  20 | void * | pVtable3
  28 | int | nMap1_pad
  32 | int | nMap1_color
  36 | void * | pMap1_parent
  40 | void * | pMap1_left
  44 | void * | pMap1_right
  48 | void * | pVtable4
  56 | int | nMap2_pad
  60 | int | nMap2_color
  64 | void * | pMap2_parent
  68 | void * | pMap2_left
  72 | void * | pMap2_right
  76 | int | nField_0x4C
  80 | int | nField_0x50
  84 | int | nField_0x54
  88 | int | nField_0x58
  92 | int | nField_0x5C
  96 | int | nField_0x60
  100 | int | nField_0x64
  104 | int | nField_0x68
  108 | int | nField_0x6C
  112 | float | flField_0x70
  116 | float | flField_0x74
  120 | float | flField_0x78
  124 | int | nField_0x7C
  128 | byte[256] | pUNKNOWN_0x80
  384 | float | flField_0x180

### cShardClientComponent
size: 30 (hex 0x1e)
exists: true
layout:
  0 | cEntityComponent | base
  16 | void * | pList
  20 | void * | pList_0x14_next
  24 | void * | pList_0x14_prev
  28 | ushort | wField_0x1C

### cShardNetworkComponent
size: 21 (hex 0x15)
exists: true
layout:
  0 | cEntityComponent | base
  16 | int | nField_0x10
  20 | byte | bField_0x14

### cSerializableEntityComponent
size: 16 (hex 0x10)
exists: true
layout:
  0 | cEntityComponent | base

### cTransformComponent
size: 380 (hex 0x17c)
exists: true
layout:
  0 | cEntityComponent | base_cEntityComponent
  16 | void * | pTransformProviderVtable
  20 | void * | pPhysicsComponent
  24 | void * | pFollowerComponent
  28 | float | flLocalPosX
  32 | float | flLocalPosY
  36 | float | flLocalPosZ
  40 | float | flServerPosX
  44 | float | flServerPosY
  48 | float | flServerPosZ
  52 | float | flWorldPosX
  56 | float | flWorldPosY
  60 | float | flWorldPosZ
  64 | float | flScaleX
  68 | float | flScaleY
  72 | float | flScaleZ
  76 | float | flServerScaleX
  80 | float | flServerScaleY
  84 | float | flServerScaleZ
  88 | float | flRotation
  92 | float | flServerRotation
  96 | byte[64] | pMatLocalTransform
  160 | byte[64] | pMatLocalTransformInverse
  224 | byte[64] | pMatWorldTransform
  288 | byte[64] | pMatWorldTransformInverse
  352 | int | nFacing
  356 | int | nEFacingModel
  360 | cTransformationHistory * | pTransformHistory
  364 | void * | pPredictionHistory
  368 | int | nPredictionStep
  372 | int | nPredictionEnabled
  376 | ushort | wPristineDirtyFlags
  378 | ushort | wCurrentDirtyFlags

### cPhysicsComponent
size: 108 (hex 0x6c)
exists: true
layout:
  0 | byte[16] | pBase_cEntityComponent
  16 | void * | pTransformComponent
  20 | float | flRadius
  24 | float | flMass
  28 | float | flHeight
  32 | float | flStationaryDamping
  36 | void * | pPhysicsWorldSim
  40 | int | nECollisionShape
  44 | float | flFriction
  48 | float | flMotorVelX
  52 | float | flMotorVelY
  56 | float | flMotorVelZ
  60 | float | flSavedMotorVelX
  64 | float | flSavedMotorVelY
  68 | float | flSavedMotorVelZ
  72 | void * | pRigidBody
  76 | void * | pCollisionShape
  80 | void * | pCompoundShape
  84 | void * | pMotionState
  88 | float | flRestitution
  92 | byte | bActive
  93 | byte | bDontRemoveOnSleep
  94 | byte[2] | p_pad5E
  96 | dword | dwCollisionFlags
  100 | short | nCollisionMask
  102 | short | nCollisionGroup
  104 | ushort | wPristineFlags
  106 | ushort | wDirtyFlags

### cAnimStateComponent
size: 208 (hex 0xd0)
exists: true
layout:
  0 | cEntityComponent | base_cEntityComponent
  16 | void * | pBBoxProviderVtable
  20 | float | flAnimTime
  24 | float | flDeltaTimeMultiplier
  28 | uint | dwAnimHash
  32 | void * | pAnimStr
  36 | uint | dwBankHash
  40 | void * | pBankStr
  44 | uint | dwBuildHash
  48 | void * | pBuildStr
  52 | uint | dwSkinHash
  56 | void * | pSkinStr
  60 | uint | dwOverrideBuildHash
  64 | void * | pOverrideBuildStr
  68 | int | nEPlayMode
  72 | int | nEQueuedPlayMode
  76 | byte | bRayTestOnBB
  77 | byte | bHidden
  78 | byte[2] | pPad_0x4E
  80 | uint | dwPristineDirtyFlags
  84 | uint | dwCurrentDirtyFlags
  88 | uint | dwDeserializedAnimHash
  92 | uint | dwQueuedAnimHash
  96 | uint | dwRgbaAddColour
  100 | uint | dwRgbaMultColour
  104 | uint | dwRgbaOverrideAddColour
  108 | uint | dwRgbaOverrideMultColour
  112 | float | flOverrideShade
  116 | float | flScaleX
  120 | float | flScaleY
  124 | float | flFinalOffsetX
  128 | float | flFinalOffsetY
  132 | float | flFinalOffsetZ
  136 | byte | bHasOverrideAddColour
  137 | byte | bHasOverrideMultColour
  138 | byte[2] | pPad_0x8A
  140 | int | nField_0x8C
  144 | float | flHauntStrength
  148 | void * | pAnimNode
  152 | void * | pVecAnimQueue_begin
  156 | void * | pVecAnimQueue_end
  160 | void * | pVecAnimQueue_cap
  164 | int | nSortOrder
  168 | void * | pAnimBankResource
  172 | void * | pUITransformComponent
  176 | float | flBBMinX
  180 | float | flBBMinY
  184 | float | flBBMinZ
  188 | float | flBBMaxX
  192 | float | flBBMaxY
  196 | float | flBBMaxZ
  200 | byte | bManualHitRegion
  201 | byte[3] | pPad_0xC9
  204 | void * | pSymbolExchangeTree

### EnvelopeComponent
size: 28 (hex 0x1c)
exists: true
layout:
  0 | cEntityComponent | base
  16 | void * | pVecEnvelopes_begin
  20 | void * | pVecEnvelopes_end
  24 | void * | pVecEnvelopes_cap

### cSoundEmitterComponent
size: 84 (hex 0x54)
exists: true
layout:
  0 | cEntityComponent | base
  16 | void * | pVtable
  20 | int | nField_0x14
  24 | int | nField_0x18
  28 | int | nField_0x1C
  32 | int | nField_0x20
  36 | int | nField_0x24
  40 | int | nField_0x28
  44 | int | nField_0x2C
  48 | int | nField_0x30
  52 | int | nField_0x34
  56 | int | nField_0x38
  60 | int | nField_0x3C
  64 | int | nField_0x40
  68 | int | nField_0x44
  72 | int | nField_0x48
  76 | int | nField_0x4C
  80 | int | nField_0x50

### cImageComponent
size: 20 (hex 0x14)
exists: true
layout:
  0 | cEntityComponent | base
  16 | void * | pTexture

### cPController
size: 25 (hex 0x19)
exists: true
layout:
  0 | float | flField_0x00
  4 | float | flField_0x04
  8 | float | flField_0x08
  12 | float | flField_0x0C
  16 | float | flField_0x10
  20 | float | flField_0x14
  24 | bool | fField_0x18

### cCameraInfo
size: 192 (hex 0xc0)
exists: true
layout:
  0 | byte[12] | pPos
  12 | byte[12] | pDir
  24 | byte[12] | pUp
  36 | byte[8] | pScreenSize
  44 | float | flFov
  48 | float | flHeading
  52 | float | flMinDist
  56 | float | flMaxDist
  60 | byte[64] | pViewMatrix
  124 | byte[64] | pProjMatrix
  188 | int | nFlags

### cSimCamera
size: 200 (hex 0xc8)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pSimulation
  8 | cCameraInfo | cameraInfo

### cFreeCamera
size: 332 (hex 0x14c)
exists: true
layout:
  0 | cSimCamera | base
  200 | cFreeCamera_sParams | params
  224 | byte[12] | pPosition
  236 | cPController | zoomController
  264 | cPController | headingController
  292 | byte[8] | pHeading
  320 | byte[12] | pFocusPos

### cFrameWalker
size: 16 (hex 0x10)
exists: true
layout:
  0 | void * | pAnim
  4 | int | nEPlayMode
  8 | int | nFrameIndex
  12 | int | nFramesRemaining

### ShadowEntityComponent
size: 27 (hex 0x1b)
exists: true
layout:
  0 | cEntityComponent | base
  16 | float | flSizeX
  20 | float | flSizeY
  24 | byte | bEnabled
  25 | byte | bPristine
  26 | byte | bFlags

### SimplexNoise
size: 2052 (hex 0x804)
exists: true
layout:
  0 | void * | pVtable
  4 | byte[256] | pPerm
  260 | byte[768] | pUNKNOWN_0x104
  1028 | byte[256] | pPermMod12
  1284 | byte[768] | pUNKNOWN_0x504

### VFXEmitterManager
size: 4100 (hex 0x1004)
exists: true
layout:
  0 | void * | pVtable
  4 | byte[4096] | pEmitterSlots

