// ============================================================================
// DST core type layouts — recovered from dontstarve_steam (macOS i386, base 0x1000)
// Binary: macos_7654020901729138319/dontstarve_steam  (old version)
// Toolchain: ghidra-mcp (struct baseline) + idalib-mcp (cross-verify)
// Pointer width: 4 bytes (i386)
// ============================================================================
// 字段名规则:
//   UNKNOWN_0xXX — 偏移已知、语义未定(见 tier0-core.md 未知字段汇总)
//   所有多态类开头为 vtable 指针 (offset 0)
// 证据链见 docs/superpowers/type-recovery/evidence-chain.md
// ============================================================================
#pragma once
#include <stdint.h>

// ---------------------------------------------------------------------------
// Mutex / CriticalSection (pthread wrapper)
// ctor 0x272f5c; pthread_mutex_t (44B) + pthread_mutexattr_t (12B)
// ---------------------------------------------------------------------------
struct Mutex {
    int32_t  __sig;            // 0x00 pthread_mutex_t
    uint8_t  __opaque[40];     // 0x04
    int32_t  attr_sig;         // 0x2C pthread_mutexattr_t
    uint8_t  attr_opaque[8];   // 0x30
};                             // total 0x38 = 56
typedef Mutex CriticalSection; // alias (0x26ffe6 → 0x27309c)

// ---------------------------------------------------------------------------
// cHashedString (defined in IDB, 8 bytes)
// ---------------------------------------------------------------------------
struct cHashedString {
    uint32_t hash;             // 0x00
    char*    buf;              // 0x04
};

// cHashedStringCSL = hash + const char* (same layout, ctor via Set)
struct cHashedStringCSL {
    uint32_t hash;             // 0x00
    const char* cstr;          // 0x04
};

// cStdString — libstdc++ COW 旧 ABI string (4B, data pointer only)
// created in Ghidra by RetypePending (retype-pending.md)
struct cStdString {
    void* pRepData;            // 0x00
};                             // total 0x4 = 4

// ---------------------------------------------------------------------------
// cEntityComponent — base class of all components (16 bytes)
// ---------------------------------------------------------------------------
struct cEntityComponent {
    void*     p__vtf;          // 0x00
    uint8_t   bAwakeFlag;      // 0x04
    uint8_t   pad05[3];        // 0x05
    void*     pVec_component;  // 0x08
    struct cEntity* pEntity;   // 0x0C
};

// ---------------------------------------------------------------------------
// cEntityManager (309 bytes) — ctor 0xd2796
// ---------------------------------------------------------------------------
struct cEntityManager {
    void*    pP__vft;                                  // 0x00
    int32_t  nLocalGuidCounter;                        // 0x04
    void*    pServerGuidCounter;                       // 0x08
    struct cSimulation* pSimulation;                   // 0x0C (cSimulation*)
    // vec 头 (begin/end/cap × 9)
    void*    componentLists_begin;                     // 0x14
    void*    componentLists_end;                       // 0x18
    void*    componentLists_cap;                       // 0x1C
    void*    wallUpdateTypes_begin;                    // 0x1C
    void*    wallUpdateTypes_end;                      // 0x20
    void*    wallUpdateTypes_cap;                      // 0x24
    void*    updateTypes_begin;                        // 0x28
    void*    updateTypes_end;                          // 0x2C
    void*    updateTypes_cap;                          // 0x30
    void*    postUpdateTypes_begin;                    // 0x34
    void*    postUpdateTypes_end;                      // 0x38
    void*    postUpdateTypes_cap;                      // 0x3C
    void*    debugUpdateTypes_begin;                   // 0x40
    void*    debugUpdateTypes_end;                     // 0x44
    void*    debugUpdateTypes_cap;                     // 0x48
    void*    allEntities_begin;                        // 0x4C
    void*    allEntities_end;                          // 0x50
    void*    allEntities_cap;                          // 0x54
    void*    destroyQueue_begin;                       // 0x58
    void*    destroyQueue_end;                         // 0x5C
    void*    destroyQueue_cap;                         // 0x60
    void*    newEntities_begin;                        // 0x64
    void*    newEntities_end;                          // 0x68
    void*    newEntities_cap;                          // 0x6C
    void*    awakeEntities_begin;                      // 0x70
    void*    awakeEntities_end;                        // 0x74
    void*    awakeEntities_cap;                        // 0x78
    void*    pendingComponentAdditions_begin;          // 0x7C
    void*    pendingComponentAdditions_end;            // 0x80
    void*    pendingComponentAdditions_cap;            // 0x84
    cBaseFactory* pComponentFactory;                   // 0x88
    Mutex    criticalSection;                          // 0x8C (56B)
    int32_t  UNKNOWN_0xC4;                             // 0xC4
    int32_t  UNKNOWN_0xC8;                             // 0xC8
    int32_t  UNKNOWN_0xCC;                             // 0xCC
    uint8_t  entityPool[40];                           // 0xD0
    void*    pSpatialHash;                             // 0xF8 TODO: cSpatialHash_cEntity*
    int32_t  nUiRootGuid;                              // 0xFC
    int32_t  nIsBeingDestroyed;                        // 0x100
    float    flLastCameraPosition[3];                  // 0x104
    uint8_t  padding_110[4];                           // 0x110
    int32_t  entityPositionMap_color;                  // 0x114 RBTree 头
    void*    entityPositionMap_parent;                 // 0x118
    void*    entityPositionMap_left;                   // 0x11C
    void*    entityPositionMap_right;                  // 0x120
    int32_t  entityPositionMap_nodeCount;              // 0x124
    int32_t  destroyedEntityPositions_begin;           // 0x128
    int32_t  destroyedEntityPositions_end;             // 0x12C
    int32_t  destroyedEntityPositions_cap;             // 0x130
    uint8_t  bIsProcessingNewEntities;                 // 0x134
};                                                     // total 0x135 = 309

// ---------------------------------------------------------------------------
// cEntity (defined in IDB, 252 bytes / 39 members — 恢复基准)
// ---------------------------------------------------------------------------
struct cEntity {
    void*             __vft;            // 0x00
    uint32_t          guid;             // 0x04
    char*             name;             // 0x08
    char*             prefab;           // 0x0C
    cHashedString     prefabNameHash;   // 0x10
    void*             children_begin;   // 0x18 StdVectorEntityPtr
    void*             children_end;     // 0x1C
    void*             children_cap;     // 0x20
    struct cEntity*   parentEntity;     // 0x24
    // RbTreeFollowerComponents @ 0x28 (24B)
    int32_t           follower_color;   // 0x28
    void*             follower_parent;  // 0x2C
    void*             follower_left;    // 0x30
    void*             follower_right;   // 0x34
    int32_t           follower_count;   // 0x38
    int32_t           follower_cmp;     // 0x3C
    struct cSimulation* simulation;     // 0x40
    void*             components_begin; // 0x44 StdVectorComponentPtr
    void*             components_end;   // 0x48
    void*             components_cap;   // 0x4C
    SceneGraphNode*   worldNode;        // 0x50
    SceneGraphNode*   UINode;           // 0x54
    uint8_t           visible;          // 0x58
    uint8_t           UNKNOWN_0x59;     // 0x59
    uint8_t           pad5a[2];         // 0x5A
    uint32_t          gameStep;         // 0x5C
    uint8_t           tagset[72];       // 0x60 TagSet
    void*             UNKNOWN_0xA8;     // 0xA8
    // RbTreeLuaNetVarsMap @ 0xAC (24B)
    int32_t           luaNetVars_color; // 0xAC
    void*             luaNetVars_parent;// 0xB0
    void*             luaNetVars_left;  // 0xB4
    void*             luaNetVars_right; // 0xB8
    int32_t           luaNetVars_count; // 0xBC
    int32_t           luaNetVars_cmp;   // 0xC0
    uint32_t          dirty_flags;      // 0xC4
    uint8_t           sleeping;         // 0xC8
    uint8_t           unknown_0xc9;     // 0xC9
    uint8_t           unknown_0xca;     // 0xCA
    uint8_t           unknown_0xcb;     // 0xCB
    uint8_t           unknown_0xcc;     // 0xCC
    uint8_t           inWorld;          // 0xCD
    uint8_t           inHud;            // 0xCE
    uint8_t           unknown_0xcf;     // 0xCF
    uint8_t           isPredictingMovement; // 0xD0
    uint8_t           _padd1[3];        // 0xD1
    cNetworkComponent* networkComponent; // 0xD4
    cTransformComponent* transformComponent; // 0xD8
    cAnimStateComponent* animStateComponent; // 0xDC
    void*             transformprovider; // 0xE0 /* TODO: cTransformProvider* */
    uint32_t          field_0xe4;       // 0xE4
    uint8_t           worldposition[12];// 0xE8 Vector3f
    uint8_t           disableUnregisterLuaNetVars; // 0xF4
    uint8_t           _padf5[3];        // 0xF5
    uint32_t          field_0xf8;       // 0xF8
};

// ---------------------------------------------------------------------------
// cSimulation (412 bytes) — ctor 0xf71d2, vtables 0x456728/0x45675c
// ---------------------------------------------------------------------------
struct cSimulation {
    void*    pVtable_cGameEventListener;      // 0x00 → 0x456728
    // RbTree<cGameEvent> 头
    int32_t  nRbTreeGameEvent_comparator;     // 0x04
    int32_t  nRbTreeGameEvent_color;          // 0x08
    void*    pRbTreeGameEvent_parent;         // 0x0C
    void*    pRbTreeGameEvent_left;           // 0x10
    void*    pRbTreeGameEvent_right;          // 0x14
    int32_t  nRbTreeGameEvent_count;          // 0x18
    void*    pVtable_cSystemEventListener;    // 0x1C → 0x45675C
    // RbTree<SystemEvent> 头
    int32_t  nRbTreeSysEvent_comparator;      // 0x20
    int32_t  nRbTreeSysEvent_color;           // 0x24
    void*    pRbTreeSysEvent_parent;          // 0x28
    void*    pRbTreeSysEvent_left;            // 0x2C
    void*    pRbTreeSysEvent_right;           // 0x30
    int32_t  nRbTreeSysEvent_count;           // 0x34
    uint8_t  bPostUpdateTriggered;            // 0x38
    uint8_t  pad39[3];                        // 0x39
    float    flTimeScale;                     // 0x3C
    cEntityManager* pEntityManager;           // 0x40
    int32_t  nSimStep;                        // 0x44
    // cSimTime 子对象 @ 0x48 (12B)
    void*    pSimTime_vtable;                 // 0x48
    uint32_t dwSimTime_nTick;                 // 0x4C
    float    flSimTime_fRemainder;            // 0x50
    uint8_t  bPhysicsDebugRender;             // 0x54
    uint8_t  pad55[3];                        // 0x55
    void*    pLuaState; /* TODO: lua_State* */   // 0x58 lua_State*
    struct cGame* pGame;                      // 0x5C
    struct WorldSim* pWorldSim;               // 0x60 WorldSim*
    struct cSimCamera* pMainCamera;           // 0x64 cSimCamera*
    void*    pStrScenarioScript;              // 0x68 std::string*
    float    flTimeStep;                      // 0x6C (0.001f)
    struct cSimCamera* pDebugCamera;          // 0x70 cSimCamera*
    int32_t  UNKNOWN_0x74;                    // 0x74 (ctor: -1)
    float    flElapsedUpdateTime;             // 0x78
    float    flPhysicsTime;                   // 0x7C
    float    flLuaTime;                       // 0x80
    uint8_t  bLogAllocations;                 // 0x84
    uint8_t  bTrackAllocsEnabled;             // 0x85
    uint8_t  bTrackAllocsActive;              // 0x86
    uint8_t  pad87[1];                        // 0x87
    void*    pVecQueuedSysEvents_begin;       // 0x88
    void*    pVecQueuedSysEvents_end;         // 0x8C
    void*    pVecQueuedSysEvents_cap;         // 0x90
    Mutex    mutexSysEvents;                  // 0x94 (56B)
    void*    pVecQueuedGameEvents_begin;      // 0xCC
    void*    pVecQueuedGameEvents_end;        // 0xD0
    void*    pVecQueuedGameEvents_cap;        // 0xD4
    Mutex    mutexGameEvents;                 // 0xD8 (56B)
    uint8_t  pMapHashedStringUint[24];        // 0x110 eastl hash_map 头
    int32_t  nRefPushEntityEvent;             // 0x128
    int32_t  nRefRemoveEntity;                // 0x12C
    int32_t  nRefUpdate;                      // 0x130
    int32_t  nRefPostUpdate;                  // 0x134
    int32_t  nRefWallUpdate;                  // 0x138
    int32_t  nRefTraceback;                   // 0x13C
    int32_t  nRefOnInputKey;                  // 0x140
    int32_t  nRefOnInputText;                 // 0x144
    int32_t  nRefOnMouseButton;               // 0x148
    int32_t  nRefOnPhysicsCollision;          // 0x14C
    int32_t  nRefOnGesture;                   // 0x150
    int32_t  nRefOnFocusLost;                 // 0x154
    int32_t  nRefOnFocusGained;               // 0x158
    int32_t  nStepsThisFrame;                 // 0x15C
    uint8_t  pRgbAmbientColor[4];             // 0x160
    uint8_t  pRgbaColor2[4];                  // 0x164
    cStdString pStrJsonSettings;              // 0x168
    cStdString pStrPurchases;                 // 0x16C
    struct cBPWorld* pBPWorld;                // 0x170 cBPWorld*
    uint8_t  bAbortSim;                       // 0x174
    uint8_t  pad175[3];                       // 0x175
    float    flAccumulatedSimTime;            // 0x178
    void*    pVecUnknown17C_begin;            // 0x17C
    void*    pVecUnknown17C_end;              // 0x180
    void*    pVecUnknown17C_cap;              // 0x184
    int32_t  nGCThreshold;                    // 0x188
    uint8_t  bSkipSim;                        // 0x18C
    uint8_t  pad18D[3];                       // 0x18D
    struct Thread* pPhysicsThread;            // 0x190 Thread*
    uint8_t  bUseThreadedPhysics;             // 0x194
    uint8_t  pad195[3];                       // 0x195
    float    flProfilerTime;                  // 0x198
};                                            // total 0x19C = 412

// ---------------------------------------------------------------------------
// cGame (304 bytes) — vtable 0x4567d8
// ---------------------------------------------------------------------------
struct cGame {
    void*    pVtable;                         // 0x00
    void*    pBaseEventListenerVtable;        // 0x04
    int32_t  nRbTreeComparator;               // 0x08
    int32_t  nRbTreeColor;                    // 0x0C
    void*    pRbTreeParent;                   // 0x10
    void*    pRbTreeLeft;                     // 0x14
    void*    pRbTreeRight;                    // 0x18
    int32_t  nPauseState;                     // 0x1C
    struct cSimulation* pSimulation;          // 0x20
    uint8_t  bField_0x24;                     // 0x24
    uint8_t  pad25[3];                        // 0x25
    void*    pWindowManager;                  // 0x28
    PostProcessor* pPostProcessor;            // 0x2C
    Renderer* pRenderer;                      // 0x30
    VFXEmitterManager* pVFXEmitterManager;    // 0x34
    QuadTreeNode* pQuadTreeNode;              // 0x38
    SceneGraphNode* pSceneGraphNode;          // 0x3C
    void*    pInputManager; /* TODO: Input_SDLInputManager* */ // 0x40
    AnimManager* pAnimManager;                // 0x44
    void*    pFileManager; /* TODO: FileManager* */       // 0x48
    AtlasManager* pAtlasManager;              // 0x4C
    void*    pSoundProjectManager; /* TODO: SoundProjectManager* */ // 0x50
    EnvelopeManager* pEnvelopeManager;        // 0x54
    void*    pMOTDImageLoader; /* TODO: MOTDImageLoader* */ // 0x58
    void*    pField_0x5C;                     // 0x5C
    void*    pGameEventDispatcher; /* TODO: cEventDispatcher* */ // 0x60
    cSoundSystem* pSoundSystem;               // 0x64
    void*    pStrUnknown68;                   // 0x68
    uint8_t  bRestarting;                     // 0x6C
    uint8_t  bShutdownRequested;              // 0x6D
    uint8_t  bField_0x6E;                     // 0x6E
    uint8_t  pad6F[1];                        // 0x6F
    uint32_t dwCurrentTimeMS;                 // 0x70
    float    flRenderTime;                    // 0x74
    int32_t  nField_0x78;                     // 0x78
    uint8_t  bInitializedOnMainThread;        // 0x7C
    uint8_t  pad7D[3];                        // 0x7D
    void*    pVecPrefabs_begin;               // 0x80
    void*    pVecPrefabs_end;                 // 0x84
    void*    pVecPrefabs_cap;                 // 0x88
    uint8_t  bDebugRender;                    // 0x8C
    uint8_t  bDebugCamera;                    // 0x8D
    uint8_t  bPlaying;                        // 0x8E
    uint8_t  pad8F[1];                        // 0x8F
    int32_t  nField_0x90;                     // 0x90
    cStdString pStrInstanceSettings;          // 0x94
    uint32_t dwTexture;                       // 0x98
    uint32_t dwRenderBufferA;                 // 0x9C
    uint32_t dwRenderBufferB;                 // 0xA0
    RenderTarget* pRenderTargetA;             // 0xA4
    RenderTarget* pRenderTargetB;             // 0xA8
    PersistentStorage* pPersistentStorage;    // 0xAC
    DontStarveSystemService* pSystemService;  // 0xB0
    DontStarveGameService* pGameService;      // 0xB4
    int32_t  nEnvelopeColour;                 // 0xB8
    int32_t  nEnvelopeVector2;                // 0xBC
    uint32_t dwRenderTarget;                  // 0xC0
    cStdString pStrPurchases;                 // 0xC4
    float    flInputScale;                    // 0xC8
    uint8_t  bNetbookMode;                    // 0xCC
    uint8_t  padCD[3];                        // 0xCD
    float    flInputScaleDefault;             // 0xD0
    int32_t  nField_0xD4;                     // 0xD4
    uint8_t  bPerfIndicatorsInitialized;      // 0xD8
    uint8_t  padD9[3];                        // 0xD9
    PerfIndicator* pPerfSimTime;              // 0xDC
    PerfIndicator* pPerfLuaTime;              // 0xE0
    PerfIndicator* pPerfPhysicsTime;          // 0xE4
    PerfIndicator* pPerfRenderTime;           // 0xE8
    PerfIndicator* pPerfFPSAvg;               // 0xEC
    PerfIndicator* pPerfPing;                 // 0xF0
    PerfIndicator* pPerfLUAAvg;               // 0xF4
    PerfIndicator* pPerfSimAvg;               // 0xF8
    PerfIndicator* pPerfPhysicsAvg;           // 0xFC
    PerfIndicator* pPerfRenderAvg;            // 0x100
    PerfIndicator* pPerfPushed;               // 0x104
    PerfIndicator* pPerfSent;                 // 0x108
    PerfIndicator* pPerfResent;               // 0x10C
    PerfIndicator* pPerfProcessed;            // 0x110
    PerfIndicator* pPerfActualSent;           // 0x114
    PerfPane*      pPerfPaneAvgTime;          // 0x118
    PerfPane*      pPerfPaneInstTime;         // 0x11C
    PerfPane*      pPerfPaneNetwork;          // 0x120
    PerfPane*      pPerfPanePing;             // 0x124
    void*    pSystemEventDispatcher; /* TODO: cEventDispatcher* */ // 0x128
    float    flSmoothFPS;                     // 0x12C
};                                            // total 0x130 = 304

// ---------------------------------------------------------------------------
// cDontStarveSettings (28 bytes) — vtable 0x45d9d0, ctor 内联
// 修正:MultiFileSettings 实为 24B (std::_Rb_tree 头, pad@0..count@0x14)
// ---------------------------------------------------------------------------
struct SettingFile; // 56B, 见下
struct MultiFileSettings {
    int32_t  nAllocPad;              // 0x00 allocator 基类
    int32_t  nColor;                 // 0x04
    void*    pParent;                // 0x08 (root)
    void*    pLeft;                  // 0x0C
    void*    pRight;                 // 0x10
    int32_t  nCount;                 // 0x14
};                                   // total 0x18 = 24 (std::map<string,SettingFile*>)
struct SettingFile {
    // CSimpleIniTempl<char,SI_GenericNoCase,SI_ConvertA> 包装 (ctor 0x285844)
    int32_t  nDataSize;              // 0x00
    int32_t  nField_0x04;            // 0x04
    int32_t  nField_0x08;            // 0x08
    int32_t  map_pad;                // 0x0C std::map<Entry,multimap<...>> 头
    int32_t  map_color;              // 0x10
    void*    map_parent;             // 0x14
    void*    map_left;               // 0x18
    void*    map_right;              // 0x1C
    int32_t  map_count;              // 0x20
    void*    list_next;              // 0x24 std::list<Entry>
    void*    list_prev;              // 0x28
    uint8_t  cfgByte0;               // 0x2C
    uint8_t  bMultiKeyGate;          // 0x2D
    uint8_t  cfgByte2;               // 0x2E
    uint8_t  bMultiKeyEnabled;       // 0x2F
    int32_t  nUnmatched;             // 0x30
    uint8_t  m_strFileName[4];       // 0x34 std::string (CoW)
};                                   // total 0x38 = 56
struct cDontStarveSettings {
    void*    pVtable;                // 0x00 → 0x45d9d0
    MultiFileSettings settings;      // 0x04
};                                   // total 0x1C = 28

// ---------------------------------------------------------------------------
// cNetworkComponent (684 bytes) — ctor 0x5adec
// ---------------------------------------------------------------------------
struct cNetworkComponent {
    cEntityComponent base_cEntityComponent;    // 0x00 (16B)
    uint8_t  replica3Base[344];                // 0x10 Replica3 基类
    int32_t  nField_0x168;                     // 0x168
    int32_t  nField_0x16C;                     // 0x16C
    uint8_t  bIsSleeping;                    // 0x170
    uint8_t  bField_0x171;                     // 0x171
    uint8_t  pad172[2];                        // 0x172
    uint32_t dwSleepingFlagsLower;             // 0x174
    uint32_t dwSleepingFlagsUpper;             // 0x178
    uint8_t  mOwnerGUID[8];                    // 0x17C
    uint16_t wMOwnerSystemIndex;               // 0x184
    uint8_t  pad186[2];                        // 0x186
    uint8_t  mClassifiedTargetGUID[8];         // 0x188
    uint16_t wMClassifiedTargetIndex;          // 0x190
    uint8_t  pad192[2];                        // 0x192
    uint8_t  bitStream[276];                   // 0x194 RakNet::BitStream
    int32_t  nSerializeState;                  // 0x2A8
};                                            // total 0x2AC = 684

// ---------------------------------------------------------------------------
// EntityLuaProxy (16 bytes) — ctor 0xe171c
// 注:非 cEntity 头部复用,是独立 4 字段;CheckPointer (0xe17be) 刷新 +0
// ---------------------------------------------------------------------------
struct EntityLuaProxy {
    struct cEntity*   pEntity;      // 0x00 (失效时经 GetEntityByGUID 刷新)
    struct cSimulation* pSimulation;// 0x04
    uint32_t          guid;         // 0x08
    int32_t           versionSnapshot; // 0x0C (entity manager 版本计数)
};

// ---------------------------------------------------------------------------
// cPrefab (52 bytes) — ctor 0xf5bf6, dtor 0xebfac
// 修正(Tier 3-B):nameHash @ +0x08 非 +0x00;vecAssets @ +0x14;vecDeps @ +0x28
// ---------------------------------------------------------------------------
struct cPrefab {
    char*    pName;                 // 0x00 name string _M_p
    int32_t  nFlags;                // 0x04
    uint32_t nameHash_dwHash;       // 0x08
    char*    nameHash_pCstr;        // 0x0C
    char*    sName2;                // 0x10
    void*    vecAssets_begin;       // 0x14 vector<sPrefabAsset>
    void*    vecAssets_end;         // 0x18
    void*    vecAssets_cap;         // 0x1C
    int32_t  nField_0x20;           // 0x20
    struct cGame* pGame;            // 0x24
    void*    vecDeps_begin;         // 0x28 vector<string>
    void*    vecDeps_end;           // 0x2C
    void*    vecDeps_cap;           // 0x30
};                                   // total 0x34 = 52

// ---------------------------------------------------------------------------
// cHashedStringLookup (92 bytes) — ctor 0x284002, singleton @ 0x45d9c4
// ---------------------------------------------------------------------------
struct cHashedStringLookup {
    void*    pVtable;               // 0x00 → 0x45BD80
    Mutex    criticalSection;       // 0x04 (56B)
    void*    lookupVec_begin;       // 0x3C std::vector<sLookup>
    void*    lookupVec_end;         // 0x40
    void*    lookupVec_cap;         // 0x44
    char*    pStringPool;           // 0x48 (3MB alloc @ ctor)
    char*    pStringPoolEnd;        // 0x4C
    int32_t  nStringPoolSize;       // 0x50 (3145728 = 0x300000)
};                                   // total 0x54 = 84

// ============================================================================
// Tier 3 — 游戏功能类型(2026-08-08, 5 分片并发恢复)
// 详见 tier3-gamestuff.md + 各分片报告
// 关键前提:std::string = 4B 旧 ABI;std::_Rb_tree 头 = 24B
// ============================================================================

// --- 事件类 (Slice C) ---
struct cGameEvent { void* vptr; int32_t nType; };                 // 8B 公共基类
struct cInputKeyEvent { void* vptr; int32_t nType; int32_t nKey; bool bPressed; uint8_t _pad[3]; }; // 0x10
struct cInputMouseButtonEvent { void* vptr; int32_t nType; int32_t nButton; bool bPressed; float flX; float flY; }; // 0x18
struct cInputMouseMoveEvent { void* vptr; int32_t nType; int32_t nX; int32_t nY; }; // 0x10
struct cInputGestureEvent { void* vptr; int32_t nType; int32_t eGesture; }; // 0x0C
struct cInputTextEvent { void* vptr; int32_t nType; uint8_t sText[4]; }; // 0x0C (CoW string)
struct cTogglePauseEvent { void* vptr; int32_t nType; bool bPaused; uint8_t _pad[3]; }; // 0x0C
struct cFocusGainedEvent { void* vptr; int32_t nType; };          // 0x08
struct cFocusLostEvent { void* vptr; int32_t nType; };           // 0x08
struct WindowMoveEvent { void* vptr; int32_t nType; int32_t nX; int32_t nY; }; // 0x10
struct ResizeEvent { void* vptr; int32_t nType; int32_t nW; int32_t nH; }; // 0x10

// --- Input (Slice C) ---
struct Control { uint32_t nId; uint32_t nType; uint32_t nInput; uint32_t nInput2; }; // 16B
struct cLineEditor { char sBuffer[1000]; int32_t nCursorPos; int32_t nLength; int32_t nHistoryCount; bool bInsertMode; void* vecHistory[3]; }; // 0x404
struct DontStarveInputHandler { void* vptr; void* pStateObj; void* pInputManager; /* TODO: IInputManager* */ void* pGameEventDispatcher; /* TODO: cEventDispatcher* */ void* pLuaCallTarget; void* pLuaState; uint8_t mInitVec[16]; int32_t nRefOnInputKey; int32_t nRefOnMouseButton; int32_t nRefOnMouseMove; int32_t nField_0x30; uint8_t vecControls[12]; int32_t nField_0x40; uint8_t oControlMapper[516]; uint8_t oMappingStorage[124]; float flMouseX; float flMouseY; uint8_t bMouseDown[5]; uint8_t bMousePressed[5]; uint8_t bKeys[128]; }; // ~0x2C4

// --- Map (Slice B) ---
struct MapComponentBase { cEntityComponent base; uint8_t UNKNOWN_0x10[232]; uint8_t vecRenderLayers[12]; uint8_t vecTiles[12]; uint8_t bUndergroundLayer; MapRenderer* pMapRenderer; int32_t mapTileCount[5]; }; // 0x130
struct MapComponent { MapComponentBase base; int32_t nNumWalkableTiles; int32_t nNumUndergroundTiles; uint8_t mMat4_0[16]; uint8_t mMat4_1[16]; float flColorScale[4]; uint8_t bInitialized; void* pNavGrid; /* TODO: TileGrid* */ MapRenderer* pMapRenderer; WaveComponent* pWaveComponent; RoadManagerComponent* pRoadManager; GroundCreep* pGroundCreep; cNetworkTileRegion** ppNetworkTileRegions; int32_t nField_0x184; float flOverlayScale; uint8_t bFinalized; uint8_t _pad[3]; }; // 0x190
struct MapGenSim { cEntityComponent base; void* pWorld; /* TODO: btDiscreteDynamicsWorld* */ int32_t nField_0x14; int32_t nCollObjCount; int32_t nCollObjCap; void* pCollObjs; uint8_t bAlignedAlloc; void* pBroadphase; /* TODO: btDbvtBroadphase* */ void* pDispatcher; /* TODO: btCollisionDispatcher* */ void* pSolver; /* TODO: btSequentialImpulseConstraintSolver* */ void* pConfig; /* TODO: btDefaultCollisionConfiguration* */ uint8_t vecNodes[12]; void* pShapeBox; /* TODO: btConvex2dShape* */ void* pShapeTri; /* TODO: btConvex2dShape* */ void* pShapeCylinder; /* TODO: btConvex2dShape* */ uint8_t vecConstraints[12]; }; // 0x5C
struct Maze { float bounds[4]; void* points[3]; int32_t eMazeType; int32_t nField_0x20; int32_t groundType; int32_t floorType; }; // 0x2C
struct QuadTreeNode_Node { float bounds[4]; QuadTreeNode_Node* pChild[4]; int32_t nField_0x20; int32_t set[5]; }; // 0x38
struct QuadTreeNode { uint8_t base[148]; QuadTreeNode_Node* pRootNode; int32_t set[5]; }; // 0xB0
struct AStarSearch_PathNode { void* pVtable; int32_t nStatus; uint8_t openSet[12]; uint8_t closedSet[12]; void* pParams; /* TODO: PathfinderParams* */ uint8_t path[12]; float flSearchTime; }; // 0x34
struct AStarSearch_ulong { void* pVtable; int32_t nStatus; uint8_t openSet[12]; uint8_t closedSet[12]; void* pParams; /* TODO: AstarParams* */ int32_t nField[3]; float flSearchTime; }; // 0x34
struct PathfinderComponent { cEntityComponent base; int32_t nField_0x10; int32_t nField_0x14; int32_t nField_0x18; int32_t map1[5]; int32_t map2[5]; int32_t searches[5]; int32_t nNextSearchId; }; // 0x68

// --- Network (Slice D) ---
struct cShardBroadcast { uint8_t str_0x00[4]; };                  // 4B
struct cShardManager { void* pVtable; int32_t nEShardType; int32_t nField_08; int32_t nField_0C; uint8_t bField_10; uint8_t pPad_11[3]; cStdString strClusterName; uint32_t dwShardId; int32_t nField_1C; int32_t nField_20; cStdString strWorldSession; uint8_t m_shardPlayers[24]; int32_t nDefaultFlag; uint8_t m_incomingMigrations[24]; uint8_t bIncomingMigrationActive; uint8_t m_restartMigrations[24]; float flReconnectInterval; Timer Timer_1; int32_t nField_0x84; Timer Timer_2; void* pM_strList_next; void* pM_strList_prev; uint8_t bFlag_0x98; uint8_t bFlag_0x99; void* pCheshireCat; /* TODO: tCheshireCat_Shard* */ void* pField_0xA0; cShardBroadcast* pShardBroadcast; }; // 0xA8
struct cAccountManager { void* pVtable; uint8_t bInitialized; uint8_t str_0x08[4]; uint8_t tAuthenticated[16]; uint8_t m_authToken[4]; uint8_t m_username[4]; uint8_t str_0x24[4]; uint8_t str_0x28[4]; uint8_t str_0x2C[4]; int32_t nField_0x30; uint8_t str_0x34[4]; cAccountCommunication* pCommunication; int32_t nField_0x3C; uint8_t bOnlineCapable; uint8_t pad_0x41[3]; uint8_t str_0x44[4]; uint8_t str_0x48[4]; uint8_t m_offlineUserId[4]; }; // 0x50
struct cTwitchManager { void* pVtable; void* pCheshireCat; /* TODO: tCheshireCat_Twitch* */ int32_t bTVInitialized; Timer Timer; uint8_t bDeferredInit; uint8_t m_username[4]; uint8_t bEnabled; int32_t nState; uint8_t m_channelName[4]; }; // 0x28
struct LuaHttpQuery { void* pVtable; uint8_t m_requests[20]; uint32_t m_pendingCount; uint32_t m_requestCounter; }; // 0x20
struct CurlRequest { uint32_t m_id; uint8_t m_url[4]; uint8_t m_postData[4]; uint32_t m_authToken[2]; uint32_t nField_0x14; uint16_t wField_0x18; void* pCurlMulti; /* TODO: CURLM* */ void* pCurlEasy; /* TODO: CURL* */ void* pCurlSlist; /* TODO: curl_slist* */ uint16_t wField_0x28; uint8_t bField_0x2A; uint8_t m_response[4]; uint32_t nField_0x30; uint16_t wField_0x34; }; // ~0x36
struct CurlRequestManager { void* pVtable; void* pClientThread; }; // 8B
struct GetURL { void* pVtable; HttpClient2* pHttpClient2; };             // 8B
struct cCachedPingResults { int32_t nRbTreeHeader; uint8_t m_cachedPings[16]; int32_t nMapNodeCount; uint8_t m_hashCache[12]; uint8_t bDirty; int32_t m_cachedPingSize; }; // 0x2C
struct cGiftingManager { void* pVtable; int32_t nState; void* m_listA[2]; Mutex Mutex_1; uint8_t m_giftItems[24]; void* m_unverifiedReceipts[2]; Mutex Mutex_2; }; // 0xA0
struct DontStarveGameService { void* pVtable; DontStarveSystemService* pSystemService; int32_t nField_0x08; int32_t nField_0x0C; uint8_t m_achievements[20]; }; // 0x24
struct DontStarveSystemService { void* pVtable; int32_t nField_0x04; int32_t nField_0x08; void* pCacheMap; uint8_t m_playerId[36]; uint8_t flags_0x34[4]; int32_t nStorageStateA; int32_t nStorageStateB; uint8_t callbacks[84]; int32_t luaRefs[4]; }; // 0xA4
struct cNetworkLuaProxy { void* pVtable; int32_t nField_0x04; uint8_t map_like_0x08[20]; void* pNetworkContext; }; // 0x20
struct cAccountCommunication { void* pVtable; uint8_t m_netId[44]; uint8_t bConnected; uint8_t strs[16]; int32_t nField_0x44; Mutex Mutex; uint8_t m_accountEvents[40]; void* pAccountManager; int32_t nField_0xAC; int32_t nField_0xB0; int32_t nField_0xB4; Timer Timer; uint8_t bBusy; uint8_t _pad[3]; }; // 0xC4
struct DatagramHeaderFormat { uint8_t n24_0x00[3]; uint32_t n32_0x04; uint8_t bFullHeader; uint8_t b_0x09; uint8_t b_0x0A; uint8_t b_0x0B; uint8_t b_0x0C; uint8_t b_0x0D; uint8_t b_0x0E; }; // 0x0F
struct Socket { int32_t m_fd; int32_t m_lastError; int32_t nField_0x08; int32_t nField_0x0C; uint8_t UNKNOWN_0x10[8]; uint8_t bBlocking; }; // 0x1C
struct NodeAddress { void* m_path[3]; };                          // 0x0C

// --- System (Slice E) ---
struct Timer { uint32_t nStartTick; uint32_t nStartTickHi; };     // 8B
struct Semaphore { void* pSem; /* TODO: SDL_sem* */ };                 // 4B
struct ProcessId { int32_t nPID; };                               // 4B
struct Process { void* pVtable; uint8_t m_strExe[4]; uint8_t m_strWorkingDir[4]; void* m_args[2]; uint8_t bRunning; uint8_t m_strPID[4]; int32_t nPID; }; // 0x20
struct Thread { void* pVtable; uint8_t bRunning; uint32_t nPriority; uint32_t nStackSize; Mutex mMutex; void* hThread; /* TODO: pthread_t */ uint8_t mAttr[40]; uint8_t m_strName[4]; uint8_t UNKNOWN_0x78[128]; }; // 0xF8
struct Heap { uint32_t m_nHeapID; uint32_t m_nTotalSize; void* pBase; void* pFirstBlock; /* TODO: MemoryBlock* */ void* pLastBlock; /* TODO: MemoryBlock* */ uint32_t nAllocatedCount; uint32_t nFreeBlockCount; Mutex mMutex; uint8_t bNeedsCoalesce; uint32_t nTotalFree; }; // 0x5C
struct PersistentStorage { void* pVtable; uint8_t bFlag; uint8_t _pad[3]; }; // 8B
struct Metrics { void* pVtable; uint8_t bEnabled; uint8_t m_strBranchA[4]; uint8_t m_strBranchB[4]; uint8_t m_strBranchC[4]; uint8_t m_Generator[32]; }; // 0x34
struct FrameProfiler { void* pVtable; uint32_t nThreadID; Timer m_Timer; uint8_t bRecording; uint32_t nProfileCount; int32_t nFileIndex; float flSpinTime; uint32_t nSpinCount; }; // 0x24
struct PerfIndicator { cGame* pGame; uint8_t m_strName[4]; float flHistory[256]; int32_t nWriteIndex; uint8_t m_colour[4]; uint32_t nUpdateCount; uint32_t nSampleDivisor; }; // 0x418
struct PerfPane { void* vecIndicators[3]; void* vecGrids[3]; cGame* pGame; float flPosX; float flPosY; float flSizeX; float flSizeY; uint8_t UNKNOWN_0x2C[20]; }; // 0x40
struct cStringBuilder { void* pVtable; char* pBuffer; char* pWritePtr; uint32_t nCapacity; uint8_t m_str[16]; }; // 0x20
struct cReader { void* pVtable; int32_t nReadHead; uint32_t nBufferLength; void* pBuffer; uint8_t bOwnsBuffer; uint8_t _pad[3]; }; // 0x14
struct cWriter { void* pVtable; void* m_buffer[3]; };              // 0x10
struct ZipSaver { void* zipFile; };                               // 4B
struct cBaseFactory { void* pVtable; Mutex criticalSection; };     // 0x3C
struct IPCSignals { void* pVtable; int32_t m_handlers[6]; uint8_t bEnabled; int32_t m_signals[6]; }; // 0x38
struct GoogleAnalyticsCookie { void* pVtable; uint8_t m_strValue[4]; uint8_t m_strName[4]; void* m_args[3]; }; // 0x18
struct GoogleAnalyticsGenerator { uint32_t nField_0; uint8_t m_strReportName[4]; int32_t m_settings[6]; }; // 0x20
struct MemoryCache { int32_t m_cache[6]; };                        // 0x18
struct CacheItem { int32_t nCrc32; uint32_t nSize; uint8_t bSynchronized; char szName[259]; void* pData; }; // 0x110
struct CSHA1 { uint32_t m_state[5]; uint32_t m_count[2]; int32_t nField_0x1C; uint8_t m_buffer[64]; uint8_t m_digest[20]; uint8_t m_workspace[64]; void* pWorkspace; }; // 0xC4

// --- Rendering (Slice A) ---
struct BaseTexture { void* pVtable; void* pMipData; /* TODO: sMipDescription* */ uint32_t dwFlags; int32_t nField_0x0C; uint8_t name[4]; }; // 0x14
struct Attribute { uint32_t nType; uint32_t nElementType; uint16_t nCount; uint16_t nOffset; }; // 0x0C
struct BaseVertexDescription { void* pVtable; uint16_t nStride; uint16_t nPad; uint32_t dwAttributeMask; uint8_t attributes[12]; }; // 0x18
struct VertexDescription { void* pVtable; uint16_t nStride; uint16_t nPad; uint32_t dwAttributeMask; uint8_t attributes[12]; }; // 0x18
struct Region { uint32_t dwHash; uint8_t UNKNOWN_0x04[20]; };     // 0x18
struct Atlas { uint8_t name[4]; int32_t nTextureHandle; uint8_t regions[12]; uint8_t filename[4]; uint8_t bLoaded; uint8_t _pad[3]; }; // 0x1C
struct AtlasManager { void* pVtable; int32_t nField_0x04; uint8_t resources[12]; uint8_t hashMap[20]; uint8_t vec_2C[12]; uint8_t name[4]; Renderer* pRenderer; }; // 0x40
struct Shader { void* pVtable; int32_t nHandle; uint8_t name[4]; int32_t nField_0x0C; int32_t nField_0x10; int32_t nField_0x14; }; // 0x18
struct HWEffect { void* pVtable; Shader vsShader; Shader psShader; void* pShaderData; uint8_t shaderName[4]; uint32_t nShaderDataSize; uint32_t glProgram; uint8_t paramMap1[28]; uint8_t paramMap2[28]; uint8_t paramData[12]; uint8_t paramInfo[12]; uint8_t UNKNOWN_str[4]; int32_t bInitState; }; // 0xA0
struct Effect { HWEffect base; uint8_t name[4]; };                // 0xA4
struct EffectManager { uint8_t base[148]; };                       // 0x94
struct RenderTarget { void* pVtable; };                            // 4B 抽象
struct HWRenderTarget { void* pVtable; uint32_t dwFramebufferId; uint32_t dwColorTexHandle; uint32_t dwDepthTexHandle; uint32_t dwField_0x10; uint32_t dwTextureHandle; uint32_t dwWidth; uint32_t dwHeight; }; // 0x20
struct RenderTargetManager { uint8_t base[148]; };                 // 0x94
struct BitmapFont { uint8_t name[4]; uint16_t nLineHeight; uint16_t nBase; float flSize; float flScaleW; float flScaleH; uint32_t dwOutline; uint32_t nPages; uint8_t glyphMap[12]; uint8_t kerningMap[12]; uint32_t dwTextureHandle; uint8_t fallbackFonts[12]; }; // 0x44
struct WorkingVB { void* pVertexData[4]; void* pCurVertex[4]; int32_t nVertCount[4]; int32_t nVertCap[4]; }; // 0x40
struct BitmapFontManager { void* pVtable; int32_t nField_0x04; uint8_t resources[12]; uint8_t hashMap[20]; uint8_t vec_2C[12]; uint8_t name[4]; uint8_t registeredFonts[20]; GameRenderer* pRenderer; }; // 0x58
struct BitmapFontRenderer { void* pVtable; int32_t nField_0x04; WorkingVB workingVB; GameRenderer* pRenderer; BitmapFontManager* pFontManager; uint32_t dwVertDescHandle; uint32_t dwEffectHandle_font; uint32_t dwEffectHandle_packed; uint32_t dwEffectHandle_outline; }; // 0x60
struct VFXEffect { void* pVtable; uint8_t UNKNOWN_0x04[24]; };     // 0x1C
struct VFXEffectEmitter { void* pVtable; uint8_t UNKNOWN_0x04[124]; }; // 0x80
// 前置声明(blob-b 拆分回写引入的向后引用;定义见本文件下方)
struct ParticleBuffer;
struct ParticleBufferRenderer;
struct GameRenderer;
struct ParticleEmitter { void* pVtable; uint8_t bAwakeFlag; uint8_t pPad_05[3]; void* pVec_component; void* pEntity; float flMaxAge; uint32_t dwField_14; uint32_t dwField_18; uint32_t dwField_1C; uint32_t dwField_20; float pAcceleration[3]; uint8_t bRotation; uint8_t pPad_31[2]; bool fParticleBufferFlag; uint8_t bField_34; uint8_t bHasRotationComponents; uint8_t pUNKNOWN_36[26]; float pUVFrameSize[2]; uint32_t dwBlendMode; uint32_t dwField_5C; uint32_t dwField_60; uint32_t dwTextureHandle; float flUVHeight; float flUVWidth; uint32_t dwEffectHandle; uint32_t dwField_74; uint32_t dwRenderLayer; void* pNode; ParticleBuffer* pParticleBuffer; uint32_t dwMaxParticles; }; // 0x88
struct PostProcessor { void* pVtable; uint8_t pPostState[132]; }; // 0x88
struct VideoNode { uint8_t base[80]; void* pSizeXY; uint8_t flSize[8]; uint8_t pSgnTailAndGame[60]; uint32_t decoderHandles[3]; uint32_t dwWidth; uint32_t dwHeight; uint32_t nField_0xA8; uint32_t nField_0xAC; uint32_t dwTint; uint32_t dwPlayState; uint8_t pStrPath[4]; uint8_t timer[32]; uint8_t pIoAndPlayback[8]; uint32_t dwTexY; uint32_t dwTexU; uint32_t dwTexV; uint8_t bLoopOrFlag; uint32_t nField_0x100; uint32_t nField_0x104; uint32_t dwFrameBuf0; uint32_t dwFrameBuf1; uint32_t dwFrameBufIndex; }; // 0x114

// ============================================================================
// 未创建核心类型补齐 (2026-08-08) — 详见 unbuilt-types.md
// ============================================================================
struct cSimTime { void* pVtable; uint32_t nTick; float fRemainder; }; // 12B
struct cBPWorld { void* pVtable; void* pBroadphase; /* TODO: btBroadphaseInterface* */ void* pConfig; /* TODO: btDefaultCollisionConfiguration* */ void* pDispatcher; /* TODO: btCollisionDispatcher* */ void* pSolver; /* TODO: btSequentialImpulseConstraintSolver* */ void* pWorld; /* TODO: btDiscreteDynamicsWorld* */ void* pGroundShape; /* TODO: btCollisionShape* */ void* pGroundBody; /* TODO: btRigidBody* */ uint8_t UNKNOWN_0x20[12]; cSimulation* pSimulation; }; // 52B
struct EnvelopeManager { void* pVtable; void* pVecEnvelopes[3]; uint8_t indexManager[8]; }; // 24B
struct cApplication { DontStarveSystemService* mSystemService; DontStarveGameService* mGameService; cGame* mGame; uint8_t mCommandLine[4]; }; // 16B
struct cLoggerImplementation { void* pVtable; int32_t nField_0x04; uint8_t m_strLogFile[4]; Mutex criticalSection; int32_t nField_0x48; int32_t nField_0x4C; uint8_t UNKNOWN_0x50[4088]; int32_t nField_0x104C; int32_t nStartTime; }; // 4180B
struct cLogger { void* pVtable; cLoggerImplementation impl; }; // 4184B
struct cInventoryManager { void* pVtable; int32_t nField_0x04; void* list_0x08[2]; int32_t map1[5]; int32_t map2[5]; uint8_t m_strRestricted[4]; uint8_t m_str_0x44[4]; uint8_t UNKNOWN_0x48[1024]; }; // ~0x448
struct cSoundSystem { void* pVtable; int32_t map1[6]; int32_t map2[6]; uint8_t bField_0x34; uint8_t _pad[3]; }; // 56B
struct cNetID2 { int32_t nField[11]; }; // 44B
struct cMasterServer { void* list[2]; Timer timer_0x08; uint8_t deque_0x10[40]; Timer timer_0x38; cMasterServerRequest* pRequest; cMasterServerBroadcast* pBroadcast; Mutex Mutex_0x48; int32_t nField_0x80; int32_t nField_0x84; int32_t nField_0x88; int32_t nProtocolFlags; uint8_t bEnabled; }; // 145B
struct WaveComponent { cEntityComponent base; int32_t nField_0x10; int32_t nField_0x14; int32_t nField_0x18; int32_t nField_0x1C; int32_t nField_0x20; int32_t nField_0x24; int32_t nField_0x28; int32_t nField_0x2C; int32_t nField_0x30; int32_t nField_0x34; int32_t nField_0x38; int32_t nField_0x3C; int32_t nField_0x40; int32_t nField_0x44; int32_t nField_0x48; int32_t nField_0x4C; int32_t nField_0x50; int32_t nField_0x54; int32_t nField_0x58; int32_t nField_0x5C; int32_t nTime; float flWidth; float flHeight; int32_t nNumWaves; int32_t nField_0x70; int32_t nField_0x74; int32_t nWaveTextureHandle; int32_t nWaveEffectHandle; int32_t nVertexBufferHandle; int32_t nVertexDescHandle; uint8_t bEnabled; uint8_t pPad_0x89[3]; int32_t nGameRenderer; }; // 144B
struct FollowerComponent { cEntityComponent base; int32_t nSymbolHash; uint8_t pSymbolCstr[4]; uint8_t pOffset[12]; uint8_t pOffsetNet[12]; int32_t nLeaderGuid; int32_t nField_0x34; uint8_t bField_0x38; int32_t nTransform; uint16_t wDirtyFlags; }; // 66B
struct cLabelComponent { cEntityComponent base; int32_t nField_0x10; }; // 20B
struct cLightEmitterComponent { cEntityComponent base; uint8_t pLightParams[16]; int32_t nColour; int32_t nFlagsEnabled; uint8_t bDirtyFlags; }; // 41B
struct cLightWatcherComponent { cEntityComponent base; uint8_t bIsInLight; int32_t nLightAlpha; int32_t nLightValue; cSimTime simTime; int32_t nField_0x28; float flLightThresh; float flDarkThresh; uint16_t wFlags; }; // 62B
struct MiniMapComponent { cEntityComponent base; void* pVtable2; int32_t map[5]; int32_t nField_0x2C; int32_t nField_0x30; int32_t nField_0x34; int32_t nField_0x38; int32_t nField_0x3C; int32_t nField_0x40; int32_t nField_0x44; int32_t nField_0x48; uint8_t bField_0x4C; uint8_t bField_0x4D; int32_t nField_0x50; int32_t nField_0x54; int32_t nField_0x58; int32_t nField_0x5C; }; // 96B
struct MiniMapEntityComponent { cEntityComponent base; int32_t nPriority; int32_t nIconHash; uint8_t pStrName[4]; int32_t nFlags; uint8_t bField_0x20; }; // 33B
struct DebugRenderComponent { cEntityComponent base; uint8_t sceneGraphNode[148]; int32_t nY; uint8_t bField_0xA8; int32_t nVecStrings_begin; int32_t nVecStrings_end; int32_t nVecStrings_cap; int32_t nVecLines_begin; int32_t nVecLines_end; int32_t nVecLines_cap; int32_t nVecCircles_begin; int32_t nVecCircles_end; int32_t nVecCircles_cap; int32_t nVecBoxes_begin; int32_t nVecBoxes_end; int32_t nVecBoxes_cap; int32_t nVecTriangles_begin; int32_t nVecTriangles_end; int32_t nVecTriangles_cap; }; // 232B
struct DynamicShadowComponent { cEntityComponent base; float flSizeX; float flSizeY; bool fEnabled; uint8_t bPristine; uint8_t bFlags; uint8_t bPad_0x1B; int32_t nField_0x1C; int32_t nField_0x20; }; // 36B
struct StaticShadowComponent { cEntityComponent base; int32_t nField_0x10; int32_t nField_0x14; int32_t nField_0x18; int32_t nField_0x1C; int32_t nField_0x20; }; // 36B
struct ShadowManagerComponent { cEntityComponent base; int32_t nField_0x10; int32_t nField_0x14; int32_t nField_0x18; int32_t nField_0x1C; }; // 32B
struct GraphicsOptionsComponent { cEntityComponent base; }; // 16B
struct PostProcessorComponent { cEntityComponent base; }; // 16B
struct RoadManagerComponent { cEntityComponent base; uint8_t sceneGraphNode[148]; uint8_t roadBuilder[44]; int32_t nGameRenderer; int32_t nVertexDescHandle; int32_t nQuadTreeRoot; int32_t nSpCountedBase; int32_t nField_0xE0; int32_t nField_0xE4; int32_t nField_0xE8; int32_t nField_0xEC; int32_t nField_0xF0; int32_t nField_0xF4; }; // 248B
struct TwitchComponent { cEntityComponent base; void* pVtable2; int32_t map[5]; int32_t nField_0x2C; }; // 48B
struct cUITransformComponent { cEntityComponent base; void* pVtable2; void* pVtable3; void* pVtable4; int32_t map1[5]; int32_t map2[5]; int32_t nHAnchor; int32_t nVAnchor; int32_t nField_0x54; int32_t nField_0x58; int32_t nField_0x5C; int32_t nField_0x60; int32_t nField_0x64; int32_t nField_0x68; int32_t nField_0x6C; float flScaleX; float flScaleY; float flScaleZ; int32_t nField_0x7C; uint8_t UNKNOWN_0x80[256]; float flMaxScale; }; // 388B
struct cShardClientComponent { cEntityComponent base; void* pList; void* list_0x14[2]; uint16_t wField_0x1C; }; // 30B
struct cShardNetworkComponent { cEntityComponent base; int32_t nLastSerializedState; uint8_t bSerializeRetry; }; // 21B
struct cSerializableEntityComponent { cEntityComponent base; }; // 16B

// ============================================================================
// Phase 0 sync merge (2026-08-10) — Ghidra get_struct_layout 布局同步
// 来源: sync-s1-net.md / sync-s2-entity.md / sync-s3-render.md / sync-s4-ui.md / sync-s5-misc.md
// 规则: 一行式紧凑布局;缺失引用类型以 uint8_t[]/void* 占位(2026-08-10 已全部补齐,见 todo-fix-report.md)
// ============================================================================

// ===== 网络/RakNet =====
struct Replica3;
struct LastSerializationResultBS;
struct tServerListing;
struct BitStream { uint32_t dwNumberOfBitsUsed; uint32_t dwNumberOfBitsAllocated; uint32_t dwReadOffset; uint8_t* pData; bool fCopyData; uint8_t pStackData[256]; uint8_t p_pad[3]; }; // total 0x114 = 276
struct RakNetGUID { uint64_t qwG; uint16_t wSystemIndex; uint8_t p_pad[2]; }; // total 0xc = 12
struct SystemAddress { uint8_t pAddr4[16]; uint16_t wDebugPort; uint16_t wSystemIndex; }; // total 0x14 = 20
struct PRO { int32_t nPriority; int32_t nReliability; char cOrderingChannel; uint8_t p_pad[3]; uint32_t dwSendReceipt; }; // total 0x10 = 16
struct PluginInterface2 { void* pVtable; void* pRakPeerInterface; /* TODO: RakPeerInterface* */ void* pTcpInterface; /* TODO: TCPInterface* */ }; // total 0xc = 12
struct NetworkIDObject { void* pVtable; uint64_t qwNetworkID; void* pNetworkIDManager; /* TODO: NetworkIDManager* */ NetworkIDObject* pParent; NetworkIDObject* pNextInstanceForNetworkIDManager; }; // total 0x18 = 24
struct RakNetList { void* pListArray; uint32_t dwList_size; uint32_t dwAllocation_size; }; // total 0xc = 12
struct LastSerializationResult { Replica3* pReplica; uint64_t qwWhenLastSerialized; LastSerializationResultBS* pLastSerializationResultBS; }; // total 0x10 = 16
struct LastSerializationResultBS { BitStream bitStream; bool fIndicesToSend; uint8_t p_pad[3]; }; // total 0x118 = 280
struct SerializeParameters { BitStream outputBitstream; BitStream* pLastSentBitstream; uint64_t qwMessageTimestamp; PRO pro; Connection_RM3* pDestinationConnection; uint32_t dwBitsWrittenSoFar; uint64_t qwWhenLastSerialized; uint64_t qwCurTime; }; // total 0x148 = 328
struct DeserializeParameters { BitStream serializationBitstream; bool fBitstreamWrittenTo; uint8_t p_pad[3]; uint64_t qwTimeStamp; Connection_RM3* pSourceConnection; }; // total 0x124 = 292
struct RM3World { RakNetList connectionList; RakNetList userReplicaList; uint8_t bWorldId; uint8_t p_pad[3]; void* pNetworkIDManager; /* TODO: NetworkIDManager* */ }; // total 0x20 = 32
struct cPendingConnection { int32_t nEState; uint8_t bIsDedicated; uint8_t pM_ip[4]; uint16_t wPort; uint8_t pRakNetGUID[12]; uint8_t pM_token[4]; cNetID2 m_netId; uint8_t bHasToken; Timer Timer; tServerListing* pServerListing; uint8_t pM_pingIP[4]; uint16_t wPingPort; }; // total 0x6a = 106
struct cNetworkManager { void* pVtable; void* pIface1_vtable; int32_t nIface1_field1; int32_t nIface1_field2; uint8_t bIface1_flag; uint8_t bPad_11; uint8_t bPad_12; uint8_t bPad_13; void* pIface2_vtable; int32_t nIface2_field1; int32_t nIface2_field2; uint8_t bIface2_flag; uint8_t bPad_21; uint8_t bPad_22; uint8_t bPad_23; void* pIface3_vtable; int32_t nIface3_field1; int32_t nIface3_field2; uint8_t bIface3_flag; uint8_t bPad_31; uint8_t bPad_32; uint8_t bPad_33; void* pStrServerName; int32_t nNetworkState; uint8_t bField_0x3C; uint8_t bPad_3D; uint8_t bPad_3E; uint8_t bPad_3F; uint8_t pDequeRakNetGUID[40]; int32_t nTickRate; int32_t nMaxPlayers; int32_t nWhitelistSlots; int32_t nConnectionTimeoutMs; void* pStrServerDescription; void* pStrClanInfo; void* pStrServerIntention; void* pStrServerPassword; uint16_t wServerPort; uint16_t wAuthPort; uint16_t wMasterPort; uint8_t bPad_0x8E; bool fAutosaverEnabled; void* pStrGameMode; void* pStrServerTags; int32_t nServerGameplayFlags; uint8_t pNetID[36]; int32_t nSteamGroupIdLo; int32_t nSteamGroupIdHi; uint8_t bField_0xC8; uint8_t bIsLANOnly; uint8_t bPad_CA; uint8_t bPad_CB; cNetworkRPCManager* pNetworkRPCManager; cNetworkVoiceManager* pNetworkVoiceManager; cNetworkReplicaManager* pNetworkReplicaManager; cSteamFriendsManager* pSteamFriendsManager; void* pNetworkIDManager; /* TODO: NetworkIDManager* */ void* pRakPeer; /* TODO: RakPeerInterface* */ void* pDirectoryDeltaTransfer; /* TODO: DirectoryDeltaTransfer* */ void* pFileListTransfer; /* TODO: FileListTransfer* */ void* pIncrementalReadInterface; /* TODO: IncrementalReadInterface* */ PluginInterface2* pAdditionalPlugin; int32_t nField_0xF4; cMasterServer* pMasterServer; cNatTraversal* pNatTraversal; int32_t nMRakString; cClientColourPicker* pClientColourPicker; uint8_t bEnableFrameDeserialize; uint8_t bIsServer; uint8_t bServerStarted; uint8_t bIsOnline; uint8_t bPeerCreated; uint8_t bPad_10D; uint8_t bPad_10E; uint8_t bPad_10F; cSimulation* pSimulation; void* pReadyEvent; /* TODO: ReadyEvent* */ uint16_t wUnassignedSystemIndex; uint8_t bPad_11A; uint8_t bPad_11B; void* pCheshireCat; /* TODO: tCheshireCat_Network* */ uint8_t pPendingConnection[116]; uint8_t pTimer1[8]; uint8_t bField_0x19C; uint8_t bField_0x19D; uint8_t bPad_19E; uint8_t bPad_19F; cStdString str_0x1A0; uint8_t pTimer2[8]; void* pSnapshotManager; /* TODO: SnapshotManager* */ cStdString str_0x1B0; cStdString str_0x1B4; cSteamPunchthrough* pSteamPunchthrough; void* pVecPermissions1_begin; void* pVecPermissions1_end; void* pVecPermissions1_cap; void* pVecPermissions2_begin; void* pVecPermissions2_end; void* pVecPermissions2_cap; void* pVecStrings_begin; void* pVecStrings_end; void* pVecStrings_cap; void* pListTimedBan_next; void* pListTimedBan_prev; int32_t nListTimedBan_count; uint8_t bField_0x1EC; uint8_t bPad_1ED; uint8_t bPad_1EE; uint8_t bPad_1EF; void* pListServerModInfo_next; void* pListServerModInfo_prev; cStdString str_0x1F8; void* pServerListingData; /* TODO: ServerListingData* */ void* pStrDisconnectReason; void* pStrPopupReason; void* pStrPopupDialog; uint8_t pTimer3[8]; uint8_t pConsoleInput[220]; uint8_t pTimer4[8]; int32_t nField_0x2F8; void* pVtableObject_0x2FC; uint8_t pLoggerImpl[4180]; void* pListStrings_next; void* pListStrings_prev; uint8_t bField_0x135C; uint8_t bField_0x135D; uint8_t bPad_135E; uint8_t bPad_135F; int32_t nField_0x1360; cSteamRichPresence* pSteamRichPresence; uint8_t pMigrationInfo[72]; cDedicatedServerProcess* pDedicatedServerProcess1; cDedicatedServerProcess* pDedicatedServerProcess2; }; // total 0x13b8 = 5048
struct MigrationInfo { int32_t nState; uint8_t pM_strTarget[4]; uint16_t wPort; uint8_t pM_strSteamId[4]; uint8_t pM_netId[8]; int32_t nField_0x18; cNetID2 m_targetNetId; }; // total 0x48 = 72
struct cSteamPunchthroughPlugin { void* pVtable; uint8_t pPluginInterface2[12]; uint8_t pCcallback1[24]; uint8_t pCcallback2[24]; uint8_t pM_addressToSteamID[24]; uint8_t pM_steamIDToAddress[24]; uint8_t pM_idleTimers[24]; int32_t nMinAddress; int32_t nMaxAddress; int32_t nNextAddress; uint8_t pM_timers2[24]; uint8_t pM_timers3[24]; }; // total 0xc4 = 196
struct cNatPunchthroughDebugInterfaceImpl { void* pVtable; }; // total 0x4 = 4
struct cSteamAccountCommunication { cAccountCommunication base; uint8_t pCcallback1[24]; uint8_t pCcallback2[24]; uint8_t pCcallback3[24]; void* pAuthTicketBuffer; uint32_t dwAuthTicket; int32_t nTicketBufferSize; int32_t nField_0x118; }; // total 0x11c = 284
struct cLuaNetworkVariable { void* pVtable; uint8_t bDirty; uint8_t pM_strName[4]; cEntity* pEntity; }; // total 0x10 = 16
struct cNetworkVoiceManager { void* pVtable; BitStream* pBitStream; uint8_t bEnabled; uint8_t pM_mutedPlayers[8]; }; // total 0x14 = 20
struct cSteamFriendsManager { void* pVtable; uint8_t pM_friends[8]; uint8_t pM_clans[8]; uint8_t pM_clanMembers[8]; uint8_t bField_0x1C; }; // total 0x1d = 29
struct Connection_RM3 { void* pVtable; bool fIsValidated; bool fIsFirstConstruction; uint8_t p_pad0[2]; SystemAddress systemAddress; RakNetGUID guid; RakNetList constructedReplicaList; RakNetList queryToConstructReplicaList; RakNetList queryToSerializeReplicaList; RakNetList queryToDestructReplicaList; RakNetList constructedReplicasCulled; RakNetList destroyedReplicasCulled; bool fGotDownloadComplete; uint8_t p_pad1[3]; BitStream bitStream1; BitStream bitStream2; int32_t nUNKNOWN_0x29C; }; // total 0x2a0 = 672
struct cNetworkFileTransferCB { void* pVtable; }; // total 0x4 = 4
struct cNatTraversal { uint8_t pNatPunchthroughClient[400]; uint8_t pDebugInterface[4]; int32_t nField_0x194; }; // total 0x198 = 408
struct Replica3 { NetworkIDObject base; RakNetGUID creatingSystemGUID; RakNetGUID deletingSystemGUID; ReplicaManager3* pReplicaManager; LastSerializationResultBS lastSentSerialization; bool fForceSendUntilNextUpdate; uint8_t p_pad[3]; LastSerializationResult* pLsr; uint32_t dwReferenceIndex; }; // total 0x158 = 344
struct tServerListing { cStdString strName; cStdString strIp; cStdString strRow; cStdString strSession; cStdString strHost; cStdString strDescription; cStdString strTags; cStdString strMode; cStdString strGameData; cStdString strWorldGenData; cStdString strPlayersData; cStdString strSeason; cStdString strIntention; uint8_t pListModsInfo[8]; uint16_t wPort; uint16_t wMaxConnections; uint16_t wConnected; int32_t nPing; int32_t nVersion; int32_t nSteamRoomLo; int32_t nSteamRoomHi; cNetID2 netId; cNetID2 netId2; int32_t nTick; uint8_t bDedicated; uint8_t bClientHosted; int32_t nFlagsBoolPack; cNetID2 netId3; uint8_t pGuid[8]; int32_t nField_0xEC; int32_t nNat; int32_t nFlagsPost; uint8_t pStrModsConfigData[4]; int32_t nFlagsClient; uint8_t bOffline; uint8_t pStr_0x104[4]; uint16_t wField_0x108; }; // total 0x10a = 266
struct cMasterServerBroadcast { uint8_t bField_0x00; uint8_t pM_strServerName[4]; int32_t nField_0x08; uint8_t pM_strPassword[4]; cMasterServer* pMasterServer; Timer m_timer; Mutex m_mutex; tServerListing* pListing; }; // total 0x58 = 88
struct cNetworkRPCManager { void* pRPC4; /* TODO: RPC4* */ BitStream* unnamed_0x04; char** pSlotNames; int32_t nField_0x0C; uint8_t bField_0x10; }; // total 0x11 = 17
struct cSteamPunchthrough { void* pVtable; int32_t nCallbackId; void* pRakPeer; /* TODO: RakPeerInterface* */ uint8_t pCcallResult[32]; void* pVecPendingClanGUID_begin; int32_t nVecPendingClanGUID_end; int32_t nVecPendingClanGUID_cap; cSteamPunchthroughPlugin* pPlugin; uint8_t bIsSteamGameServer; uint8_t bGameConnectionInitiated; int32_t nAuthTargetIP; uint16_t wAuthTargetPort; }; // total 0x46 = 70
struct cNetworkConnection { Connection_RM3 base; int32_t nField_0x2A0; }; // total 0x2a4 = 676
struct ReplicaManager3 { PluginInterface2 base; PRO defaultSendParameters; uint64_t qwUNKNOWN_0x1C; uint64_t qwUNKNOWN_0x24; uint64_t qwUNKNOWN_0x2C; uint32_t dwUNKNOWN_0x34; uint64_t qwAutoSerializeInterval; uint64_t qwLastAutoSerializeOccurance; bool fAutoCreateConnections; bool fAutoDestroyConnections; uint8_t p_pad[2]; Replica3* pCurrentlyDeallocatingReplica; uint32_t dwNextReferenceIndex; void* pWorldsArray[255]; RakNetList worldsList; }; // total 0x45c = 1116
struct cNetworkReplica { Replica3 base; int32_t nField_0x158; int32_t nField_0x15C; uint8_t bField_0x160; uint8_t bRegistered; }; // total 0x162 = 354
struct cNetworkReplicaManager { ReplicaManager3 base; int32_t nField_0x45C; int32_t nField_0x460; uint16_t wAutoSerializePerTicksState; uint8_t p_pad[2]; int32_t nFrameCounter; uint8_t pAwakeState[1536]; uint8_t pAsleepState[1536]; uint8_t pConstructedState[1536]; void* pVecReplicas_begin; void* pVecReplicas_end; void* pVecReplicas_cap; }; // total 0x1678 = 5752
struct cNetworkTileRegion { cNetworkReplica base; void* pNetworkManager; int32_t nRegionIndex; void* pTileGrid; /* TODO: TileGrid* */ MapComponent* pMapComponent; void* pTileData; void* pTileDataPtr; int32_t nField_0x180; }; // total 0x184 = 388
struct cPlayerListingData { cStdString strName; cNetID2 netId; void* pRakStr; uint32_t dwHash0; uint32_t dwHash1; uint32_t dwColour; uint8_t bUserFlags; uint8_t bNetScore; uint16_t wAge; uint8_t bAdmin; uint8_t pPad_0x45[3]; uint32_t dwField_48; cHashedString hashPrefab; cHashedString hashSkin1; cHashedString hashSkin2; cHashedString hashSkin3; uint32_t dwHashSkin4; void* pEquipBegin; void* pEquipEnd; void* pEquipCap; uint8_t bDirty_0x7C; uint8_t bDirty_0x7D; uint8_t pPad_0x7E[2]; }; // total 0x80 = 128
struct cNetworkClientObject2 { cNetworkReplica base; uint8_t pM_rakNetGUID[12]; uint32_t pConnectionMask[2]; cEntity* pPlayerEntity; cPlayerListingData listing; Timer Timer; uint8_t bField_0x204; void* pNetStats; void* pField_0x20C; uint8_t bField_0x210; uint8_t bField_0x211; uint8_t bFlags_0x212; int32_t nField_0x213; uint16_t wField_0x217; int32_t nField_0x21C; }; // total 0x220 = 544

// ===== 实体/场景 =====
struct cBootScreen;
struct cGameScreen;
struct MyMotionState { uint32_t dwField_0x00; uint8_t pUNKNOWN[76]; }; // total 0x50 = 80
struct SimplexNoise { void* pVtable; uint8_t pPerm[256]; uint8_t pGrad3[768]; uint8_t pPermMod12[256]; uint8_t pGrad3B[768]; }; // total 0x804 = 2052
struct cCameraInfo { uint8_t pPos[12]; uint8_t pDir[12]; uint8_t pUp[12]; uint8_t pScreenSize[8]; float flFov; float flHeading; float flMinDist; float flMaxDist; uint8_t pViewMatrix[64]; uint8_t pProjMatrix[64]; int32_t nFlags; }; // total 0xc0 = 192
struct cSoundEmitterComponent { cEntityComponent base; void* pEvents_begin; int32_t nEvents_end; int32_t nEvents_cap; int32_t nVecSoundNames_begin; int32_t nVecSoundNames_end; int32_t nVecSoundNames_cap; int32_t nMapNamedEvents; int32_t nMapHeader_color; int32_t nMapHeader_parent; int32_t nMapHeader_left; int32_t nMapHeader_right; int32_t nMapNodeCount; int32_t nActive; int32_t nVecDirtyEvents; int32_t nVecDirtyEventsPrev; int32_t nVolume; int32_t nField_0x50; }; // total 0x54 = 84
struct SceneGraphNode { void* vtable; uint16_t wFlags; uint16_t wPad6; float flMatrix0; float flMatrix1; float flMatrix2; float flMatrix3; float flMatrix4; float flMatrix5; float flMatrix6; float flMatrix7; float flMatrix8; float flMatrix9; float flMatrix10; float flMatrix11; float flMatrix12; float flMatrix13; float flMatrix14; float flMatrix15; uint32_t dwRenderFlags; uint8_t bFlag4C; uint8_t bPad4D; uint16_t wField4E; void* pChildren_begin; void* pChildren_end; uint16_t wField5A; void* pGame; uint32_t dwNameHash0; uint32_t dwNameHash1; void* pParentNode; uint32_t dwField6C; float flSortDepth; uint32_t dwField74; float flAabb_min_x; float flAabb_min_y; float flAabb_min_z; float flAabb_max_x; float flAabb_max_y; float flAabb_max_z; uint8_t bAABBDirty; }; // total 0x91 = 145
struct cSimCamera { void* pVtable; cSimulation* pSimulation; cCameraInfo cameraInfo; }; // total 0xc8 = 200
struct cImageComponent { cEntityComponent base; Texture* pTexture; }; // total 0x14 = 20
struct cPhysicsComponent { uint8_t pBase_cEntityComponent[16]; cTransformComponent* pTransformComponent; float flRadius; float flMass; float flHeight; float flStationaryDamping; cBPWorld* pPhysicsWorldSim; int32_t nECollisionShape; float flFriction; float flMotorVelX; float flMotorVelY; float flMotorVelZ; float flSavedMotorVelX; float flSavedMotorVelY; float flSavedMotorVelZ; void* pRigidBody; /* TODO: btRigidBody* */ void* pCollisionShape; /* TODO: btCollisionShape* */ void* pCompoundShape; /* TODO: btCompoundShape* */ MyMotionState* pMotionState; float flRestitution; uint8_t bActive; uint8_t bDontRemoveOnSleep; uint8_t p_pad5E[2]; uint32_t dwCollisionFlags; int16_t nCollisionMask; int16_t nCollisionGroup; uint16_t wPristineFlags; uint16_t wDirtyFlags; }; // total 0x6c = 108
struct EnvelopeTemplate { uint32_t dwVtable; uint32_t dwCount; uint32_t dwEntries; uint32_t dwCapacity; }; // total 0x10 = 16
struct WorldSim { void* pCallbackObj; void* pCallbackFunc; int32_t nCallbackAdjust; SimThread* pSimThread; }; // total 0x10 = 16
struct GroundCreep { uint8_t base_cEntityComponent[16]; uint8_t sceneGraphNode[148]; float fAccumTime; float field_0xA8; float fUpdateInterval; void* pTileGrid1; void* pTileGrid2; void* pByteArray; void* pListBegin; void* pListEnd; uint32_t field_0xC4; void* pMapLayerManagerCmp; void* pMapRenderer; void* strEncodedData; uint8_t bVBsDirty; }; // total 0xd5 = 213
struct VFXEmitterManager { void* pVtable; uint8_t pEmitterSlots[4096]; }; // total 0x1004 = 4100
struct cFrameWalker { sAnim* pAnim; int32_t nEPlayMode; int32_t nFrameIndex; int32_t nFramesRemaining; }; // total 0x10 = 16
struct cAnimStateComponent { cEntityComponent base_cEntityComponent; void* pBBoxProviderVtable; float flAnimTime; float flDeltaTimeMultiplier; uint32_t dwAnimHash; void* pAnimStr; uint32_t dwBankHash; void* pBankStr; uint32_t dwBuildHash; void* pBuildStr; uint32_t dwSkinHash; void* pSkinStr; uint32_t dwOverrideBuildHash; void* pOverrideBuildStr; int32_t nEPlayMode; int32_t nEQueuedPlayMode; uint8_t bRayTestOnBB; uint8_t bHidden; uint8_t pPad_0x4E[2]; uint32_t dwPristineDirtyFlags; uint32_t dwCurrentDirtyFlags; uint32_t dwDeserializedAnimHash; uint32_t dwQueuedAnimHash; uint32_t dwRgbaAddColour; uint32_t dwRgbaMultColour; uint32_t dwRgbaOverrideAddColour; uint32_t dwRgbaOverrideMultColour; float flOverrideShade; float flScaleX; float flScaleY; float flFinalOffsetX; float flFinalOffsetY; float flFinalOffsetZ; uint8_t bHasOverrideAddColour; uint8_t bHasOverrideMultColour; uint8_t pPad_0x8A[2]; int32_t nField_0x8C; float flHauntStrength; AnimNode* pAnimNode; void* pVecAnimQueue_begin; void* pVecAnimQueue_end; void* pVecAnimQueue_cap; int32_t nSortOrder; void* pAnimBankResource; cUITransformComponent* pUITransformComponent; float flBBMinX; float flBBMinY; float flBBMinZ; float flBBMaxX; float flBBMaxY; float flBBMaxZ; uint8_t bManualHitRegion; uint8_t pPad_0xC9[3]; void* pSymbolExchangeTree; }; // total 0xd0 = 208
struct cDontStarveSim { cSimulation base_cSimulation; cFreeCamera* pFreeCamera; float flLastCameraRotation; uint8_t pInputHandler[720]; DontStarveSystemService* pSystemService; DontStarveGameService* pGameService; }; // total 0x47c = 1148
struct cPController { float flCurrent; float flTarget; float flRate; float flField_0x0C; float flField_0x10; float flDeadzone; bool fClamp; }; // total 0x19 = 25
struct ShadowEntityComponent { cEntityComponent base; float flSizeX; float flSizeY; uint8_t bEnabled; uint8_t bPristine; uint8_t bFlags; }; // total 0x1b = 27
struct RoadBuilder { void* pVtable; uint8_t pVecControlPoints[12]; int32_t nRoadCount; uint8_t pVecVisibility[12]; uint8_t pVecGenerated[12]; }; // total 0x2c = 44
struct cDontStarveGame { cGame base_cGame; cBootScreen* pBootScreen; cGameScreen* pGameScreen; void* pSoundFEV; }; // total 0x13c = 316
struct WorldSimActual { void* pLunarBase; void* pBoostMap; /* TODO: BoostMap* */ void* pTileGrid; /* TODO: TileGrid* */ uint8_t pLunarMetadata[24]; }; // total 0x24 = 36
struct EnvelopeComponent { cEntityComponent base; void* pVecEnvelopes_begin; void* pVecEnvelopes_end; void* pVecEnvelopes_cap; }; // total 0x1c = 28
struct GroundCreepEntity { uint8_t base_cEntityComponent[16]; uint8_t nFlags; uint8_t _pad11[3]; float fRadius; }; // total 0x18 = 24
struct cTransformationHistoryCell { uint32_t dwTimeMS; float flPosX; float flPosY; float flPosZ; float flRotation; }; // total 0x14 = 20
struct cTransformationHistory { cTransformationHistoryCell* pBuffer; uint32_t dwHead; uint32_t dwTail; uint32_t dwCapacity; uint32_t dwMaxEntries; uint32_t dwTickIntervalMS; }; // total 0x18 = 24
struct cFreeCamera_sParams { uint8_t data[24]; }; // total 0x18 = 24
struct cTransformComponent { cEntityComponent base_cEntityComponent; void* pTransformProviderVtable; cPhysicsComponent* pPhysicsComponent; FollowerComponent* pFollowerComponent; float flLocalPosX; float flLocalPosY; float flLocalPosZ; float flServerPosX; float flServerPosY; float flServerPosZ; float flWorldPosX; float flWorldPosY; float flWorldPosZ; float flScaleX; float flScaleY; float flScaleZ; float flServerScaleX; float flServerScaleY; float flServerScaleZ; float flRotation; float flServerRotation; uint8_t pMatLocalTransform[64]; uint8_t pMatLocalTransformInverse[64]; uint8_t pMatWorldTransform[64]; uint8_t pMatWorldTransformInverse[64]; int32_t nFacing; int32_t nEFacingModel; cTransformationHistory* pTransformHistory; void* pPredictionHistory; int32_t nPredictionStep; int32_t nPredictionEnabled; uint16_t wPristineDirtyFlags; uint16_t wCurrentDirtyFlags; }; // total 0x17c = 380
struct cFreeCamera { cSimCamera base; cFreeCamera_sParams params; uint8_t pPosition[12]; cPController zoomController; cPController headingController; uint8_t pHeading[8]; uint8_t pFocusPos[12]; }; // total 0x14c = 332

// ===== 渲染 =====
struct VertexBufferManager { uint8_t pBase[148]; }; // total 0x94 = 148
struct AnimNode { SceneGraphNode base; void* pAnimFile; void* pBuild; uint32_t dwBankHash0; uint32_t dwBankHash1; uint32_t dwAnimHash0; uint32_t dwAnimHash1; uint32_t dwBuildHash0; uint32_t dwBuildHash1; uint32_t dwFacingMode; uint32_t dwPlayMode; float flTime; float flScaleX; float flScaleY; float flDepthBias; uint32_t dwEffectFallbackZ0; uint32_t dwEffectFallbackZN; float flEffectOverride; uint32_t dwVertexDescHandle; void* hiddenLayers_begin; void* hiddenLayers_end; void* hiddenLayers_cap; void* hiddenSymbols_begin; void* hiddenSymbols_end; void* hiddenSymbols_cap; uint8_t bDepthTestEnabled; uint8_t bDepthWriteEnabled; uint16_t wPad_F6; float flSortOrder; uint32_t dwAddColour; uint32_t dwMultColour; float flDepthFogParam; float flRandSeed; uint32_t dwRbTree_comparator; uint32_t dwRbTree_hdr_color; void* rbTree_hdr_parent; void* rbTree_hdr_left; void* rbTree_hdr_right; int32_t nRbTree_nodeCount; int32_t nBillboardType; float flRotation; float flLightOverride; float flFinalOffsetX; float flFinalOffsetY; float flFinalOffsetZ; int32_t nOverrideBankHandle1; uint32_t dwOverrideBankHash1; int32_t nOverrideBankHandle2; uint32_t dwOverrideBankHash2; int32_t nOverrideSymbolHandle1; uint32_t dwOverrideSymbolHash1; int32_t nOverrideSymbolHandle2; uint32_t dwOverrideSymbolHash2; }; // total 0x15c = 348
struct TDataCacheShadowRenderer { void* pVtable; ShadowRenderer* pOwner; uint8_t pMatrix[64]; }; // total 0x48 = 72
struct TDataCacheVFXParticleBufferRenderer { void* pVtable; VFXParticleBufferRenderer* pOwner; uint8_t pMatrix[64]; uint8_t pCachedState[28]; }; // total 0x64 = 100
struct TextNode { uint8_t pSgn[148]; uint32_t dwFontHandle; float flFontSize; float flLineSpacing; float flRegionW; float flRegionH; uint32_t dwWordWrap; uint8_t bWhitespaceWrap; uint32_t dwHAnchor; uint32_t dwVAnchor; uint8_t pColour[4]; uint8_t pEditLineHandles[56]; uint32_t dwDepthTest; uint8_t pOffset[12]; uint8_t bAutoRegion; uint8_t bStrText; uint8_t bShowEditCursor; uint8_t pEditCursorPos[4]; uint8_t bField_0x120; uint8_t bField_0x121; uint8_t bField_0x122; uint32_t dwTexHandle; uint32_t dwField_0x128; uint32_t dwField_0x12C; float pAABB_max[3]; float pAABB_min[3]; uint32_t dwField_0x148; uint32_t dwField_0x14C; uint8_t pColour2[4]; uint32_t dwField_0x160; }; // total 0x164 = 356
struct AnimationFile { char* filename_str_ptr; void* pAnimArray; void* pAnimElemArray; void* pFrameArray; void* pElemHashArray; uint32_t numElements; uint32_t numAnims; uint32_t numFrames; uint32_t numAnimElems; void* pBuild; }; // total 0x28 = 40
struct TextureManager { uint8_t pBase[148]; }; // total 0x94 = 148
struct MapRenderer { GameRenderer* pGameRenderer; void* pLayerMgr; /* TODO: MapLayerManagerComponent* */ uint32_t dwVertDescHandle; uint32_t dwEffectHandle_1; uint32_t dwEffectHandle_2; uint32_t dwBlendTextureHandle; uint32_t dwBlendFactor; }; // total 0x1c = 28
struct sAnim { void* pParent; void* pFrames; float flFps; uint32_t dwBankHash0; uint32_t dwBankHash1; uint32_t dwNumFrames; void* name; uint8_t bFacingByte; uint8_t bPad1D; uint8_t bPad1E; uint8_t bPad1F; float flDuration; }; // total 0x24 = 36
struct VertexDescriptionManager { uint8_t pBase[148]; }; // total 0x94 = 148
struct Batcher { uint32_t dwRenderer; uint32_t dwTexHandle0; uint32_t dwTexHandle1; uint32_t dwTexHandle2; uint32_t dwVertDescHandle; uint32_t dwBlendMode; uint32_t dwEffectHandle; float flAlphaMin; float flAlphaMax; float flEffectParam0; float flEffectParam1; float flEffectParam2; float flEffectParam3; uint8_t bHasEffectParams; uint8_t b_pad35; uint8_t b_pad36; uint8_t b_pad37; uint32_t dwVertBegin; uint32_t dwVertEnd; uint32_t dwVertCap; }; // total 0x44 = 68
struct TDataCacheGameRender { void* pVtable; void* pOwner; uint8_t pMatrix[64]; uint8_t pUNKNOWN_0x48[1192]; }; // total 0x4f0 = 1264
struct TDataCacheParticleBufferRenderer { void* pVtable; ParticleBufferRenderer* pOwner; uint8_t pMatrix[64]; uint32_t dwField_48; ParticleEmitter* pEmitter; uint32_t dwField_50; uint32_t dwNumVerts; void* pData0; void* pData1; void* pData2; void* pData3; void* pData4; }; // total 0x6c = 108
struct VFXParticleBufferRenderer { uint8_t pSgn[148]; VFXEffectEmitter* pEmitter; }; // total 0x98 = 152
struct TDataCacheRoadManagerNode { void* pVtable; void* pOwner; uint8_t pMatrix[64]; void* pStripData_begin; void* pStripData_end; void* pStripData_cap; uint32_t dwVertDescHandle; uint8_t pField_58[4]; void* pAABB_begin; void* pAABB_end; void* pAABB_cap; GameRenderer* pRenderer; uint8_t pField_0x6C[4]; }; // total 0x70 = 112
struct AnimManager { void* vtable; uint32_t dwBase_04; uint32_t dwBase_08; uint32_t dwBase_0C; uint32_t dwBase_10; uint32_t dwPad14; void* vec_begin; uint32_t dwField_1C; void* vec_end; void* vec_cap; uint32_t dwField_28; uint32_t dwField_2C; uint32_t dwField_30; uint32_t dwField_34; void* strField38; void* pRenderer; void* bankMap_begin; void* bankMap_end; void* bankMap_cap; void* buildMap_begin; void* buildMap_end; uint32_t dwField_54; uint32_t dwShader_anim; uint32_t dwShader_anim_fade; uint32_t dwShader_anim_haunted; uint32_t dwShader_bloom; uint32_t dwShader_fade_haunted; uint32_t dwVertexDesc; uint32_t dwErosionTexture; }; // total 0x74 = 116
struct sBuild { void* pParent; uint32_t dwName_cow; void* pTexturesVec_begin; void* pTexturesVec_end; void* pTexturesVec_cap; void* pTextureHandles_begin; void* pTextureHandles_end; uint32_t dw_pad28; void* pSymbols; void* pSymbolFrames; uint32_t dwVbHandle; uint32_t dwVbHandle2; void* pVertexData; void* pVertexData2; uint32_t dwNumVerts; uint32_t dwNumVerts2; uint32_t dwNumSymbolFrames; uint32_t dwNumSymbols; bool fTexturesLoaded; uint8_t p_pad49[3]; }; // total 0x4c = 76
struct TDataCacheSceneNode { void* pVtable; SceneGraphNode* pOwner; }; // total 0x8 = 8
struct ParticleBuffer { uint32_t dwColour0; uint32_t dwColour1; uint16_t wActiveCount; void* pParticleDataA; void* pParticleDataB; void* pRotationData; void* pDataC; void* pDataD; }; // total 0x20 = 32
struct TDataCacheMapComponent { void* pVtable; SceneGraphNode* pOwner; uint8_t pMatrix[64]; uint8_t pMapCache[96]; }; // total 0xa8 = 168
struct HWBuffer { void* pVtable; uint32_t dwStride; uint32_t dwCount; uint32_t dwField_0x0C; uint32_t dwEUsage; }; // total 0x14 = 20
struct IndexBuffer { HWBuffer base; }; // total 0x14 = 20
struct RenderState { uint8_t UNKNOWN[372]; }; // total 0x174 = 372
struct CommandBuffer { uint8_t UNKNOWN[120]; }; // total 0x78 = 120
struct Matrix4 { float m[16]; }; // total 0x40 = 64
struct Renderer { uint32_t dwVtable; uint32_t dwField_04; uint32_t dwField_08; uint8_t bField_0C; uint8_t p_pad0D[3]; RenderState renderState; uint32_t dwShaderConstantSet; uint32_t dwShaderPushCount; uint32_t dwResManager; uint32_t dwVertDescMgr; uint32_t dwField_194; uint32_t dwField_198; uint32_t dwField_19C; uint32_t dwField_1A0; uint32_t dwField_1A4; uint8_t p_gap1A8[8]; uint32_t dwField_1B0; uint32_t dwListSentinel; uint32_t dwListNext; CommandBuffer cmdBuf; }; // total 0x234 = 564
struct WallStencilBuffer { void* pVtable; uint8_t pListNode[8]; uint32_t dwListSentinel; uint32_t dwListNext; uint32_t dwField_0x18; GameRenderer* pRenderer; uint32_t dwDepthTextureHandle; uint32_t dwRenderTargetHandle; uint32_t dwVBHandle; uint32_t dwVertDescHandle; uint32_t dwEffectHandle_depth; uint32_t dwEffectHandle_tri; void* pDispatcher; /* TODO: cEventDispatcher* */ uint8_t bRenderEnabled; }; // total 0x3d = 61
struct TDataCacheVideoNode { void* pVtable; VideoNode* pOwner; uint8_t pMatrix[64]; int32_t nHAnchor; int32_t nVAnchor; float pSizeXY[2]; uint32_t dwEffectHandle; uint32_t dwTint; int32_t nFrameW; int32_t nFrameH; void* pFramePixels; uint32_t dwTexY; uint32_t dwTexU; uint32_t dwTexV; bool fUseTransTex; uint8_t pPad_0x79[3]; }; // total 0x7c = 124
struct ShaderConstantSet { uint32_t dwField_0x00; uint8_t pDataStack[4096]; uint8_t pHashToIndexMap[16]; uint8_t pListSentinel[16]; uint32_t dwListHead; }; // total 0x1028 = 4136
struct TDataCacheImageNode { void* pVtable; ImageNode* pOwner; uint8_t pMatrix[64]; uint8_t pImageCacheState[108]; }; // total 0xb4 = 180
struct VertexBuffer { HWBuffer base; }; // total 0x14 = 20
struct UIRenderAssetManager { uint32_t dwVtable; uint32_t dwRenderer; uint32_t dwVertDescHandle; uint32_t dwEffectHandle_ui; uint32_t dwEffectHandle_yuv; uint32_t dwEffectHandle_anim; uint32_t dwVbHandle; uint32_t dwBatcher; }; // total 0x20 = 32
struct TDataCacheAnimNode { void* vtable; AnimNode* pAnimNode; float matrix_0; float matrix_1; float matrix_2; float matrix_3; float matrix_4; float matrix_5; float matrix_6; float matrix_7; float matrix_8; float matrix_9; float matrix_10; float matrix_11; float matrix_12; float matrix_13; float matrix_14; float matrix_15; float scaleX; float scaleY; uint32_t facingMode; int32_t billboardType; float rotation; float lightOverride; float finalOffsetX; float finalOffsetY; float finalOffsetZ; float depthFogParam; uint32_t unk_70; sBuild* pBuild; uint32_t unk_78; uint32_t unk_7C; uint32_t effectFallbackZ0; uint32_t effectFallbackZN; float effectOverride; uint32_t dwAddColour; uint32_t dwMultColour; float unk_94; AnimNode* pAnimNodeRef; uint8_t bDepthWriteEnabled; uint8_t bDepthTestEnabled; uint8_t pad_9E; uint8_t pad_9F; float depthBias; uint32_t vertexDescHandle; void* hiddenLayers_begin; void* hiddenLayers_end; void* hiddenLayers_cap; void* hiddenSymbols_begin; void* hiddenSymbols_end; void* hiddenSymbols_cap; uint32_t rbTree_comparator; void* rbTree_hdr_color; void* rbTree_hdr_parent; void* rbTree_hdr_left; void* rbTree_hdr_right; uint32_t rbTree_nodeCount; int32_t overrideBankHandle1; uint32_t overrideBankHash1; int32_t overrideBankHandle2; uint32_t overrideBankHash2; int32_t overrideSymbolHandle1; uint32_t overrideSymbolHash1; int32_t overrideSymbolHandle2; uint32_t overrideSymbolHash2; }; // total 0xf8 = 248
struct TDataCacheBase { void* pVtable; }; // total 0x4 = 4
struct TDataCacheMiniMapRenderer { void* pVtable; void* pOwner; uint8_t pMatrix[64]; uint8_t pMiniMapCache[224]; }; // total 0x128 = 296
struct TDataCacheWorld { void* pVtable; void* pOwner; uint8_t pMatrix[64]; uint8_t pUNKNOWN_0x48[880]; }; // total 0x3b8 = 952
struct ImageNode { uint8_t pSgn[148]; int32_t nMaxLines; int32_t nField_98; uint32_t dwField_9C; uint32_t dwBlendMode; uint32_t dwTextureHandle; uint32_t dwTextureHandle2; uint32_t dwField_AC; float pSize[2]; uint32_t dwField_B8; uint32_t dwField_BC; uint32_t dwTint; float flAlphaMax; float flAlphaMin; float flField_CC; float pVOffset[3]; uint32_t dwField_DC; float flField_E0; float pVEffectParams[2]; uint8_t pVField_EC[8]; bool fDepthTest; bool fDepthWrite; float pVField_F8[3]; }; // total 0x104 = 260
struct ParticleBufferRenderer { uint8_t pSgn[148]; GameRenderer* pRenderer; ParticleEmitter* pEmitter; uint32_t dwField_0x9C; }; // total 0xa0 = 160
struct GraphRenderer { void* pVtable; uint8_t pVecTriangles[12]; uint32_t dwExtraVertBuffer; uint32_t dwField_0x14; uint32_t dwField_0x18; uint8_t pVecStrings[12]; uint8_t pVecDebugLines[12]; uint32_t dwField_0x34; uint32_t dwField_0x38; GameRenderer* pGameRenderer; uint32_t dwEffectHandle_1; uint32_t dwEffectHandle_2; uint32_t dwVertDescHandle_1; uint32_t dwVertDescHandle_2; uint32_t dwEffectHandle_3; uint32_t dwEffectHandle_4; }; // total 0x58 = 88
struct HWTexture { BaseTexture base; uint32_t dwGlTextureId; int32_t nWrapS; int32_t nWrapT; int32_t nFilterMin; int32_t nFilterMag; }; // total 0x28 = 40
struct TDataCacheTextNode { void* pVtable; TextNode* pOwner; uint8_t pMatrix[64]; uint8_t pTextCacheState[164]; }; // total 0xec = 236
struct IndexBufferManager { uint8_t pBase[148]; }; // total 0x94 = 148
struct ShadowRenderer { uint8_t pSgn[148]; uint32_t dwField_0x94; uint32_t dwVertDescHandle; uint32_t dwEffectHandle; ShadowManagerComponent* pManager; Renderer* pRenderer; }; // total 0xa8 = 168
struct TDataCacheMiniMapComponent { void* pVtable; void* pOwner; uint8_t pMatrix[64]; uint8_t pUNKNOWN_0x48[32]; }; // total 0x68 = 104
struct sBuildSymbolFrame { uint32_t frameStart; uint32_t frameCount; uint32_t dwVertexStart; uint32_t dwVertexCount; uint32_t dwVertexStart2; uint32_t dwVertexCount2; float bb_min_x; float bb_min_y; float bb_min_z; float bb_max_x; float bb_max_y; float bb_max_z; float radius; }; // total 0x34 = 52
struct Texture { BaseTexture base; uint32_t dwField_0x14; uint32_t dwField_0x18; uint32_t dwField_0x1C; uint32_t dwField_0x20; uint32_t dwField_0x24; }; // total 0x28 = 40
struct DebugRenderer { uint8_t pVecDebugLines[12]; }; // total 0x58 = 88
struct GameRenderer { Renderer base; Matrix4 pMatrices[18]; uint32_t pMatrices_2[18]; uint8_t p_pad6FC[72]; uint32_t dwField_744; uint8_t p_gap748[32]; uint32_t dwField_768; uint8_t p_gap76C[32]; uint32_t dwPtr78C; uint32_t dwPtr790; uint32_t dwPtr794; uint32_t dwPtr798; uint32_t dwPtr79C; uint32_t dwPtr7A0; uint32_t dwPtr7A4; uint32_t dwPtr7A8; uint32_t dwPtr7AC; uint32_t dwPtr7B0; uint32_t dwPtr7B4; uint32_t dwPtr7B8; uint32_t dwUIRenderMgr; uint32_t dwGame; uint32_t dwErosionMode; uint32_t dwEffectH_7C8; uint32_t dwEffectH_7CC; uint32_t dw_gap7D0; uint32_t dwEffectH_7D4; uint32_t dwEffectH_7D8; uint32_t dwEffectH_7DC; uint32_t dw_gap7E0; uint32_t dwEffectH_7E4; }; // total 0x7e8 = 2024

// ===== UI =====
struct cImageWidget { cEntityComponent base; void* pVtable2; void* pImageObj; }; // total 0x18 = 24
struct PurchasesManagerComponent { void* pVtable; uint8_t pVecStrings[12]; }; // total 0x10 = 16
struct WindowManager { void* pVtable; uint8_t pListenerListHeader[24]; Mutex mutex; float flWidth; float flHeight; Renderer* pRenderer; void* pSDLWindow; void* pGLContext; void* pEventDispatcher; uint8_t pVecDisplayResolutions[12]; uint8_t pVecDisplayModeMaps[12]; bool fIsFullscreen; bool fFlag_0x85; bool fFlag_0x86; uint8_t bPad; }; // total 0x88 = 136
struct cUIScreen { void* pVtable; uint8_t pM_strName[4]; cGame* pGame; }; // total 0xC = 12
struct ControlMapper { void* pInputManager; /* TODO: IInputManager* */ uint16_t wIsMapping; void* pMappingDeviceId; int32_t nControlCount; int32_t nControlType; void* pMappingScratch; void* pInputManager2; /* TODO: IInputManager* */ int32_t nLastInputId; uint8_t bMappingChanged; ControlMapper* pSelf; void* pGlobal2; int32_t nCallbackUser; int32_t nInputMappings; int32_t nDeviceDirtyFlags; int32_t nNumDevices; uint8_t pMappingTableBlob[452]; }; // total 0x208 = 520
struct cConsoleInput { uint8_t pThread[120]; uint8_t pM_strName[4]; uint8_t pDeque[40]; Mutex Mutex; }; // total 0xDC = 220
struct cUnpackModThread { uint8_t pThread[120]; uint8_t pStrs[12]; uint8_t pUgcResult[288]; void* pWorkshop; /* TODO: SteamWorkshop* */ }; // total 0x1A8 = 424
struct FontComponent { cEntityComponent base; }; // total 0x10 = 16
struct cVideoWidget { cEntityComponent base; void* pVtable2; VideoNode* pVideoObj; }; // total 0x18 = 24
struct cGameScreen { cUIScreen base; cGame* pGame; }; // total 0x10 = 16
struct cClientColourPicker { uint8_t pMap_colour[24]; uint8_t pVecColours[12]; uint8_t pColour[4]; }; // total 0x28 = 40
struct cBootScreen { cUIScreen base; }; // total 0xC = 12
struct cTextWidget { cEntityComponent base; TextNode* pTextObj; }; // total 0x14 = 20

// ===== 系统/杂项 =====
struct GameService_PlayerId { uint32_t pM_data[9]; }; // total 0x24 = 36
struct FileOpResult { void* pVtable; uint8_t pM_callback[12]; void* pContext; int32_t nRequestType; int32_t nEStatus; GameService_PlayerId playerId; char pData[256]; int32_t nField_0x140; int32_t nField_0x144; }; // total 0x148 = 328
struct GameLibConfig { bool fEnableAudio; bool fField_01; bool fField_02; bool fField_03; int32_t nMaxPlayers; int32_t nField_08; int32_t nField_0C; int32_t nField_10; cNetID2 netId; ProcessId processId; cStdString str_0; cStdString str_1; cStdString str_2; cStdString str_3; cStdString str_4; cStdString strGameName; cStdString strBindAddress; cStdString str_7; bool fField_64; uint8_t pPad_65[3]; cNetID2 netId2; }; // total 0x94 = 148
struct FileOpRequest { void* pVtable; uint8_t pM_callback[12]; void* pContext; int32_t nRequestType; GameService_PlayerId playerId; char pFilename[256]; uint32_t dwDataLen; void* pData; }; // total 0x144 = 324
struct GrowableBinaryBufferWriter { void* pVtable; void* pVec; }; // total 0x8 = 8
struct FileHandle { int32_t nMOp; int32_t nMStatus; int32_t nMNumRefs; char pM_path[256]; uint8_t pM_pathHash[8]; int32_t nMMode; int32_t nField_0x118; int32_t nM_nSize; int32_t nM_nBytesRead; void* pM_pData; int32_t nField_0x128; int32_t nField_0x12C; int32_t nField_0x130; int32_t nField_0x134; uint8_t pMResultHandler[12]; int32_t nField_0x144; int32_t nField_0x148; int32_t nField_0x14C; uint8_t bHasData; Semaphore semaphore; }; // total 0x158 = 344
struct SimThread { uint8_t pBaseThread[120]; void* pLuaState; /* TODO: lua_State* */ cSimulation* pSimulation; uint8_t bSuccess; uint8_t bPad_81; uint8_t bPad_82; uint8_t bPad_83; char* pStrResult; int32_t nRefTraceback; }; // total 0x8c = 140
struct TwitchAuthThread { uint8_t pThread[120]; int32_t nField_0x78; int32_t nField_0x7C; int32_t nField_0x80; int32_t nField_0x98; uint8_t pStr_0xA0[4]; uint8_t pStr_0xA4[4]; Socket m_socket; }; // total 0xc1 = 193
struct GameService_PlayerInfo { GameService_PlayerId playerId; uint8_t pM_strName[64]; uint8_t pM_strDisplayName[64]; uint8_t bIsSignedIn; uint8_t bIsOnline; uint8_t p_pad[64]; }; // total 0x126 = 294
struct cDedicatedServerProcess { Process base; int32_t nField_0x20; bool fField_0x24; uint8_t pM_str[4]; uint8_t pVecSignalHandlers[12]; }; // total 0x38 = 56
struct cPlayerSaveLocation { uint8_t pMap[24]; }; // total 0x18 = 24
struct cMasterServerRequest { void* pVtable; uint8_t bInFlight; uint8_t pM_strURL[4]; cMasterServer* pMasterServer; }; // total 0x10 = 16
struct BinaryBufferWriter { void* pVtable; void* pBuffer; /* TODO: Buffer* */ uint32_t dwOffset; }; // total 0xc = 12
struct HttpClient2 { CurlRequestManager* pCurlRequestManager; }; // total 0x4 = 4
struct BinaryBufferReader { void* pVtable; int32_t nOffset; void* pBuffer; uint32_t dwBufferLength; }; // total 0x10 = 16
struct FileSystem { void* pVtable; uint8_t pM_strMountName[8]; char pM_szMountPath[256]; uint8_t bMounted; }; // total 0x10d = 269
struct CABody { uint8_t pBounds[16]; uint8_t pTileGrid[32]; }; // total 0x30 = 48
struct cSteamRichPresence { void* pVtable; uint8_t pM_presence[24]; uint8_t bDirty; cNetID2 m_serverNetId; uint8_t pM_connectString[4]; uint8_t bHasConnectString; }; // total 0x53 = 83
struct GameServiceImpl { void* pVtable; int32_t nNumSimultaneousPlayers; int32_t nActivePlayerCount; uint8_t pPlayerInfo[294]; }; // total 0x132 = 306
struct GrowableEndianSwappedBinaryBufferWriter { GrowableBinaryBufferWriter base; }; // total 0x8 = 8
struct LocalFileSystem { FileSystem base; uint8_t pM_strRoot[4]; }; // total 0x114 = 276
struct ZipFileSystem { FileSystem base; void* pZipArchive; }; // total 0x114 = 276
struct EndianSwappedBinaryBufferReader { BinaryBufferReader base; }; // total 0x10 = 16
