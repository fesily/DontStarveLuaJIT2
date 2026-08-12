# audit-s5-misc — S5 系统/杂项 void* 字段纠正表

> Phase 0.5 只读审计。源: `sync-s5-misc.md` exists:true 结构 + `types_common.h` + `tier0-core.md` / `tier3-e-system.md` / `remaining-f4-misc.md` / `remaining-c-kleifile.md` / `remaining-d-nested.md`。
> 规则: 字段名语义明确且类型已在 types_common.h → **确定**; 语义明确但类型未建 → **推断**; 无证据 → **待定**; vtable/vector 三件套/rb-tree/`pPad_*`/`pField_*`/`pUnknown*`/`pVec*` → **跳过**。
> missing 类型(31)不纠正。不写 Ghidra。

## Scope

- exists:true (57): cApplication, cLogger, cLoggerImplementation, cInventoryManager, cSoundSystem, cBPWorld, cSimTime, cDedicatedServerProcess, GameLibConfig, DontStarveGameService, GameServiceImpl, DontStarveSystemService, GameService_PlayerInfo, CABody, HttpClient2, FileSystem, LocalFileSystem, ZipFileSystem, MemoryCache, BinaryBufferReader, BinaryBufferWriter, GrowableBinaryBufferWriter, EndianSwappedBinaryBufferReader, GrowableEndianSwappedBinaryBufferWriter, FileHandle, FileOpRequest, FileOpResult, Timer, Mutex, Semaphore, Thread, SimThread, TwitchAuthThread, FrameProfiler, PerfIndicator, PerfPane, Metrics, GoogleAnalyticsCookie, GoogleAnalyticsGenerator, Heap, cGiftingManager, PersistentStorage, ZipSaver, cPlayerSaveLocation, cGameEvent, cInputKeyEvent, cInputMouseButtonEvent, cInputMouseMoveEvent, cInputGestureEvent, cInputTextEvent, cTogglePauseEvent, cFocusGainedEvent, cFocusLostEvent, WindowMoveEvent, ResizeEvent, cMasterServerRequest, cSteamRichPresence
- notes 别名布局: SoundProjectManager (alias for cSoundProjectManager); GameService_PlayerId (related; used by GameService_PlayerInfo / FileOp*)
- void* 字段判定: **确定 12 / 推断 13 / 待定 9 / 跳过 69**
- 无 void* 的 exists 结构: cDedicatedServerProcess, GameLibConfig, GameService_PlayerInfo, CABody, LocalFileSystem, EndianSwappedBinaryBufferReader, GrowableEndianSwappedBinaryBufferWriter, Timer, Mutex, TwitchAuthThread, cPlayerSaveLocation

## cApplication

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pMSystemService | 0x0 | void * | DontStarveSystemService* | 确定 |
| pMGameService | 0x4 | void * | DontStarveGameService* | 确定 |
| pMGame | 0x8 | void * | cGame* | 确定 |

- `pMSystemService`@0x0: 字段名语义; types_common 已定义 DontStarveSystemService
- `pMGameService`@0x4: 字段名语义; types_common 已定义 DontStarveGameService
- `pMGame`@0x8: pMGame→cGame*; types_common 已定义 cGame (运行时多为 cDontStarveGame)

## cLogger

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |

## cLoggerImplementation

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |

## cInventoryManager

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pList_0x08_next | 0x8 | void * | void * | 跳过 |
| pList_0x08_prev | 0xc | void * | void * | 跳过 |
| pMap1_parent | 0x18 | void * | void * | 跳过 |
| pMap1_left | 0x1c | void * | void * | 跳过 |
| pMap1_right | 0x20 | void * | void * | 跳过 |
| pMap2_parent | 0x2c | void * | void * | 跳过 |
| pMap2_left | 0x30 | void * | void * | 跳过 |
| pMap2_right | 0x34 | void * | void * | 跳过 |

## cSoundSystem

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pMap1_parent | 0xc | void * | void * | 跳过 |
| pMap1_left | 0x10 | void * | void * | 跳过 |
| pMap1_right | 0x14 | void * | void * | 跳过 |
| pMap2_parent | 0x24 | void * | void * | 跳过 |
| pMap2_left | 0x28 | void * | void * | 跳过 |
| pMap2_right | 0x2c | void * | void * | 跳过 |

## cBPWorld

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pBroadphase | 0x4 | void * | btBroadphaseInterface* | 推断 |
| pConfig | 0x8 | void * | btDefaultCollisionConfiguration* | 推断 |
| pDispatcher | 0xc | void * | btCollisionDispatcher* | 推断 |
| pSolver | 0x10 | void * | btSequentialImpulseConstraintSolver* | 推断 |
| pWorld | 0x14 | void * | btDiscreteDynamicsWorld* | 推断 |
| pGroundShape | 0x18 | void * | btCollisionShape* | 推断 |
| pGroundBody | 0x1c | void * | btRigidBody* | 推断 |
| pSimulation | 0x30 | void * | cSimulation* | 确定 |

- `pBroadphase`@0x4: Bullet 宽相接口命名; 类型不在 types_common (需建类型)
- `pConfig`@0x8: Bullet 碰撞配置命名; 类型不在 types_common (需建类型)
- `pDispatcher`@0xc: Bullet 分发器命名; 类型不在 types_common (需建类型)
- `pSolver`@0x10: Bullet 约束求解器命名; 类型不在 types_common (需建类型)
- `pWorld`@0x14: Bullet 动力学世界命名; 类型不在 types_common (需建类型)
- `pGroundShape`@0x18: 地面碰撞形状; 类型不在 types_common (需建类型)
- `pGroundBody`@0x1c: 地面刚体; 类型不在 types_common (需建类型)
- `pSimulation`@0x30: 字段名语义; types_common 已定义 cSimulation

## cSimTime

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |

## cDedicatedServerProcess

_无 void* 字段_

## GameLibConfig

_无 void* 字段_

## DontStarveGameService

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pSystemService | 0x4 | void * | DontStarveSystemService* | 确定 |

- `pSystemService`@0x4: 字段名语义; types_common 已定义; header: void* pSystemService

## GameServiceImpl

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |

## DontStarveSystemService

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pCacheMap | 0xc | void * | void * | 待定 |

- `pCacheMap`@0xc: map 节点/缓存表指针, 无元素类型证据

## GameService_PlayerInfo

_无 void* 字段_

## CABody

_无 void* 字段_

## HttpClient2

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pCurlRequestManager | 0x0 | void * | CurlRequestManager* | 确定 |

- `pCurlRequestManager`@0x0: 证据 C2: this[0]=new CurlRequestManager(); types_common 已定义

## FileSystem

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |

## LocalFileSystem

_无 void* 字段_

## ZipFileSystem

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pZipArchive | 0x110 | void * | void * | 待定 |

- `pZipArchive`@0x110: remaining-c: zip_open 返回值; 不透明句柄

## MemoryCache

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pM_cache_parent | 0x8 | void * | void * | 跳过 |
| pM_cache_left | 0xc | void * | void * | 跳过 |
| pM_cache_right | 0x10 | void * | void * | 跳过 |

## BinaryBufferReader

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pBuffer | 0x8 | void * | void * | 待定 |

- `pBuffer`@0x8: remaining-c: Buffer::GetData() 返回数据指针; 保持 void*

## BinaryBufferWriter

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pBuffer | 0x4 | void * | Buffer* | 推断 |

- `pBuffer`@0x4: remaining-c: ctor 存 Buffer&; Buffer 类型不在 types_common (需建类型)

## GrowableBinaryBufferWriter

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pVec | 0x4 | void * | void * | 跳过 |

## EndianSwappedBinaryBufferReader

_无 void* 字段_

## GrowableEndianSwappedBinaryBufferWriter

_无 void* 字段_

## FileHandle

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pM_pData | 0x124 | void * | void * | 待定 |

- `pM_pData`@0x124: 无类型证据

## FileOpRequest

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pContext | 0x10 | void * | void * | 待定 |
| pData | 0x140 | void * | void * | 待定 |

- `pContext`@0x10: 通用回调上下文
- `pData`@0x140: 操作载荷; 无固定类型

## FileOpResult

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pContext | 0x10 | void * | void * | 待定 |

- `pContext`@0x10: 自 request 复制的通用上下文

## Timer

_无 void* 字段_

## Mutex

_无 void* 字段_

## Semaphore

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pSem | 0x0 | void * | SDL_sem* | 推断 |

- `pSem`@0x0: review-slice14: SDL_CreateSemaphore(0); 平台类型不在 types_common (需建类型)

## Thread

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pThread | 0x48 | void * | pthread_t | 推断 |

- `pThread`@0x48: review-slice14: pthread_create((pthread_t*)(this+0x48)); 文档名 hThread; 非 Thread* (平台类型)

## SimThread

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pLuaState | 0x78 | void * | lua_State* | 推断 |
| pSimulation | 0x7c | void * | cSimulation* | 确定 |
| pStrResult | 0x84 | void * | char* | 确定 |

- `pLuaState`@0x78: 与 cSimulation.pLuaState 同语义; types_common 仅注释 (需建类型)
- `pSimulation`@0x7c: 字段名语义; types_common 已定义
- `pStrResult`@0x84: pStr* 字符串指针命名

## TwitchAuthThread

_无 void* 字段_

## FrameProfiler

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |

## PerfIndicator

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pGame | 0x0 | void * | cGame* | 确定 |

- `pGame`@0x0: tier3-e: pGame | cGame* | ctor=param_2

## PerfPane

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVecIndicators_begin | 0x0 | void * | void * | 跳过 |
| pVecIndicators_end | 0x4 | void * | void * | 跳过 |
| pVecIndicators_cap | 0x8 | void * | void * | 跳过 |
| pVecGrids_begin | 0xc | void * | void * | 跳过 |
| pVecGrids_end | 0x10 | void * | void * | 跳过 |
| pVecGrids_cap | 0x14 | void * | void * | 跳过 |
| pGame | 0x18 | void * | cGame* | 确定 |

- `pGame`@0x18: tier3-e: pGame | cGame*

## Metrics

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |

## GoogleAnalyticsCookie

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pM_args_begin | 0xc | void * | void * | 跳过 |
| pM_args_end | 0x10 | void * | void * | 跳过 |
| pM_args_cap | 0x14 | void * | void * | 跳过 |

## GoogleAnalyticsGenerator

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pM_settings_parent | 0x10 | void * | void * | 跳过 |
| pM_settings_left | 0x14 | void * | void * | 跳过 |
| pM_settings_right | 0x18 | void * | void * | 跳过 |

## Heap

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pBase | 0x8 | void * | void * | 待定 |
| pFirstBlock | 0xc | void * | MemoryBlock* | 推断 |
| pLastBlock | 0x10 | void * | MemoryBlock* | 推断 |

- `pBase`@0x8: 堆基址原始内存
- `pFirstBlock`@0xc: review-slice15: MemoryBlock* 链表首块; 类型不在 types_common (需建类型)
- `pLastBlock`@0x10: review-slice15: MemoryBlock* 链表末块; 类型不在 types_common (需建类型)

## cGiftingManager

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pM_listA_next | 0x8 | void * | void * | 跳过 |
| pM_listA_prev | 0xc | void * | void * | 跳过 |
| pM_unverifiedReceipts_next | 0x60 | void * | void * | 跳过 |
| pM_unverifiedReceipts_prev | 0x64 | void * | void * | 跳过 |

## PersistentStorage

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |

## ZipSaver

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pZipFile | 0x0 | void * | void * | 待定 |

- `pZipFile`@0x0: minizip zipOpen 句柄; 不透明

## cPlayerSaveLocation

_无 void* 字段_

## cGameEvent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |

## cInputKeyEvent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |

## cInputMouseButtonEvent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |

## cInputMouseMoveEvent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |

## cInputGestureEvent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |

## cInputTextEvent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |

## cTogglePauseEvent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |

## cFocusGainedEvent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |

## cFocusLostEvent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |

## WindowMoveEvent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |

## ResizeEvent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |

## cMasterServerRequest

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pMasterServer | 0xc | void * | cMasterServer* | 确定 |

- `pMasterServer`@0xc: evidence: ctor=param_1 cMasterServer*; types_common 已定义

## cSteamRichPresence

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |

## SoundProjectManager (alias for cSoundProjectManager)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pSoundSystem | 0x3c | void * | cSoundSystem* | 确定 |

- `pSoundSystem`@0x3c: 字段名语义; types_common 已定义 cSoundSystem

---

## 汇总

确定 **12** / 推断 **13** / 待定 **9** / 跳过 **69**

### 确定 (可直接回写)

| Struct | 字段 | 偏移 | 目标 |
|--------|------|------|------|
| cApplication | pMSystemService | 0x0 | DontStarveSystemService* |
| cApplication | pMGameService | 0x4 | DontStarveGameService* |
| cApplication | pMGame | 0x8 | cGame* |
| cBPWorld | pSimulation | 0x30 | cSimulation* |
| DontStarveGameService | pSystemService | 0x4 | DontStarveSystemService* |
| HttpClient2 | pCurlRequestManager | 0x0 | CurlRequestManager* |
| SimThread | pSimulation | 0x7c | cSimulation* |
| SimThread | pStrResult | 0x84 | char* |
| PerfIndicator | pGame | 0x0 | cGame* |
| PerfPane | pGame | 0x18 | cGame* |
| cMasterServerRequest | pMasterServer | 0xc | cMasterServer* |
| SoundProjectManager (alias for cSoundProjectManager) | pSoundSystem | 0x3c | cSoundSystem* |

### 推断 (需建类型后再回写)

| Struct | 字段 | 偏移 | 目标 | 说明 |
|--------|------|------|------|------|
| cBPWorld | pBroadphase | 0x4 | btBroadphaseInterface* | Bullet 宽相接口命名; 类型不在 types_common (需建类型) |
| cBPWorld | pConfig | 0x8 | btDefaultCollisionConfiguration* | Bullet 碰撞配置命名; 类型不在 types_common (需建类型) |
| cBPWorld | pDispatcher | 0xc | btCollisionDispatcher* | Bullet 分发器命名; 类型不在 types_common (需建类型) |
| cBPWorld | pSolver | 0x10 | btSequentialImpulseConstraintSolver* | Bullet 约束求解器命名; 类型不在 types_common (需建类型) |
| cBPWorld | pWorld | 0x14 | btDiscreteDynamicsWorld* | Bullet 动力学世界命名; 类型不在 types_common (需建类型) |
| cBPWorld | pGroundShape | 0x18 | btCollisionShape* | 地面碰撞形状; 类型不在 types_common (需建类型) |
| cBPWorld | pGroundBody | 0x1c | btRigidBody* | 地面刚体; 类型不在 types_common (需建类型) |
| BinaryBufferWriter | pBuffer | 0x4 | Buffer* | remaining-c: ctor 存 Buffer&; Buffer 类型不在 types_common (需建类型) |
| Semaphore | pSem | 0x0 | SDL_sem* | review-slice14: SDL_CreateSemaphore(0); 平台类型不在 types_common (需建类型) |
| Thread | pThread | 0x48 | pthread_t | review-slice14: pthread_create((pthread_t*)(this+0x48)); 文档名 hThread; 非 Thread* (平台类型) |
| SimThread | pLuaState | 0x78 | lua_State* | 与 cSimulation.pLuaState 同语义; types_common 仅注释 (需建类型) |
| Heap | pFirstBlock | 0xc | MemoryBlock* | review-slice15: MemoryBlock* 链表首块; 类型不在 types_common (需建类型) |
| Heap | pLastBlock | 0x10 | MemoryBlock* | review-slice15: MemoryBlock* 链表末块; 类型不在 types_common (需建类型) |

### 待定 (保持 void*)

| Struct | 字段 | 偏移 | 说明 |
|--------|------|------|------|
| DontStarveSystemService | pCacheMap | 0xc | map 节点/缓存表指针, 无元素类型证据 |
| ZipFileSystem | pZipArchive | 0x110 | remaining-c: zip_open 返回值; 不透明句柄 |
| BinaryBufferReader | pBuffer | 0x8 | remaining-c: Buffer::GetData() 返回数据指针; 保持 void* |
| FileHandle | pM_pData | 0x124 | 无类型证据 |
| FileOpRequest | pContext | 0x10 | 通用回调上下文 |
| FileOpRequest | pData | 0x140 | 操作载荷; 无固定类型 |
| FileOpResult | pContext | 0x10 | 自 request 复制的通用上下文 |
| Heap | pBase | 0x8 | 堆基址原始内存 |
| ZipSaver | pZipFile | 0x0 | minizip zipOpen 句柄; 不透明 |

### 跳过类别

- vtable: `pVtable` / `pVptr`
- vector 三件套: `pVec*` / `*_begin` / `*_end` / `*_cap`
- rb-tree/list 节点: `*_parent` / `*_left` / `*_right` / `*_next` / `*_prev` / `pMap*` / `pList*`
- pad/unknown: `pPad_*` / `pField_*` / `pUnknown*` / `pUNKNOWN*`

### missing (不纠正)

- cSoundProjectManager
- GameService
- SystemService
- PlayerId
- AchievementId
- BugReporter
- FileManager
- KleiFile
- tUpdateJobThread
- tRenderJobThread
- cSingleton
- FrameProfilerSection
- MemoryManager
- BasePool
- sPerPlayerSleepCheckPred
- sNetworkSleepCheckPred
- sClientSleepCheckPred
- sOfflineSleepCheckPred
- sServerSleepCheckPred
- sRayCastPred
- sComponentPred
- SetBloomEnabledEvent
- SetDistortionEnabledEvent
- SetFullScreenEvent
- TwitchChatStatusUpdateEvent
- TwitchLoginAttemptEvent
- TwitchMessageReceivedEvent
- SystemEvent
- SteamWorkshop
- cFactory
