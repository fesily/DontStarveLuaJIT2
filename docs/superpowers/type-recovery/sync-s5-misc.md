# Phase 0 sync — S5 misc/system struct layouts

> program: `dontstarve_steam` (macOS i386)
> source: ghidra-mcp get_struct_layout (read-only)
> shard: S5 系统/杂项
> generated: 2026-08-10

## Summary

- processed: 88
- exists: 57 (real layout, Size > 1)
- missing: 31 (not found OR Size=1 placeholder OR non-structure)
- report: docs/superpowers/type-recovery/sync-s5-misc.md

## Layouts

### cApplication
size: 16 (hex 0x10)
exists: true
layout:
       0 |    4 | void *               | pMSystemService
       4 |    4 | void *               | pMGameService
       8 |    4 | void *               | pMGame
      12 |    4 | byte[4]              | pMCommandLine

### cLogger
size: 4184 (hex 0x1058)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 | 4180 | cLoggerImplementation | impl

### cLoggerImplementation
size: 4180 (hex 0x1054)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | int                  | nField_0x04
       8 |    4 | byte[4]              | pM_strLogFile
      16 |   56 | Mutex                | criticalSection
      72 |    4 | int                  | nField_0x48
      76 |    4 | int                  | nField_0x4C
      80 | 4088 | byte[4088]           | pUNKNOWN_0x50
    4172 |    4 | int                  | nField_0x104C
    4176 |    4 | int                  | nStartTime

### cInventoryManager
size: 1096 (hex 0x448)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | int                  | nField_0x04
       8 |    4 | void *               | pList_0x08_next
      12 |    4 | void *               | pList_0x08_prev
      16 |    4 | int                  | nMap1_pad
      20 |    4 | int                  | nMap1_color
      24 |    4 | void *               | pMap1_parent
      28 |    4 | void *               | pMap1_left
      32 |    4 | void *               | pMap1_right
      36 |    4 | int                  | nMap2_pad
      40 |    4 | int                  | nMap2_color
      44 |    4 | void *               | pMap2_parent
      48 |    4 | void *               | pMap2_left
      52 |    4 | void *               | pMap2_right
      64 |    4 | byte[4]              | pM_strRestricted
      68 |    4 | byte[4]              | pM_str_0x44
      72 | 1024 | byte[1024]           | pUNKNOWN_0x48

### cSoundSystem
size: 56 (hex 0x38)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | int                  | nMap1_pad
       8 |    4 | int                  | nMap1_color
      12 |    4 | void *               | pMap1_parent
      16 |    4 | void *               | pMap1_left
      20 |    4 | void *               | pMap1_right
      24 |    4 | int                  | nMap1_count
      28 |    4 | int                  | nMap2_pad
      32 |    4 | int                  | nMap2_color
      36 |    4 | void *               | pMap2_parent
      40 |    4 | void *               | pMap2_left
      44 |    4 | void *               | pMap2_right
      48 |    4 | int                  | nMap2_count
      52 |    1 | byte                 | bField_0x34
      53 |    3 | byte[3]              | p_pad

### cSoundProjectManager
size: n/a
exists: false

### cBPWorld
size: 52 (hex 0x34)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | void *               | pBroadphase
       8 |    4 | void *               | pConfig
      12 |    4 | void *               | pDispatcher
      16 |    4 | void *               | pSolver
      20 |    4 | void *               | pWorld
      24 |    4 | void *               | pGroundShape
      28 |    4 | void *               | pGroundBody
      32 |   12 | byte[12]             | pUNKNOWN_0x20
      48 |    4 | void *               | pSimulation

### cSimTime
size: 12 (hex 0xc)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | uint                 | dwTick
       8 |    4 | float                | flRemainder

### cDedicatedServerProcess
size: 56 (hex 0x38)
exists: true
layout:
       0 |   32 | Process              | base
      32 |    4 | int                  | nField_0x20
      36 |    1 | bool                 | fField_0x24
      40 |    4 | byte[4]              | pM_str
      44 |   12 | byte[12]             | pVecSignalHandlers

### GameLibConfig
size: 148 (hex 0x94)
exists: true
layout:
       0 |   68 | byte[68]             | pField_0x00
      68 |   32 | byte[32]             | pStrs
     100 |   48 | byte[48]             | pNetIds

### GameService
size: n/a
exists: false

### DontStarveGameService
size: 36 (hex 0x24)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | void *               | pSystemService
       8 |    4 | int                  | nField_0x08
      12 |    4 | int                  | nField_0x0C
      16 |   20 | byte[20]             | pM_achievements

### GameServiceImpl
size: 306 (hex 0x132)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | int                  | nField_0x04
       8 |    4 | int                  | nField_0x08
      12 |  294 | byte[294]            | pPlayerInfo

### SystemService
size: n/a
exists: false

### DontStarveSystemService
size: 164 (hex 0xa4)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | int                  | nField_0x04
       8 |    4 | int                  | nField_0x08
      12 |    4 | void *               | pCacheMap
      16 |   36 | byte[36]             | pM_playerId
      52 |    4 | byte[4]              | pFlags_0x34
      56 |    4 | int                  | nField_0x38
      60 |    4 | int                  | nField_0x3C
      64 |   84 | byte[84]             | pCallbacks
     148 |   16 | int[4]               | pLuaRefs

### GameService_PlayerInfo
size: 294 (hex 0x126)
exists: true
layout:
       0 |   36 | GameService_PlayerId | playerId
      36 |   64 | byte[64]             | pM_strName
     164 |   64 | byte[64]             | pM_strDisplayName
     228 |    1 | byte                 | bIsSignedIn
     229 |    1 | byte                 | bIsOnline
     230 |   64 | byte[64]             | p_pad

### PlayerId
size: 1 (hex 0x1)
exists: false

### AchievementId
size: 1 (hex 0x1)
exists: false

### BugReporter
size: n/a
exists: false

### CABody
size: 48 (hex 0x30)
exists: true
layout:
       0 |   16 | byte[16]             | pBounds
      16 |   32 | byte[32]             | pTileGrid

### HttpClient2
size: 4 (hex 0x4)
exists: true
layout:
       0 |    4 | void *               | pCurlRequestManager

### FileManager
size: 1 (hex 0x1)
exists: false

### KleiFile
size: 1 (hex 0x1)
exists: false

### FileSystem
size: 269 (hex 0x10d)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    8 | byte[8]              | pM_strMountName
      12 |  256 | char[256]            | pM_szMountPath
     268 |    1 | byte                 | bMounted

### LocalFileSystem
size: 276 (hex 0x114)
exists: true
layout:
       0 |  269 | FileSystem           | base
     272 |    4 | byte[4]              | pM_strRoot

### ZipFileSystem
size: 276 (hex 0x114)
exists: true
layout:
       0 |  269 | FileSystem           | base
     272 |    4 | void *               | pZipArchive

### MemoryCache
size: 24 (hex 0x18)
exists: true
layout:
       0 |    4 | int                  | nM_cache_pad
       4 |    4 | int                  | nM_cache_color
       8 |    4 | void *               | pM_cache_parent
      12 |    4 | void *               | pM_cache_left
      16 |    4 | void *               | pM_cache_right
      20 |    4 | int                  | nM_cache_count

### BinaryBufferReader
size: 16 (hex 0x10)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | int                  | nOffset
       8 |    4 | void *               | pBuffer
      12 |    4 | uint                 | dwBufferLength

### BinaryBufferWriter
size: 12 (hex 0xc)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | void *               | pBuffer
       8 |    4 | uint                 | dwOffset

### GrowableBinaryBufferWriter
size: 8 (hex 0x8)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | void *               | pVec

### EndianSwappedBinaryBufferReader
size: 16 (hex 0x10)
exists: true
layout:
       0 |   16 | BinaryBufferReader   | base

### GrowableEndianSwappedBinaryBufferWriter
size: 8 (hex 0x8)
exists: true
layout:
       0 |    8 | GrowableBinaryBufferWriter | base

### FileHandle
size: 344 (hex 0x158)
exists: true
layout:
       0 |    4 | int                  | nMOp
       4 |    4 | int                  | nMStatus
       8 |    4 | int                  | nMNumRefs
      12 |  256 | char[256]            | pM_path
     268 |    8 | byte[8]              | pM_pathHash
     276 |    4 | int                  | nMMode
     280 |    4 | int                  | nField_0x118
     284 |    4 | int                  | nM_nSize
     288 |    4 | int                  | nM_nBytesRead
     292 |    4 | void *               | pM_pData
     296 |    4 | int                  | nField_0x128
     300 |    4 | int                  | nField_0x12C
     304 |    4 | int                  | nField_0x130
     308 |    4 | int                  | nField_0x134
     312 |   12 | byte[12]             | pMResultHandler
     324 |    4 | int                  | nField_0x144
     328 |    4 | int                  | nField_0x148
     332 |    4 | int                  | nField_0x14C
     336 |    1 | byte                 | bHasData
     340 |    4 | Semaphore            | semaphore

### FileOpRequest
size: 324 (hex 0x144)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |   12 | byte[12]             | pM_callback
      16 |    4 | void *               | pContext
      20 |    4 | int                  | nRequestType
      24 |   36 | GameService_PlayerId | playerId
      60 |  256 | char[256]            | pFilename
     316 |    4 | uint                 | dwDataLen
     320 |    4 | void *               | pData

### FileOpResult
size: 328 (hex 0x148)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |   12 | byte[12]             | pM_callback
      16 |    4 | void *               | pContext
      20 |    4 | int                  | nRequestType
      24 |    4 | int                  | nEStatus
      28 |   36 | GameService_PlayerId | playerId
      64 |  256 | char[256]            | pData
     320 |    4 | int                  | nField_0x140
     324 |    4 | int                  | nField_0x144

### Timer
size: 8 (hex 0x8)
exists: true
layout:
       0 |    4 | uint                 | dwStartTick
       4 |    4 | uint                 | dwStartTickHi

### Mutex
size: 56 (hex 0x38)
exists: true
layout:
       0 |    4 | int                  | n__sig
       4 |   40 | byte[40]             | p__opaque
      44 |    4 | int                  | nAttr_sig
      48 |    8 | byte[8]              | pAttr_opaque

### Semaphore
size: 4 (hex 0x4)
exists: true
layout:
       0 |    4 | void *               | pSem

### Thread
size: 248 (hex 0xf8)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    1 | byte                 | bRunning
       8 |    4 | uint                 | dwPriority
      12 |    4 | uint                 | dwStackSize
      16 |   56 | Mutex                | mMutex
      72 |    4 | void *               | pThread
      76 |   40 | byte[40]             | pMAttr
     116 |    4 | byte[4]              | pM_strName
     120 |  128 | byte[128]            | pUNKNOWN_0x78

### tUpdateJobThread
size: 1 (hex 0x1)
exists: false

### tRenderJobThread
size: 1 (hex 0x1)
exists: false

### SimThread
size: 140 (hex 0x8c)
exists: true
layout:
       0 |  120 | byte[120]            | pBaseThread
     120 |    4 | void *               | pLuaState
     124 |    4 | void *               | pSimulation
     128 |    1 | byte                 | bSuccess
     129 |    1 | byte                 | bPad_81
     130 |    1 | byte                 | bPad_82
     131 |    1 | byte                 | bPad_83
     132 |    4 | void *               | pStrResult
     136 |    4 | int                  | nRefTraceback

### TwitchAuthThread
size: 193 (hex 0xc1)
exists: true
layout:
       0 |  120 | byte[120]            | pThread
     120 |    4 | int                  | nField_0x78
     124 |    4 | int                  | nField_0x7C
     128 |    4 | int                  | nField_0x80
     152 |    4 | int                  | nField_0x98
     160 |    4 | byte[4]              | pStr_0xA0
     164 |    4 | byte[4]              | pStr_0xA4
     168 |   25 | Socket               | m_socket

### cSingleton
size: n/a
exists: false

### FrameProfiler
size: 36 (hex 0x24)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | uint                 | dwThreadID
       8 |    8 | Timer                | m_Timer
      16 |    1 | byte                 | bRecording
      20 |    4 | uint                 | dwProfileCount
      24 |    4 | int                  | nFileIndex
      28 |    4 | float                | flSpinTime
      32 |    4 | uint                 | dwSpinCount

### FrameProfilerSection
size: 1 (hex 0x1)
exists: false

### PerfIndicator
size: 1048 (hex 0x418)
exists: true
layout:
       0 |    4 | void *               | pGame
       4 |    4 | byte[4]              | pM_strName
       8 | 1024 | float[256]           | pHistory
    1032 |    4 | int                  | nWriteIndex
    1036 |    4 | byte[4]              | pM_colour
    1040 |    4 | uint                 | dwUpdateCount
    1044 |    4 | uint                 | dwSampleDivisor

### PerfPane
size: 64 (hex 0x40)
exists: true
layout:
       0 |    4 | void *               | pVecIndicators_begin
       4 |    4 | void *               | pVecIndicators_end
       8 |    4 | void *               | pVecIndicators_cap
      12 |    4 | void *               | pVecGrids_begin
      16 |    4 | void *               | pVecGrids_end
      20 |    4 | void *               | pVecGrids_cap
      24 |    4 | void *               | pGame
      28 |    4 | float                | flPosX
      32 |    4 | float                | flPosY
      36 |    4 | float                | flSizeX
      40 |    4 | float                | flSizeY
      44 |   20 | byte[20]             | pUNKNOWN_0x2C

### Metrics
size: 52 (hex 0x34)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    1 | byte                 | bEnabled
       8 |    4 | byte[4]              | pM_strBranchA
      12 |    4 | byte[4]              | pM_strBranchB
      16 |    4 | byte[4]              | pM_strBranchC
      20 |   32 | byte[32]             | pM_Generator

### GoogleAnalyticsCookie
size: 24 (hex 0x18)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | byte[4]              | pM_strValue
       8 |    4 | byte[4]              | pM_strName
      12 |    4 | void *               | pM_args_begin
      16 |    4 | void *               | pM_args_end
      20 |    4 | void *               | pM_args_cap

### GoogleAnalyticsGenerator
size: 32 (hex 0x20)
exists: true
layout:
       0 |    4 | uint                 | dwField_0
       4 |    4 | byte[4]              | pM_strReportName
       8 |    4 | int                  | nM_settings_pad
      12 |    4 | int                  | nM_settings_color
      16 |    4 | void *               | pM_settings_parent
      20 |    4 | void *               | pM_settings_left
      24 |    4 | void *               | pM_settings_right
      28 |    4 | int                  | nM_settings_count

### Heap
size: 92 (hex 0x5c)
exists: true
layout:
       0 |    4 | uint                 | dwM_nHeapID
       4 |    4 | ulong                | dwM_nTotalSize
       8 |    4 | void *               | pBase
      12 |    4 | void *               | pFirstBlock
      16 |    4 | void *               | pLastBlock
      20 |    4 | uint                 | dwAllocatedCount
      24 |    4 | uint                 | dwFreeBlockCount
      28 |   56 | Mutex                | mMutex
      84 |    1 | byte                 | bNeedsCoalesce
      88 |    4 | uint                 | dwTotalFree

### MemoryManager
size: n/a
exists: false

### BasePool
size: n/a
exists: false

### cGiftingManager
size: 160 (hex 0xa0)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    4 | int                  | nField_0x04
       8 |    4 | void *               | pM_listA_next
      12 |    4 | void *               | pM_listA_prev
      16 |   56 | Mutex                | Mutex_1
      72 |   24 | byte[24]             | pM_giftItems
      96 |    4 | void *               | pM_unverifiedReceipts_next
     100 |    4 | void *               | pM_unverifiedReceipts_prev
     104 |   56 | Mutex                | Mutex_2

### PersistentStorage
size: 8 (hex 0x8)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    1 | byte                 | bFlag
       5 |    3 | byte[3]              | p_pad

### ZipSaver
size: 4 (hex 0x4)
exists: true
layout:
       0 |    4 | void *               | pZipFile

### sPerPlayerSleepCheckPred
size: 1 (hex 0x1)
exists: false

### sNetworkSleepCheckPred
size: 1 (hex 0x1)
exists: false

### sClientSleepCheckPred
size: 1 (hex 0x1)
exists: false

### sOfflineSleepCheckPred
size: 1 (hex 0x1)
exists: false

### sServerSleepCheckPred
size: 1 (hex 0x1)
exists: false

### sRayCastPred
size: 1 (hex 0x1)
exists: false

### sComponentPred
size: n/a
exists: false

### cPlayerSaveLocation
size: 24 (hex 0x18)
exists: true
layout:
       0 |   24 | byte[24]             | pMap

### cGameEvent
size: 8 (hex 0x8)
exists: true
layout:
       0 |    4 | void *               | pVptr
       4 |    4 | int                  | nType

### cInputKeyEvent
size: 16 (hex 0x10)
exists: true
layout:
       0 |    4 | void *               | pVptr
       4 |    4 | int                  | nType
       8 |    4 | int                  | nKey
      12 |    1 | bool                 | fPressed
      13 |    3 | byte[3]              | p_pad

### cInputMouseButtonEvent
size: 24 (hex 0x18)
exists: true
layout:
       0 |    4 | void *               | pVptr
       4 |    4 | int                  | nType
       8 |    4 | int                  | nButton
      12 |    1 | bool                 | fPressed
      16 |    4 | float                | flX
      20 |    4 | float                | flY

### cInputMouseMoveEvent
size: 16 (hex 0x10)
exists: true
layout:
       0 |    4 | void *               | pVptr
       4 |    4 | int                  | nType
       8 |    4 | int                  | nX
      12 |    4 | int                  | nY

### cInputGestureEvent
size: 12 (hex 0xc)
exists: true
layout:
       0 |    4 | void *               | pVptr
       4 |    4 | int                  | nType
       8 |    4 | int                  | nEGesture

### cInputTextEvent
size: 12 (hex 0xc)
exists: true
layout:
       0 |    4 | void *               | pVptr
       4 |    4 | int                  | nType
       8 |    4 | byte[4]              | pSText

### cTogglePauseEvent
size: 12 (hex 0xc)
exists: true
layout:
       0 |    4 | void *               | pVptr
       4 |    4 | int                  | nType
       8 |    1 | bool                 | fPaused
       9 |    3 | byte[3]              | p_pad

### cFocusGainedEvent
size: 8 (hex 0x8)
exists: true
layout:
       0 |    4 | void *               | pVptr
       4 |    4 | int                  | nType

### cFocusLostEvent
size: 8 (hex 0x8)
exists: true
layout:
       0 |    4 | void *               | pVptr
       4 |    4 | int                  | nType

### WindowMoveEvent
size: 16 (hex 0x10)
exists: true
layout:
       0 |    4 | void *               | pVptr
       4 |    4 | int                  | nType
       8 |    4 | int                  | nX
      12 |    4 | int                  | nY

### ResizeEvent
size: 16 (hex 0x10)
exists: true
layout:
       0 |    4 | void *               | pVptr
       4 |    4 | int                  | nType
       8 |    4 | int                  | nWidth
      12 |    4 | int                  | nHeight

### SetBloomEnabledEvent
size: 1 (hex 0x1)
exists: false

### SetDistortionEnabledEvent
size: 1 (hex 0x1)
exists: false

### SetFullScreenEvent
size: 1 (hex 0x1)
exists: false

### TwitchChatStatusUpdateEvent
size: 1 (hex 0x1)
exists: false

### TwitchLoginAttemptEvent
size: 1 (hex 0x1)
exists: false

### TwitchMessageReceivedEvent
size: 1 (hex 0x1)
exists: false

### SystemEvent
size: 1 (hex 0x1)
exists: false

### cMasterServerRequest
size: 16 (hex 0x10)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |    1 | byte                 | bField_0x04
       8 |    4 | byte[4]              | pM_strURL
      12 |    4 | void *               | pMasterServer

### cSteamRichPresence
size: 83 (hex 0x53)
exists: true
layout:
       0 |    4 | void *               | pVtable
       4 |   24 | byte[24]             | pM_presence
      28 |    1 | byte                 | bField_0x1C
      32 |   44 | cNetID2              | m_serverNetId
      76 |    4 | byte[4]              | pM_connectString
      82 |    1 | byte                 | bField_0x52

### SteamWorkshop
size: 1 (hex 0x1)
exists: false

### SteamWorkshop
size: 1 (hex 0x1)
exists: false

### cFactory
size: n/a
exists: false

## Notes / aliases (not in S5 list as primary names)

### SoundProjectManager (alias for cSoundProjectManager)
size: 64 (hex 0x40)
exists: true
layout:
     0 |    4 | void *               | pVtable
     4 |   56 | byte[56]             | pBase
    60 |    4 | void *               | pSoundSystem

### GameService_PlayerId (related; used by GameService_PlayerInfo / FileOp*)
size: 36 (hex 0x24)
exists: true
layout:
     0 |   36 | uint[9]              | pM_data

### Search notes
- GameService / SystemService: only nested demangler placeholders; no root Structure (pure interfaces).
- cSoundProjectManager: not found; use SoundProjectManager (64B).
- PlayerId / AchievementId: Size=1 demangler placeholders under GameService namespace (real data is GameService_PlayerId / GameService_AchievementId 36B).
- BugReporter / MemoryManager / BasePool / cSingleton / cFactory: not found as Structure.
- sComponentPred: datatype exists but is not a Structure ("Data type is not a structure").
- SteamWorkshop listed twice in S5 inventory; both Size=1 placeholders.
- GameServiceImpl Ghidra size is 306 (0x132); prior analysis noted new(0x134)=308 — possible 2B trailing pad mismatch.
- FileSystem 269B with LocalFileSystem/ZipFileSystem at 276B (padding to 4-byte align for derived field at 272).
