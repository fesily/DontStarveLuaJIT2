# Don't Starve Engine — Ghidra Struct Analysis Knowledge Base

> Generated from reverse engineering sessions on `dontstarve_steam` (macOS 32-bit DS with full symbols).
> Active Ghidra program: `dontstarve_steam`

## Table of Contents
- [Platform-Specific Notes](#platform-specific-notes)
- [Tool Workarounds](#tool-workarounds)
- [Inheritance Hierarchy](#inheritance-hierarchy)
- [Structs Created in Ghidra](#structs-created-in-ghidra)
  - [cEntity (252 bytes)](#centity-252-bytes)
  - [cEntityManager (309 bytes)](#centitymanager-309-bytes)
  - [sComponentList (36 bytes)](#scomponentlist-36-bytes)
  - [cGame (304 bytes / 0x130)](#cgame-304-bytes--0x130)
  - [cDontStarveGame (316 bytes / 0x13C)](#cdontstarvegame-316-bytes--0x13c)
  - [cSimulation (412 bytes / 0x19C)](#csimulation-412-bytes--0x19c)
  - [cDontStarveSim (1148 bytes / 0x47C)](#cdontstarvesim-1148-bytes--0x47c)
  - [WorldSim (16 bytes / 0x10)](#worldsim-16-bytes--0x10)
  - [SimThread (140 bytes / 0x8C)](#simthread-140-bytes--0x8c)
  - [WorldSimActual (36 bytes / 0x24)](#worldsimactual-36-bytes--0x24)
  - [cNetworkManager (5048 bytes / 0x13B8)](#cnetworkmanager-5048-bytes--0x13b8)
  - [cNetworkComponent (684 bytes / 0x2AC)](#cnetworkcomponent-684-bytes--0x2ac)
  - [cTransformComponent (380 bytes / 0x17C)](#ctransformcomponent-380-bytes--0x17c)
  - [cTransformationHistory (24 bytes / 0x18)](#ctransformationhistory-24-bytes--0x18)
  - [cTransformationHistoryCell (20 bytes / 0x14)](#ctransformationhistorycell-20-bytes--0x14)
  - [cAnimStateComponent (208 bytes / 0xD0)](#canimstatecomponent-208-bytes--0xd0)
  - [cPhysicsComponent (108 bytes / 0x6C)](#cphysicscomponent-108-bytes--0x6c)
  - [GroundCreepEntity (24 bytes / 0x18)](#groundcreepentity-24-bytes--0x18)
  - [GroundCreep (213 bytes / 0xD5)](#groundcreep-213-bytes--0xd5)
  - [TileGrid (28 bytes / 0x1C)](#tilegrid-28-bytes--0x1c)
- [EntityLuaProxy Methods](#entityluaproxy-methods)
- [Key Addresses](#key-addresses)
- [Registered Component Types](#registered-component-types)
- [Unknowns & Remaining Work](#unknowns--remaining-work)

---

## Platform-Specific Notes

- **macOS 32-bit**: `std::string` = **4 bytes** (COW/libstdc++ ABI, single pointer to `_Rep` structure). NOT 12 bytes (SSO).
- **PIC code**: Global data access uses `[REG + 0x43xxxx]` pattern; REG loaded via `CALL next; POP REG`.
- **cEventListener\<T\>** base class = **0x1C bytes** (28 bytes): vtable(4) + `_Rb_tree` (comparator padding + color + parent + left + right + count).
- **Mutex** = **0x38 bytes** (56 bytes): `pthread_mutex_t` (44 bytes @ 0x00) + `pthread_mutexattr_t` (12 bytes @ 0x2C).
- **Timer** = **8 bytes**.

---

## Tool Workarounds

These Ghidra MCP tool issues were discovered during analysis:

| Tool | Issue | Workaround |
|------|-------|------------|
| `get_struct_layout` | Always returns error | Use `search_data_types` or `force_decompile` to verify |
| `decompile_function(address=...)` | Returns "Function address is required" | Use `force_decompile(address=...)` instead |
| `decompile_function(name=...)` | Broken for namespaced names like `cGame::Update` | Use address-based decompilation |
| `batch_decompile` | Fails with addresses | Decompile one at a time with `force_decompile` |
| `search_functions_enhanced` | Doesn't find namespace member functions | Use inline Ghidra script with `getChildren(ns.getSymbol())` |
| `get_valid_data_types` | Pydantic error | Skip, use `search_data_types` |
| Byte pattern `[REG+offset]` | Matches ANY register, not just `this` | Must verify via decompilation/disassembly which register holds `this` |

### Inline Script for Namespace Function Enumeration

```java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
public class ListNS extends GhidraScript {
    @Override public void run() throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        // Try NAMESPACE first, then CLASS
        SymbolIterator it = st.getSymbols("cGame"); // change name
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getSymbolType() == SymbolType.NAMESPACE || s.getSymbolType() == SymbolType.CLASS) {
                for (Symbol child : st.getChildren(s)) {
                    if (child.getSymbolType() == SymbolType.FUNCTION) {
                        println(child.getAddress() + " " + child.getName());
                    }
                }
            }
        }
    }
}
```

### Standard Workflow: Struct Analysis + Ghidra Writing

Every struct analysis session follows this sequence:

1. **函数枚举**: 用 inline Ghidra script 枚举命名空间下所有函数（地址 + 名称）
2. **反编译分析**: 对构造函数、析构函数、Serialize/Deserialize 等关键函数调用 `force_decompile(address=...)` 逐字段推导
3. **Struct 建立**: 确认完整 layout 后调用 `create_struct` 写入 Ghidra（注意：base class 字段用 `byte[N]` 替代，不展开；base class 内部偏移字段不重复列出）
4. **函数注释**: 对所有成员函数通过 inline script 批量写入 `PLATE_COMMENT`（逐字段行为摘要），关键函数同时做变量重命名
5. **保存**: 调用 `save_program` 持久化
6. **记忆文件**: 在 `docs/ghidra-struct-analysis.md` 的 TOC 和对应章节写入完整 struct layout 和函数行为摘要

**关键注意事项**:
- `set_plate_comment(function_address=...)` 对文件偏移地址直接有效（macOS binary base=0x1000）
- `batch_set_comments` 的 plate_comment 字段无效，必须用 inline script 或 `set_plate_comment`
- Struct 大小验证：`search_data_types(pattern="StructName")` 中 `/StructName` 路径下的 size 即实际大小
- Demangler 生成的同名 size=1 类型不影响自建 struct（路径不同）

---

## Inheritance Hierarchy

```
cEntityComponent (16 bytes)
├── cSerializableEntityComponent (same 16 bytes, overrides GetSerializable→this)
│   ├── + cTransformProvider (vtable-only interface @0x10)
│   │   └── cTransformComponent (380 bytes)
│   ├── + cBBoxProvider (vtable-only interface @0x10)
│   │   └── cAnimStateComponent (208 bytes)
│   └── (other serializable components...)
├── + RakNet::Replica3 (344 bytes @0x10)
│   └── cNetworkComponent (684 bytes)
└── (non-serializable components: cImageWidget, cTextWidget, etc.)

cEventListener<SystemEvent> (0x1C bytes)
└── cGame (0x130 = 304 bytes)
    └── cDontStarveGame (0x13C = 316 bytes)

cEventListener<cGameEvent> + cEventListener<SystemEvent> (dual base)
└── cSimulation (0x19C = 412 bytes)
    └── cDontStarveSim (0x47C = 1148 bytes)
```

### cTransformProvider Interface (vtable-only, at cTransformComponent+0x10)
| Slot | Method |
|------|--------|
| [0-1] | Destructors (adjustor thunks) |
| [2] | GetLocalTransform() → Matrix4* |
| [3] | GetLocalTransformInverse() → Matrix4* |
| [4] | GetWorldTransform() → Matrix4* |
| [5] | GetWorldTransformInverse() → Matrix4* |
| [6] | GetMaxScale() → float |
| [7] | GetLocalPosition() → vec3* |
| [8] | GetWorldPosition() → vec3* |
| [9] | IsInHud() → bool |
| [10] | IsInWorld() → bool |

### cBBoxProvider Interface (vtable-only, at cAnimStateComponent+0x10)
| Slot | Method |
|------|--------|
| [0-1] | Destructors (adjustor thunks) |
| [2] | RayTest(bool, Vector2*, Vector3*) |
| [3] | GetLocalBBox() |
| [4] | GetCullRadius() |

---

## Structs Created in Ghidra

### cEntity (252 bytes)
ALL fields named. Created in earlier sessions.

### cEntityManager (309 bytes)
ALL fields named. Created in earlier sessions.

### sComponentList (36 bytes)
9 fields. Created in earlier sessions.

---

### cGame (304 bytes / 0x130)

Constructor: 0xf3d2 | Destructor: 0x10e30 | Vtable: 0x4549a8 (9 virtual slots, 6-8 pure virtual)

Inherits `cEventListener<SystemEvent>` (0x1C bytes base).

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | ptr | vtable | |
| 0x04 | 4 | ptr | baseEventListenerVtable | cEventListener<SystemEvent> |
| 0x08 | 20 | obj | rbTree | _Rb_tree (comparator+header+count) |
| 0x1C | 4 | int | nPauseState | init=3 |
| 0x20 | 4 | ptr | pSimulation | cSimulation* |
| 0x24 | 1 | bool | field_0x24 | |
| 0x25-0x27 | 3 | pad | | |
| 0x28 | 4 | ptr | pWindowManager | WindowManager* |
| 0x2C | 4 | ptr | pPostProcessor | PostProcessor* |
| 0x30 | 4 | ptr | pRenderer | GameRenderer* |
| 0x34 | 4 | ptr | pVFXEmitterManager | VFXEmitterManager*, alloc 0x1004 |
| 0x38 | 4 | ptr | pQuadTreeNode | |
| 0x3C | 4 | ptr | pSceneGraphNode | |
| 0x40 | 4 | ptr | pInputManager | IInputManager* |
| 0x44 | 4 | ptr | pAnimManager | AnimManager*, alloc 0x74 |
| 0x48 | 4 | ptr | pFileManager | FileManager*, cResourceManager<char>, alloc 0x3C |
| 0x4C | 4 | ptr | pAtlasManager | AtlasManager*, alloc 0x40 |
| 0x50 | 4 | ptr | pSoundProjectManager | SoundProjectManager*, cResourceManager<FMOD::EventProject*>, alloc 0x40 |
| 0x54 | 4 | ptr | pEnvelopeManager | EnvelopeManager* |
| 0x58 | 4 | ptr | pMOTDImageLoader | MOTDImageLoader* |
| 0x5C | 4 | ? | field_0x5C | init=0, UNKNOWN — only zeroed in ctor, never accessed by any of 64 member functions |
| 0x60 | 4 | ptr | pGameEventDispatcher | cEventDispatcher<cGameEvent>* |
| 0x64 | 4 | ptr | pSoundSystem | cSoundSystem* |
| 0x68 | 4 | str | strUnknown68 | std::string (4-byte COW ptr) |
| 0x6C | 1 | bool | bRestarting | HandleRestart→0, Restart→1, Update checks |
| 0x6D | 1 | bool | bShutdownRequested | HandleEvent sets to 1 (event 0xB) |
| 0x6E | 1 | ? | field_0x6E | init=0, UNKNOWN |
| 0x6F | 1 | pad | | |
| 0x70 | 4 | uint | dwCurrentTimeMS | Update: RakNet::GetTimeMS() |
| 0x74 | 4 | float | fRenderTime | DrawCacheRender |
| 0x78 | 4 | ? | field_0x78 | init=0, UNKNOWN |
| 0x7C | 1 | bool | bInitializedOnMainThread | |
| 0x7D-0x7F | 3 | pad | | |
| 0x80 | 4 | ptr | vecPrefabs_begin | std::vector<cPrefab*> |
| 0x84 | 4 | ptr | vecPrefabs_end | |
| 0x88 | 4 | ptr | vecPrefabs_capacity | |
| 0x8C | 1 | bool | bDebugRender | |
| 0x8D | 1 | bool | bDebugCamera | ToggleDebugCamera: XOR toggle |
| 0x8E | 1 | bool | bPlaying | init=1 |
| 0x8F | 1 | pad | | |
| 0x90 | 4 | int | field_0x90 | init=-1, UNKNOWN |
| 0x94 | 4 | str | strInstanceSettings | std::string |
| 0x98 | 4 | uint | hTexture | init=0xFFFFFFFF |
| 0x9C | 4 | uint | hRenderBufferA | init=0xFFFFFFFF |
| 0xA0 | 4 | uint | hRenderBufferB | init=0xFFFFFFFF |
| 0xA4 | 4 | ptr | pRenderTargetA | LightBuffer* |
| 0xA8 | 4 | ptr | pRenderTargetB | |
| 0xAC | 4 | ptr | pPersistentStorage | PersistentStorage* |
| 0xB0 | 4 | ptr | pSystemService | DontStarveSystemService* — set in cApplication::Startup |
| 0xB4 | 4 | ptr | pGameService | DontStarveGameService* |
| 0xB8 | 4 | int | nEnvelopeColour | envelope index |
| 0xBC | 4 | int | nEnvelopeVector2 | envelope index |
| 0xC0 | 4 | uint | hRenderTarget | init=0xFFFFFFFF |
| 0xC4 | 4 | str | strPurchases | std::string |
| 0xC8 | 4 | float | fInputScale | |
| 0xCC | 1 | bool | bNetbookMode | |
| 0xCD-0xCF | 3 | pad | | |
| 0xD0 | 4 | float | fInputScaleDefault | |
| 0xD4 | 4 | int | field_0xD4 | from cApplication+0x0C, UNKNOWN purpose |
| 0xD8 | 1 | bool | bPerfIndicatorsInitialized | |
| 0xD9-0xDB | 3 | pad | | |
| 0xDC | 4 | ptr | pPerfSimTime | PerfIndicator* "simtime" Red |
| 0xE0 | 4 | ptr | pPerfLuaTime | "LuaTime" Blue |
| 0xE4 | 4 | ptr | pPerfPhysicsTime | "PhysicsTime" Violet |
| 0xE8 | 4 | ptr | pPerfRenderTime | "RenderTime" Green |
| 0xEC | 4 | ptr | pPerfFPSAvg | "FPSAvg" Cyan |
| 0xF0 | 4 | ptr | pPerfPing | "Ping" Red (displayMode=3) |
| 0xF4 | 4 | ptr | pPerfLUAAvg | "LUAAvg" Blue |
| 0xF8 | 4 | ptr | pPerfSimAvg | "SimAvg" Red |
| 0xFC | 4 | ptr | pPerfPhysicsAvg | "PhysicsAvg" Violet |
| 0x100 | 4 | ptr | pPerfRenderAvg | "RenderAvg" Green |
| 0x104 | 4 | ptr | pPerfPushed | "Pushed" Red |
| 0x108 | 4 | ptr | pPerfSent | "Sent" Blue |
| 0x10C | 4 | ptr | pPerfResent | "Resent" Green |
| 0x110 | 4 | ptr | pPerfProcessed | "Processed" Purple |
| 0x114 | 4 | ptr | pPerfActualSent | "ActualSent" Cyan |
| 0x118 | 4 | ptr | pPerfPaneAvgTime | PerfPane* (0.05,0.05) |
| 0x11C | 4 | ptr | pPerfPaneInstTime | PerfPane* (0.55,0.05) |
| 0x120 | 4 | ptr | pPerfPaneNetwork | PerfPane* (0.05,0.55) |
| 0x124 | 4 | ptr | pPerfPanePing | PerfPane* (0.55,0.55) |
| 0x128 | 4 | ptr | pSystemEventDispatcher | cEventDispatcher<SystemEvent>* |
| 0x12C | 4 | float | fSmoothFPS | DrawCacheRender: average of 120 samples |

**54 namespace functions**, all decompiled. Key: ctor 0xf3d2, dtor 0x10e30, InitPerfIndicators 0xfc54, Update 0x1345e, DrawCacheRender 0x1212e.

**Unknown fields**: 0x5C, 0x6E, 0x78, 0x90 — confirmed unused by all 64 cGame/cDontStarveGame member functions.

---

### cDontStarveGame (316 bytes / 0x13C)

Extends cGame. Constructor: 0xc2be | Destructor: 0xc38c | Vtable: 0x454928 (9 slots)

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 304 | obj | base_cGame | cGame base |
| 0x130 | 4 | ptr | pBootScreen | cBootScreen*, inherits cUIScreen, size=0x10 |
| 0x134 | 4 | ptr | pGameScreen | cGameScreen*, created in DoGameSpecificInitialize |
| 0x138 | 4 | ptr | pSoundFEV | FMOD::EventProject*, "sound/dontstarve.fev" |

Additional functions: CreateSim(0xc43e) → creates cDontStarveSim(0x47C), DoGameSpecificInitialize(0xc482), DoGameSpecificStartNewGame(0xc47c).

---

### cSimulation (412 bytes / 0x19C)

Constructor: 0xf71d2 | Destructor: 0xf787c

Dual EventListener inheritance:
- cEventListener<cGameEvent> at 0x00 (0x1C bytes)
- cEventListener<SystemEvent> at 0x1C (0x1C bytes)

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 0x1C | base | cEventListener<cGameEvent> | |
| 0x1C | 0x1C | base | cEventListener<SystemEvent> | |
| 0x38 | 1 | bool | bPostUpdateTriggered | sync flag for render thread |
| 0x39-0x3B | 3 | pad | | |
| 0x3C | 4 | float | fTimeScale | init=1.0, set to 0 on error |
| 0x40 | 4 | ptr | pEntityManager | cEntityManager*, alloc 0x138 |
| 0x44 | 4 | int | nSimStep | incremented every sim step |
| 0x48 | 0x0C | obj | simTime | cSimTime: vtable(4)+nTick(4)+fRemainder(4) |
| 0x54 | 1 | bool | bPhysicsDebugRender | |
| 0x55-0x57 | 3 | pad | | |
| 0x58 | 4 | ptr | pLuaState | lua_State* |
| 0x5C | 4 | ptr | pGame | cGame* |
| 0x60 | 4 | ptr | pWorldSim | WorldSim* |
| 0x64 | 4 | ptr | pMainCamera | cSimCamera* |
| 0x68 | 4 | str | strScenarioScript | std::string (4-byte COW) |
| 0x6C | 4 | float | fTimeStep | init=0.001f |
| 0x70 | 4 | ptr | pDebugCamera | cSimCamera* |
| 0x74 | 4 | int | field_0x74 | init=-1, UNKNOWN (sentinel?) |
| 0x78 | 4 | float | fElapsedUpdateTime | Timer::GetElapsedSeconds for entire Update |
| 0x7C | 4 | float | fPhysicsTime | accumulated physics time |
| 0x80 | 4 | float | fLuaTime | accumulated Lua time |
| 0x84 | 1 | bool | bLogAllocations | enables verbose Lua alloc logging |
| 0x85 | 1 | bool | bTrackAllocsEnabled | |
| 0x86 | 1 | bool | bTrackAllocsActive | |
| 0x87 | 1 | pad | | |
| 0x88 | 4 | ptr | vecQueuedSysEvents_begin | std::vector<QueuedSystemEvent> (4 bytes each) |
| 0x8C | 4 | ptr | vecQueuedSysEvents_end | |
| 0x90 | 4 | ptr | vecQueuedSysEvents_cap | |
| 0x94 | 0x38 | obj | mutexSysEvents | Mutex (56 bytes) |
| 0xCC | 4 | ptr | vecQueuedGameEvents_begin | std::vector<QueuedGameEvent> (0xC bytes each) |
| 0xD0 | 4 | ptr | vecQueuedGameEvents_end | |
| 0xD4 | 4 | ptr | vecQueuedGameEvents_cap | |
| 0xD8 | 0x38 | obj | mutexGameEvents | Mutex (56 bytes) |
| 0x110 | 0x18 | obj | mapHashedStringUint | std::map<cHashedString,uint> (24 bytes _Rb_tree) |
| 0x128 | 4 | int | refPushEntityEvent | lua_ref, init=LUA_NOREF(-2) |
| 0x12C | 4 | int | refRemoveEntity | |
| 0x130 | 4 | int | refUpdate | |
| 0x134 | 4 | int | refPostUpdate | |
| 0x138 | 4 | int | refWallUpdate | |
| 0x13C | 4 | int | refTraceback | _TRACEBACK |
| 0x140 | 4 | int | refOnInputKey | |
| 0x144 | 4 | int | refOnInputText | |
| 0x148 | 4 | int | refOnMouseButton | |
| 0x14C | 4 | int | refOnPhysicsCollision | |
| 0x150 | 4 | int | refOnGesture | |
| 0x154 | 4 | int | refOnFocusLost | |
| 0x158 | 4 | int | refOnFocusGained | |
| 0x15C | 4 | int | nStepsThisFrame | |
| 0x160 | 4 | bytes | rgbAmbientColor | R,G,B,A — brightness calc |
| 0x164 | 4 | bytes | rgbaColor2 | |
| 0x168 | 4 | str | strJsonSettings | std::string |
| 0x16C | 4 | str | strPurchases | std::string |
| 0x170 | 4 | ptr | pBPWorld | cBPWorld*, alloc 0x34 |
| 0x174 | 1 | bool | bAbortSim | |
| 0x175-0x177 | 3 | pad | | |
| 0x178 | 4 | float | fAccumulatedSimTime | |
| 0x17C | 4 | ptr | vecUnknown17C_begin | unused by all 87 member functions |
| 0x180 | 4 | ptr | vecUnknown17C_end | |
| 0x184 | 4 | ptr | vecUnknown17C_cap | |
| 0x188 | 4 | int | nGCThreshold | IncrementalGarbageCollect |
| 0x18C | 1 | bool | bSkipSim | |
| 0x18D-0x18F | 3 | pad | | |
| 0x190 | 4 | ptr | pPhysicsThread | Thread* |
| 0x194 | 1 | bool | bUseThreadedPhysics | |
| 0x195-0x197 | 3 | pad | | |
| 0x198 | 4 | float | fProfilerTime | |

**87 namespace functions**. Key: ctor 0xf71d2, dtor 0xf787c, Update 0xfbd60, Reset 0xfb33a, NewLuaState 0xf84e8.

**Unknown fields**: 0x74 (init=-1), 0x17C-0x184 (vector, never used by members).

---

### cDontStarveSim (1148 bytes / 0x47C)

Extends cSimulation. Constructor: 0x8b3c6 | Destructor: 0x8b93c

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x000 | 0x19C | obj | base_cSimulation | |
| 0x19C | 4 | ptr | pFreeCamera | cFreeCamera*, alloc 0x150 |
| 0x1A0 | 4 | float | fLastCameraRotation | |
| 0x1A4 | 0x2D0 | obj | inputHandler | DontStarveInputHandler (720 bytes, embedded) |
| 0x474 | 4 | ptr | pSystemService | DontStarveSystemService* |
| 0x478 | 4 | ptr | pGameService | DontStarveGameService* |

**14 namespace functions**. RegisterLuaComponents registers 39 component types.

**38 Component Types Registered**: cTransformComponent, cUITransformComponent, cSoundEmitterComponent, cAnimStateComponent, cPhysicsComponent, cNetworkComponent, cShardNetworkComponent, cShardClientComponent, cLightEmitterComponent, cImageWidget, cVideoWidget, cTextWidget, cTextEditWidget, cLightWatcherComponent, MapGenSim, MapComponent, ShadowManagerComponent, MiniMapComponent, PostProcessorComponent, FontComponent, WaveComponent, GraphicsOptionsComponent, TwitchComponent, AccountManagerComponent, cLabelComponent, cImageComponent, DynamicShadowComponent, MiniMapEntityComponent, VFXEffect, ParticleEmitter, EnvelopeComponent, FollowerComponent, DebugRenderComponent, GroundCreepEntity, RoadManagerComponent, MapLayerManagerComponent, GroundCreep, PathfinderComponent.

---

### WorldSim (16 bytes / 0x10)

Constructor: 0xd92d6 | Destructor: 0xd9360

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | ptr | pCallbackObj | FastDelegate field 1 |
| 0x04 | 4 | ptr | pCallbackFunc | FastDelegate field 2 |
| 0x08 | 4 | int | nCallbackAdjust | FastDelegate field 3 |
| 0x0C | 4 | ptr | pSimThread | SimThread*, heap-alloc 0x8C |

Run(0xd93b0), IsFinished(0xd93c6), ExecCallback(0xd93e2).

---

### SimThread (140 bytes / 0x8C)

Extends Thread (120 byte base). Constructor: 0xd98fa | Destructor: 0xda1fa

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 0x78 | obj | baseThread | Thread (120 bytes) |
| 0x78 | 4 | ptr | pLuaState | lua_State*, own VM for worldgen |
| 0x7C | 4 | ptr | pSimulation | cSimulation* |
| 0x80 | 1 | bool | bSuccess | 1=success, 0=error |
| 0x81-0x83 | 3 | pad | | |
| 0x84 | 4 | str | strResult | std::string (worldgen output or error) |
| 0x88 | 4 | int | refTraceback | lua_ref for _TRACEBACK |

Main(0xda2d6): runs `scripts/worldgen_main.lua`.

---

### WorldSimActual (36 bytes / 0x24)

Lunar<WorldSimActual> bound, 49 Lua-callable functions.

| Offset | Size | Type | Name |
|--------|------|------|------|
| 0x00 | 4 | ptr | lunarBase |
| 0x04 | 4 | ptr | pBoostMap (8 bytes) |
| 0x08 | 4 | ptr | pTileGrid |
| 0x0C | 24 | obj | lunarMetadata |

---

### cNetworkManager (5048 bytes / 0x13B8)

Singleton at `PTR_mInstance_00450930`. Constructor: 0x165992 | Destructor: 0x167598 | Vtable: 0x456fb0

**197 namespace functions**. 4 vtables: main + 3 interface bases (each 0x10 bytes at 0x04, 0x14, 0x24).

Key fields (abbreviated — full struct is 132 fields in Ghidra):

| Offset | Type | Name | Notes |
|--------|------|------|-------|
| 0x34 | str | strServerName | |
| 0x38 | int | nNetworkState | 0=disconnected, 4=server |
| 0x40 | 0x28 | obj | dequeRakNetGUID | std::deque (40 bytes) |
| 0x68 | int | nTickRate | init=15 |
| 0x6C | int | nMaxPlayers | init=16 |
| 0x88 | ushort | nServerPort | init=10999 |
| 0x8A | ushort | nAuthPort | init=8766 |
| 0x8C | ushort | nMasterPort | init=27016 |
| 0x90 | str | strGameMode | init="survival" |
| 0x9C | 0x24 | obj | netID | cNetID2 (36 bytes) |
| 0xC9 | byte | bIsLANOnly | |
| 0xCC | ptr | pNetworkRPCManager | alloc 0x14 |
| 0xD0 | ptr | pNetworkVoiceManager | alloc 0x14 |
| 0xD4 | ptr | pNetworkReplicaManager | alloc 0x1678 (5752 bytes!) |
| 0xD8 | ptr | pSteamFriendsManager | alloc 0x20 |
| 0xDC | ptr | pNetworkIDManager | alloc 0x101C |
| 0xE0 | ptr | pRakPeer | RakPeerInterface* |
| 0xE4 | ptr | pDirectoryDeltaTransfer | RakNet, alloc 0x224 |
| 0xE8 | ptr | pFileListTransfer | RakNet, alloc 0x21C |
| 0xF8 | ptr | pMasterServer | alloc 0xC0 |
| 0xFC | ptr | pNatTraversal | alloc 0x198 |
| 0x109 | byte | bIsServer | |
| 0x10A | byte | bServerStarted | |
| 0x10B | byte | bIsOnline | |
| 0x10C | byte | bPeerCreated | |
| 0x110 | ptr | pSimulation | |
| 0x11C | ptr | pCheshireCat | tCheshireCat*, alloc 0x160 (pimpl) |
| 0x120 | 0x74 | obj | pendingConnection | cPendingConnection (116 bytes) |
| 0x1AC | ptr | pSnapshotManager | alloc 8 |
| 0x1B8 | ptr | pSteamPunchthrough | alloc 0x48 |
| 0x214 | 0xDC | obj | consoleInput | cConsoleInput (220 bytes) |
| 0x300 | 0x1054 | obj | loggerImpl | cLoggerImplementation (4180 bytes) |
| 0x1364 | ptr | pSteamRichPresence | alloc 0x54 |
| 0x1368 | 0x48 | obj | migrationInfo | MigrationInfo (72 bytes) |
| 0x13B0 | ptr | pDedicatedServerProcess1 | |
| 0x13B4 | ptr | pDedicatedServerProcess2 | |

---

### cNetworkComponent (684 bytes / 0x2AC)

Extends cEntityComponent(16 bytes) + RakNet::Replica3(344 bytes @0x10). Constructor: 0x5adec | Destructor: 0x5afc2

**62 namespace functions**.

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 16 | obj | base_cEntityComponent | |
| 0x10 | 344 | obj | replica3Base | RakNet::Replica3 embedded |
| 0x168 | 4 | int | field_0x168 | |
| 0x16C | 4 | int | field_0x16C | |
| 0x170 | 1 | byte | bField_0x170 | |
| 0x171 | 1 | byte | bField_0x171 | |
| 0x172 | 2 | pad | | |
| 0x174 | 4 | uint | nSleepingFlagsLower | bitmask for sleeping flags 0-31 |
| 0x178 | 4 | uint | nSleepingFlagsUpper | bitmask for sleeping flags 32-63 |
| 0x17C | 8 | bytes | mOwnerGUID | RakNetGUID uint64 part |
| 0x184 | 2 | ushort | mOwnerSystemIndex | RakNetGUID systemIndex |
| 0x186 | 2 | pad | | |
| 0x188 | 8 | bytes | mClassifiedTargetGUID | |
| 0x190 | 2 | ushort | mClassifiedTargetIndex | |
| 0x192 | 2 | pad | | |
| 0x194 | 276 | obj | bitStream | RakNet::BitStream embedded |
| 0x2A8 | 4 | int | nSerializeState | |

Key functions: Serialize(0x5b500), Deserialize(0x5ba96), SetOwner(0x5b0c8), SetNetworkSleepingFlag(0x5c310), ComponentWallUpdate(0x5c69a), SerializeConstruction(0x5bf32).

---

### cTransformComponent (380 bytes / 0x17C)

Extends cSerializableEntityComponent(16 bytes) + cTransformProvider(vtable @0x10). Constructor: 0x7f0ce | Destructor: 0x7fda0

**63 namespace functions**.

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 16 | obj | base_cEntityComponent | cSerializableEntityComponent |
| 0x10 | 4 | ptr | pTransformProviderVtable | cTransformProvider interface |
| 0x14 | 4 | ptr | pPhysicsComponent | cPhysicsComponent* |
| 0x18 | 4 | ptr | pFollowerComponent | FollowerComponent* |
| 0x1C | 4 | float | fLocalPosX | |
| 0x20 | 4 | float | fLocalPosY | |
| 0x24 | 4 | float | fLocalPosZ | |
| 0x28 | 4 | float | fServerPosX | |
| 0x2C | 4 | float | fServerPosY | |
| 0x30 | 4 | float | fServerPosZ | |
| 0x34 | 4 | float | fWorldPosX | |
| 0x38 | 4 | float | fWorldPosY | |
| 0x3C | 4 | float | fWorldPosZ | |
| 0x40 | 4 | float | fScaleX | |
| 0x44 | 4 | float | fScaleY | |
| 0x48 | 4 | float | fScaleZ | |
| 0x4C | 4 | float | fServerScaleX | |
| 0x50 | 4 | float | fServerScaleY | |
| 0x54 | 4 | float | fServerScaleZ | |
| 0x58 | 4 | float | fRotation | radians |
| 0x5C | 4 | float | fServerRotation | degrees |
| 0x60 | 64 | mat4 | matLocalTransform | |
| 0xA0 | 64 | mat4 | matLocalTransformInverse | |
| 0xE0 | 64 | mat4 | matWorldTransform | |
| 0x120 | 64 | mat4 | matWorldTransformInverse | |
| 0x160 | 4 | int | nFacing | 0-7, 8 directions |
| 0x164 | 4 | int | eFacingModel | 0-4, default=4=none |
| 0x168 | 4 | ptr | pTransformHistory | cTransformationHistory* |
| 0x16C | 4 | ptr | pPredictionHistory | cTransformationHistory* |
| 0x170 | 4 | int | nPredictionStep | |
| 0x174 | 4 | int | nPredictionEnabled | |
| 0x178 | 2 | ushort | nPristineDirtyFlags | |
| 0x17A | 2 | ushort | nCurrentDirtyFlags | bits: 1-3=posXYZ, 4=rotation, 6-8=scaleXYZ, 9=facingModel |

---

### cTransformationHistory (24 bytes / 0x18)

Circular buffer for network transform prediction. Source: `networklib/TransformationHistory.cpp`.

| Offset | Size | Type | Name |
|--------|------|------|------|
| 0x00 | 4 | ptr | pBuffer | cTransformationHistoryCell* |
| 0x04 | 4 | uint | nHead | |
| 0x08 | 4 | uint | nTail | |
| 0x0C | 4 | uint | nCapacity | |
| 0x10 | 4 | uint | nMaxEntries | |
| 0x14 | 4 | uint | nTickIntervalMS | |

14 functions: Init(0x1b7690), Write(0x1b76d6), Read(0x1b7870), Clear(0x1b7b3c), Truncate(0x1b7b7c), Flatten(0x1b7cb6).

---

### cTransformationHistoryCell (20 bytes / 0x14)

| Offset | Type | Name |
|--------|------|------|
| 0x00 | uint | nTimeMS |
| 0x04 | float | fPosX |
| 0x08 | float | fPosY |
| 0x0C | float | fPosZ |
| 0x10 | float | fRotation |

---

### cAnimStateComponent (208 bytes / 0xD0)

Extends cSerializableEntityComponent(16 bytes) + cBBoxProvider(vtable @0x10). Constructor: 0x2960c | Destructor: 0x2980a

**87 namespace functions**.

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 16 | obj | base_cEntityComponent | cSerializableEntityComponent |
| 0x10 | 4 | ptr | pBBoxProviderVtable | cBBoxProvider interface |
| 0x14 | 4 | float | fAnimTime | current animation position |
| 0x18 | 4 | float | fDeltaTimeMultiplier | init=1.0 |
| 0x1C | 4 | uint | dwAnimHash | cHashedString hash |
| 0x20 | 4 | ptr | pAnimStr | |
| 0x24 | 4 | uint | dwBankHash | |
| 0x28 | 4 | ptr | pBankStr | |
| 0x2C | 4 | uint | dwBuildHash | |
| 0x30 | 4 | ptr | pBuildStr | |
| 0x34 | 4 | uint | dwSkinHash | |
| 0x38 | 4 | ptr | pSkinStr | |
| 0x3C | 4 | uint | dwOverrideBuildHash | |
| 0x40 | 4 | ptr | pOverrideBuildStr | |
| 0x44 | 4 | int | nEPlayMode | 0=loop, 1=bounce, 2=once |
| 0x48 | 4 | int | nEQueuedPlayMode | init=1 |
| 0x4C | 1 | byte | bRayTestOnBB | |
| 0x4D | 1 | byte | bHidden | |
| 0x4E | 2 | pad | | |
| 0x50 | 4 | uint | dwPristineDirtyFlags | |
| 0x54 | 4 | uint | dwCurrentDirtyFlags | 28+ bits |
| 0x58 | 4 | uint | dwDeserializedAnimHash | |
| 0x5C | 4 | uint | dwQueuedAnimHash | |
| 0x60 | 4 | uint | dwRgbaAddColour | init=Transparent |
| 0x64 | 4 | uint | dwRgbaMultColour | init=White |
| 0x68 | 4 | uint | dwRgbaOverrideAddColour | init=Transparent |
| 0x6C | 4 | uint | dwRgbaOverrideMultColour | init=White |
| 0x70 | 4 | float | fOverrideShade | init=1.0 |
| 0x74 | 4 | float | fScaleX | animation scale, from AnimNode+0xC0 |
| 0x78 | 4 | float | fScaleY | from AnimNode+0xC4 |
| 0x7C | 4 | float | fFinalOffsetX | from AnimNode+0x130 |
| 0x80 | 4 | float | fFinalOffsetY | from AnimNode+0x134 |
| 0x84 | 4 | float | fFinalOffsetZ | from AnimNode+0x138 |
| 0x88 | 1 | byte | bHasOverrideAddColour | |
| 0x89 | 1 | byte | bHasOverrideMultColour | |
| 0x8A | 2 | pad | | |
| 0x8C | 4 | int | field_0x8C | |
| 0x90 | 4 | float | fHauntStrength | |
| 0x94 | 4 | ptr | pAnimNode | AnimNode*, alloc 0x15C (348 bytes) |
| 0x98 | 4 | ptr | pVecAnimQueue_begin | std::vector<cHashedString> |
| 0x9C | 4 | ptr | pVecAnimQueue_end | |
| 0xA0 | 4 | ptr | pVecAnimQueue_cap | |
| 0xA4 | 4 | int | nSortOrder | init=8 |
| 0xA8 | 4 | ptr | pAnimBankResource | |
| 0xAC | 4 | ptr | pUITransformComponent | |
| 0xB0 | 4 | float | fBBMinX | init=FLT_MAX |
| 0xB4 | 4 | float | fBBMinY | init=FLT_MAX |
| 0xB8 | 4 | float | fBBMinZ | init=FLT_MAX |
| 0xBC | 4 | float | fBBMaxX | init=-FLT_MAX |
| 0xC0 | 4 | float | fBBMaxY | init=-FLT_MAX |
| 0xC4 | 4 | float | fBBMaxZ | init=-FLT_MAX |
| 0xC8 | 1 | byte | bManualHitRegion | |
| 0xC9 | 3 | pad | | |
| 0xCC | 4 | ptr | pSymbolExchangeTree | std::map<uint,pair<uint,uint>>* |

### AnimNode Internal Layout (0x15C bytes, accessed via pAnimNode)

| Offset | Type | Name | Notes |
|--------|------|------|-------|
| +0x48 | uint8_t | layer | 3-bit serialized |
| +0x4C | uint8_t | sortOrderByte | 8-bit, vtable+0 write |
| +0x94 | obj | animSubobject | +0x14=frame count, +0x20=duration |
| +0xBC | float | currentAnimTime | |
| +0xC0 | float | scaleX | mirrors cAnimStateComponent.fScaleX |
| +0xC4 | float | scaleY | mirrors cAnimStateComponent.fScaleY |
| +0xC8 | float | depthBias | decimal 200 |
| +0xCC | float | lightOverride | decimal 300 (NOTE: b5 said +0xC8=lightOverride but Deserialize writes 300=0x12C; confirm) |
| +0xDC | ptr | hiddenLayers_begin | vector<cHashedString> |
| +0xE0 | ptr | hiddenLayers_end | |
| +0xE8 | ptr | hiddenSymbols_begin | vector<cHashedString> |
| +0xEC | ptr | hiddenSymbols_end | |
| +0xF4 | bool | bDepthTestEnabled | |
| +0xF5 | bool | bDepthWriteEnabled | |
| +0xF8 | float | sortOrder | vtable+8 write |
| +0xFC | uint | dwAddColour | RGBA |
| +0x100 | — | → ApplyMultColour() | |
| +0x110 | _Rb_tree | symbolOverrideTree | begin/end/size at 0x114/0x118/0x11C/0x120 |
| +0x124 | uint8_t | orientation | 1-bit serialized |
| +0x128 | float | rotation | |
| +0x12C | float | lightOverride | decimal 300 |
| +0x130 | float | finalOffsetX | mirrors cAnimStateComponent.fFinalOffsetX |
| +0x134 | float | finalOffsetY | |
| +0x138 | float | finalOffsetZ | |

### Deserialize / Serialize — Network Sync Attributes

**Function addresses**: Serialize=0x2c39e (578 lines), Deserialize=0x2d470 (680 lines)

**DirtyFlags computation**: `uVar11 = dwCurrentDirtyFlags | (param_2 ? dwPristineDirtyFlags : 0)`

**Deserialization order** (complete, 680-line analysis):

| DirtyBit | Payload | Target Field(s) | Side Effects |
|----------|---------|-----------------|--------------|
| 0x001 | 2-bit PlayMode | `nEPlayMode` | — |
| 0x002 | 32-bit hash | `dwAnimHash` | → OnAnimChanged |
| 0x004 | 32-bit hash | `dwDeserializedAnimHash` | — |
| 0x008 | 32-bit hash | `dwBuildHash` + `dwSkinHash` | → HandleClientBuildOverrides |
| 0x010 | 32-bit hash | `dwBankHash` | → OnAnimChanged |
| always | 1-bit | `bHidden` | — |
| 0x040 | 5-bit count + entries (0x60-bit each) | `pSymbolExchangeTree` | update symbol override RbTree |
| 0x080 | 5-bit count + 32-bit hashes | `pAnimNode+0xDC/0xE0` (hiddenLayers) | — |
| (next) | 5-bit count + 32-bit hashes | `pAnimNode+0xE8/0xEC` (hiddenSymbols) | — |
| 0x300 | 32-bit×2 (X+Y) | `fScaleX`/`fScaleY` → `pAnimNode+0xC0/0xC4` | — |
| 0x400 | 3-bit | `pAnimNode+0x48` (layer) | — |
| 0x800 | 1-bit | `pAnimNode+0x124` (orientation) | — |
| 0x1000 | 32-bit float | `pAnimNode+0x128` (rotation) | — |
| 0x2000 | 8-bit (vtable+0) | `pAnimNode+0x4C` (sortOrderByte) | — |
| 0x4000 | 32-bit (vtable+8) | `pAnimNode+0xF8` (sortOrder float) | — |
| 0x8000 | 32-bit float | `fDeltaTimeMultiplier` | — |
| always | 1-bit | `bRayTestOnBB` | — |
| 0x20000 | RGBA 32-bit | `dwRgbaAddColour` → `pAnimNode+0xFC` | — |
| 0x40000 | RGBA 32-bit | `dwRgbaMultColour` → `pAnimNode+0x100` | → ApplyMultColour() |
| 0x80000 | 32-bit hash | `dwOverrideBuildHash` | → ApplyBloomEffectHandle |
| always | 1-bit bool | `fHauntStrength` (0 or const) | — |
| 0x100000 | 32-bit float | `pAnimNode+0x12C` (lightOverride) | — |
| 0x200000 | Vector3 (3×32-bit) | `fFinalOffsetX/Y/Z` → `pAnimNode+0x130/0x134/0x138` | — |
| (next) | 32-bit float | `pAnimNode+0xC8` (depthBias) | — |
| always | 1-bit | `pAnimNode+0xF4` (bDepthTestEnabled) | — |
| always | 1-bit | `pAnimNode+0xF5` (bDepthWriteEnabled) | — |
| (next bit) | 4×32-bit AABB | `fBBMinX/Y`, `fBBMaxX/Y`; sets `bManualHitRegion=1` | — |
| (next) | 32-bit float | `fAnimTime` (only if param_3==false) | — |

**Else-branch (full/initial sync)**:
1. Read 2-bit PlayMode → `nEPlayMode`
2. If BitStream has remaining bits + ReadBit==1: read 32-bit → `dwQueuedAnimHash`
3. If param_3==false: clear anim queue, `dwAnimHash=dwQueuedAnimHash`, → OnAnimChanged; if PlayMode≠2 and not loop-replaying: `fAnimTime=0.0`

**param_3 semantics**: "ignore-apply" flag — when true, AnimTime/PlayMode are not applied (prevents overriding local client state during smooth interpolation).

---

## cPhysicsComponent (108 bytes / 0x6C)

**Source**: `PhysicsComponent.cpp`
**Platform**: macOS 32-bit dontstarve_steam (full symbols)

### Function Addresses (file offsets)

| Address | Function |
|---------|----------|
| 0x677cc | ctor |
| 0x677d2 | OnSetEntity |
| 0x67936 | ~cPhysicsComponent |
| 0x67a02 | BuildDebugString |
| 0x67b20 | SetMass |
| 0x67c50 | Teleport |
| 0x67d4c | TeleportRespectingInterpolation |
| 0x67ea8 | UpdateVel |
| 0x67fb2 | SetVel |
| 0x67fe0 | SetLocalMotorVel |
| 0x68040 | SetLocalMotorVelOverride |
| 0x6806c | ClearLocalMotorVelOverride |
| 0x680a0 | SetCollisionObject |
| 0x685b8 | UpdateSleepStatus |
| 0x68642 | SetCollisionCallback |
| 0x68672 | SetRestitution |
| 0x686a8 | SetFriction |
| 0x686de | SetCollisionMask |
| 0x687b4 | SetCollisionGroup |
| 0x6888a | Update |
| 0x68956 | OnWake |
| 0x6895c | OnSleep |
| 0x68962 | SetActive |
| 0x68986 | SetDontRemoveOnSleep |
| 0x68992 | SetCollides |
| 0x68a38 | GetVelocity |
| 0x68a8e | SetStationaryDamping |
| 0x68aa2 | GetLocalMotorSpeed |
| 0x68ad8 | Serialize |
| 0x68fe6 | Deserialize |
| 0x6984c | OnPostSerialize |
| 0x69870 | SetPristine_Server |
| 0x6a142 | RegisterLua |

### Struct Layout

```c
struct cPhysicsComponent { // size=0x6C=108 bytes
    /* 0x00 */ // [cEntityComponent base, 16 bytes: vtable* + 3 unknown fields]
    /* 0x0C */ void*               pEntity_backref;       // entity+0xC8/+0xCF checked; copied to btRigidBody+0xfc
    /* 0x10 */ cTransformComponent* pTransformComponent;  // from entity+0xd8; pTransformComponent+0x14 = this (backref)
    /* 0x14 */ float               fRadius;               // init=1.0; dirty 0x100
    /* 0x18 */ float               fMass;                 // init=0.0; dirty 0x10
    /* 0x1C */ float               fHeight;               // init=1.0; capsule height; dirty 0x200
    /* 0x20 */ float               fStationaryDamping;    // init=0.0; → btRigidBody::setDamping when motorVel==0
    /* 0x24 */ void*               pPhysicsWorldSim;      // [+0x14]=physics world vtable; from entity+0x40→+0x170
    /* 0x28 */ int                 eCollisionShape;       // 0=none,1=capsule,2=sphere,3=cylinder; dirty 0x80
    /* 0x2C */ float               fFriction;             // init=1.0; → btRigidBody+0xec (friction); dirty 0x20
    /* 0x30 */ float               fMotorVelX;            // local motor velocity
    /* 0x34 */ float               fMotorVelY;
    /* 0x38 */ float               fMotorVelZ;
    /* 0x3C */ float               fSavedMotorVelX;       // override backup (SetLocalMotorVelOverride)
    /* 0x40 */ float               fSavedMotorVelY;
    /* 0x44 */ float               fSavedMotorVelZ;
    /* 0x48 */ btRigidBody*        pRigidBody;
    /* 0x4C */ btCollisionShape*   pCollisionShape;       // btCapsuleShape/btCylinderShape/btSphereShape
    /* 0x50 */ btCompoundShape*    pCompoundShape;
    /* 0x54 */ void*               pMotionState;          // custom motion state (0x50 bytes); +0x4=pTransformComponent
    /* 0x58 */ float               fRestitution;          // init=0.5; → btRigidBody+0xf0; dirty 0x40
    /* 0x5C */ uint8_t             bActive;               // init=1; dirty 0x01
    /* 0x5D */ uint8_t             bDontRemoveOnSleep;
    /* 0x5E */ uint8_t             _pad[2];
    /* 0x60 */ uint32_t            nCollisionFlags;       // bit2=collides(dirty 0x02), bit3=hasCallback; → btRigidBody+0xd8
    /* 0x64 */ int16_t             nCollisionMask;        // init=0; dirty 0x04
    /* 0x66 */ int16_t             nCollisionGroup;       // init=1; dirty 0x08
    /* 0x68 */ uint16_t            nPristineFlags;        // bits 2-15: OR-accumulated; bits 0-1: XOR-toggle (active/collides)
    /* 0x6A */ uint16_t            nDirtyFlags;           // cleared by OnPostSerialize; set by setters
};
```

### nDirtyFlags Bit Definitions

| Bit | Field |
|-----|-------|
| 0x001 | bActive (XOR-tracked) |
| 0x002 | collides (nCollisionFlags bit2, XOR-tracked) |
| 0x004 | nCollisionMask (+0x64) |
| 0x008 | nCollisionGroup (+0x66) |
| 0x010 | fMass (+0x18) |
| 0x020 | fFriction (+0x2C) |
| 0x040 | fRestitution (+0x58) |
| 0x080 | eCollisionShape (+0x28, triggers SetCollisionObject rebuild) |
| 0x100 | fRadius (+0x14) |
| 0x200 | fHeight (+0x1C) |

### Key Behaviors

- **OnSetEntity**: `this+0x24` = pPhysicsWorldSim (entity+0x40→+0x170); `this+0x10` = pTransformComponent (entity+0xd8); creates motionState (0x50B) → `this+0x54`
- **SetCollisionObject**: params=(eShape, fRadius, fHeight); destroys old btRigidBody/shape; creates btCapsule/Sphere/CylinderShape→0x4C, btCompoundShape→0x50, btRigidBody→0x48; userPointer=`this+0x0C` → btRigidBody+0xfc
- **UpdateVel**: motorVel==0 → `setDamping(fStationaryDamping, 0)`; motorVel>0 → transform to world coords → write btRigidBody+0x150-0x15C
- **GetVelocity**: returns btRigidBody+0x150-0x158
- **Serialize/Deserialize**: stream 10 dirty-flagged fields; Deserialize: if 0x80 not set → update properties in place, else → call SetCollisionObject to rebuild
- **OnPostSerialize**: `nPristineFlags = (D&3) XOR ((D&0xfffc)|P)`; `nDirtyFlags = 0`
- **SetPristine_Server**: `*(uint32*)(this+0x68) = 0` (clears both pristine+dirty)

---

## GroundCreepEntity (24 bytes / 0x18)

**Platform**: macOS 32-bit dontstarve_steam (full symbols)

### Function Addresses (file offsets)

| Address | Function |
|---------|----------|
| 0x3b2c2 | ComponentID |
| 0x3b2c8 | Serialize |
| 0x3b37e | Deserialize |
| 0x3b482 | OnPostSerialize |
| 0x3b48c | SetPristine_Server |
| 0x3b496 | cEntityManager::GetAwakeComponentList\<GroundCreepEntity\> |
| 0x3b4e6 | cEntityManager::GetComponentList\<GroundCreepEntity\> |
| 0x3b6e4 | ~GroundCreepEntity (dtor v1) |
| 0x3b6ea | ~GroundCreepEntity (dtor v2) |
| 0x3b71e | GetComponentID |
| 0x3b728 | GetComponentName |
| 0x3be48 | ComponentLuaProxy\<GroundCreepEntity\>::Register |
| 0x3be1a | GroundCreepEntityLuaProxy::SetRadius |

### Struct Layout

```c
struct GroundCreepEntity { // size=0x18=24 bytes
    /* 0x00 */ byte   base_cEntityComponent[16]; // vtable+3 fields; [0x0C]=pEntity
    /* 0x10 */ byte   nFlags;      // bit0x01=dirty(radius changed), bit0x02/04=pristine; SetRadius writes 7
    /* 0x11 */ byte   _pad11[3];
    /* 0x14 */ float  fRadius;     // network-synced radius; GetTriggeredCreepSpawners reads
};
```

### nFlags Bit Definitions

| Bit | Meaning |
|-----|---------|
| 0x01 | dirty: radius changed (set by Deserialize/SetRadius, cleared by GroundCreep::Update after reading) |
| 0x02 | pristine (cleared by OnPostSerialize: `nFlags &= 0xfd`) |
| 0x04 | pristine flag 2 |

- **SetRadius (LuaProxy)**: writes `nFlags = 7` and `fRadius = value`
- **SetPristine_Server**: `nFlags &= 1` (keep only dirty bit, clear pristine bits)
- **entity+0xe8/0xec/0xf0** = world XYZ coordinates (read by GroundCreep::GetTriggeredCreepSpawners)

---

## GroundCreep (213 bytes / 0xD5)

**Platform**: macOS 32-bit dontstarve_steam (full symbols)
**Note**: Implements SceneGraphNode rendering interface (embedded, not pointer).

### Function Addresses (file offsets)

| Address | Function |
|---------|----------|
| 0x3984c | ComponentID |
| 0x39928 | GroundCreep ctor |
| 0x39ae0 | ~GroundCreep dtor |
| 0x39b3e | OnInitializationComplete |
| 0x39d2e | DecodeString |
| 0x39e94 | InvalidateRegionsNearPlayer |
| 0x3a102 | FastForward |
| 0x3a126 | Update |
| 0x3ac2a | DoRender (v1) |
| 0x3aeea | DoRender (v2) |
| 0x3ad4e | RebuildVBs |
| 0x3af1a | OnCreep |
| 0x3afca | TriggerCreepSpawners |
| 0x3b090 | SetFromString |
| 0x3b160 | GetAsString |
| 0x3b194 | GetTriggeredCreepSpawners |
| 0x3b262 | CalculateAABB (v1) |
| 0x3b292 | CalculateAABB (v2) |
| 0x3b74a | GetComponentID |
| 0x3b750 | GetComponentName |
| 0x3b762 | RendersAlpha |
| 0x3b768 | ManualSortOrder |
| 0x3b8f6 | RegisterLua |

### Struct Layout

```c
struct GroundCreep { // size=0xD5=213 bytes
    /* 0x00 */ byte         base_cEntityComponent[16];  // vtable+3 fields; [0x0C]=pEntity backref
    /* 0x10 */ byte         sceneGraphNode[0x94];       // SceneGraphNode embedded; own vtable at +0x10; internal [0x48]=1
    /* 0xA4 */ float        fAccumTime;                 // accumulated dt; FastForward sets to fUpdateInterval+epsilon
    /* 0xA8 */ float        field_0xA8;                 // init=1.0; purpose TBD
    /* 0xAC */ float        fUpdateInterval;            // init=1.0; Update trigger threshold (seconds)
    /* 0xB0 */ TileGrid*    pTileGrid1;                 // primary read buffer; OnCreep/GetAsString use
    /* 0xB4 */ TileGrid*    pTileGrid2;                 // double-buffer write target; swapped with TileGrid1 each Update
    /* 0xB8 */ uint8_t*     pByteArray;                 // region_cols × region_rows bytes; 1=region needs VB rebuild
    /* 0xBC */ void*        pListBegin;                 // renderLayers list begin (MapLayerRenderData ptrs)
    /* 0xC0 */ void*        pListEnd;                   // renderLayers list end
    /* 0xC4 */ dword        field_0xC4;                 // init=0
    /* 0xC8 */ void*        pMapLayerManagerCmp;        // MapLayerManagerComponent*
    /* 0xCC */ void*        pMapRenderer;               // MapRenderer* (loaded from creep.ksh)
    /* 0xD0 */ void*        strEncodedData;             // std::string COW ptr; base64-encoded initial state; cleared after DecodeString
    /* 0xD4 */ byte         bVBsDirty;                  // 0=VBs current; 1=needs rebuild; set by Update, cleared by DoRender
};
```

### Double-Buffer Update Flow

```
OnInitializationComplete:
  pMapRenderer      ← new MapRenderer("creep.ksh")
  pMapLayerManagerCmp ← GetComponent<MapLayerManagerComponent>()
  pTileGrid1        ← new TileGrid(mapW, mapH)
  pTileGrid2        ← new TileGrid(mapW, mapH)
  pByteArray        ← operator_new(region_cols × region_rows), memset(1)
  if strEncodedData non-empty → DecodeString()

Update() [triggers every fUpdateInterval seconds]:
  fAccumTime += dt
  if fAccumTime >= fUpdateInterval:
    fAccumTime -= fUpdateInterval
    if bVBsDirty == 0: bzero(pByteArray)     // reset region dirty flags
    foreach GroundCreepEntity in awake list:
      if entity.nFlags & 0x01:               // dirty (radius/position changed)
        write tile coords to pTileGrid2
        entity.nFlags &= ~0x01
    swap(pTileGrid1.tile_data, pTileGrid2.tile_data)  // double-buffer swap
    bVBsDirty = 1

DoRender() [every frame]:
  if bVBsDirty:
    RebuildVBs(pByteArray)  // rebuild MapLayerRenderData for dirty regions
    bVBsDirty = 0
  if renderPass == 2: MapRenderer::DrawMap(...)
```

### Key Function Behaviors

- **OnCreep(x, z)**: reads `pTileGrid1->tile_data[y*w+x]`; returns bool (creep present at tile)
- **DecodeString**: base64 decode → write to `pTileGrid1->tile_data`; values clamped to 0 or 1
- **GetAsString**: `base64_encode(pTileGrid1->tile_data)`
- **SetFromString**: if uninitialized → store in strEncodedData; else → call DecodeString immediately
- **InvalidateRegionsNearPlayer**: marks `pByteArray[region_row * region_cols + region_col] = 1`
- **FastForward**: `fAccumTime = fUpdateInterval + epsilon` (forces Update to fire on next frame)
- **TriggerCreepSpawners**: tests distance ≤ (fRadius + constant) per GroundCreepEntity; triggers "creepactivate"
- **CalculateAABB**: returns hardcoded ±9984 bounding box

---

## TileGrid (28 bytes / 0x1C)

**Used by**: GroundCreep (double-buffered tile data for creep rendering system)

```c
struct TileGrid { // size=0x1C=28 bytes
    /* 0x00 */ int      width;
    /* 0x04 */ int      height;
    /* 0x08 */ int      region_cols;  // ceil(width / region_size); column stride for pByteArray
    /* 0x0C */ int      region_rows;
    /* 0x10 */ int      _unk10;       // unknown
    /* 0x14 */ int      _unk14;       // unknown
    /* 0x18 */ ushort*  tile_data;    // width × height × 2 bytes; values: 0 (no creep) or 1 (creep)
};
```

- `tile_data` pointer is swapped between TileGrid1 and TileGrid2 in `GroundCreep::Update()` double-buffer swap
- Region system divides the map into coarser grid cells for efficient dirty-region tracking via `pByteArray`

---

## EntityLuaProxy Methods

34 Lua-bound methods decoded from `EntityLuaProxy::methods` table. Created in earlier sessions.

---

## Key Addresses

### cApplication
| Field | Address/Offset |
|-------|---------------|
| sRenderJobThread | 0x4650a4 (global) |
| sUpdateJobThread | 0x465010 (global) |
| gUseThreadedPhysics | 0x4651b2 |
| gUseThreadedRenderer | 0x4651b0 |
| sPostUpdateTrigger | 0x4651b4 |
| gUseEmergencyGC | 0x4651b1 |

### cApplication Layout (stack-local in Main)
| Offset | Type | Name |
|--------|------|------|
| 0x00 | ptr | pSystemService |
| 0x04 | ptr | pGameService |
| 0x08 | ptr | pGame (cGame*, heap-alloc) |
| 0x0C | int | unknown (copied to cGame.0xD4) |
| 0x10 | float | fTimeout (init=180.0f) |

Main function at 0xcfa8 (GameApp::Main).

### cNetworkManager Singleton
`PTR_mInstance_00450930`

---

## Registered Component Types

38 types registered by cDontStarveSim::RegisterLuaComponents (0x8bdee):
cTransformComponent, cUITransformComponent, cSoundEmitterComponent, cAnimStateComponent, cPhysicsComponent, cNetworkComponent, cShardNetworkComponent, cShardClientComponent, cLightEmitterComponent, cImageWidget, cVideoWidget, cTextWidget, cTextEditWidget, cLightWatcherComponent, MapGenSim, MapComponent, ShadowManagerComponent, MiniMapComponent, PostProcessorComponent, FontComponent, WaveComponent, GraphicsOptionsComponent, TwitchComponent, AccountManagerComponent, cLabelComponent, cImageComponent, DynamicShadowComponent, MiniMapEntityComponent, VFXEffect, ParticleEmitter, EnvelopeComponent, FollowerComponent, DebugRenderComponent, GroundCreepEntity, RoadManagerComponent, MapLayerManagerComponent, GroundCreep, PathfinderComponent.

---

## Unknowns & Remaining Work

### cGame Unknown Fields
- **0x5C**: init=0, never accessed by any of 64 member functions
- **0x6E**: init=0, never accessed
- **0x78**: init=0, never accessed (previous evidence was misattributed to sRenderJobThread)
- **0x90**: init=-1, previous evidence was misattributed to sRenderJobThread

### cSimulation Unknown Fields
- **0x74**: init=-1, only in ctor
- **0x17C-0x184**: vector, zeroed in ctor/freed in dtor, never used by any of 87 member functions

### Not Yet Analyzed (potential future work)
- cUITransformComponent (50 namespace functions found)
- cLightEmitterComponent
- cSoundEmitterComponent
- AnimNode (0x15C bytes) — internal layout partially mapped
- cEntityComponent vtable slots
- sRenderJobThread struct
- DontStarveInputHandler (720 bytes, embedded in cDontStarveSim)
- cPendingConnection (116 bytes, embedded in cNetworkManager)
- cConsoleInput (220 bytes, embedded in cNetworkManager)
- cLoggerImplementation (4180 bytes, embedded in cNetworkManager)
- MigrationInfo (72 bytes, embedded in cNetworkManager)
