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
  - [TDataCacheAnimNode (248 bytes / 0xF8)](#tdatacacheanimnode-248-bytes--0xf8)
  - [SceneGraphNode (145 bytes / 0x91)](#scenegraphnode-145-bytes--0x91)
  - [AnimNode (~348 bytes / 0x15C)](#animnode-348-bytes--0x15c)
  - [AnimationFile (40 bytes / 0x28)](#animationfile-40-bytes--0x28)
  - [sAnim (36 bytes / 0x24)](#sanim-36-bytes--0x24)
  - [sFrame (40 bytes / 0x28)](#sframe-40-bytes--0x28)
  - [sAnimElement (84 bytes / 0x54)](#sanimelement-84-bytes--0x54)
  - [sBuild (76 bytes / 0x4C)](#sbuild-76-bytes--0x4c)
  - [sBuildSymbolFrame (52 bytes / 0x34)](#sbuildsymbolframe-52-bytes--0x34)
  - [sAnimEntry (44 bytes / 0x2C)](#sanimentry-44-bytes--0x2c)
  - [AnimManager (116 bytes / 0x74)](#animmanager-116-bytes--0x74)
  - [BatchVertex (24 bytes / 0x18)](#batchvertex-24-bytes--0x18)
  - [Batcher (68 bytes / 0x44)](#batcher-68-bytes--0x44)
  - [UIRenderAssetManager (32 bytes / 0x20)](#uirenderassetmanager-32-bytes--0x20)
  - [AutoShaderConstant (9 bytes)](#autoshaderconstant-9-bytes)
  - [StencilState (28 bytes / 0x1C)](#stencilstate-28-bytes--0x1c)
  - [TextureStage (24 bytes / 0x18)](#texturestage-24-bytes--0x18)
  - [Matrix4 (64 bytes / 0x40)](#matrix4-64-bytes--0x40)
  - [RenderState (372 bytes / 0x174)](#renderstate-372-bytes--0x174)
  - [CommandBuffer (120 bytes / 0x78)](#commandbuffer-120-bytes--0x78)
  - [Renderer (564 bytes / 0x234)](#renderer-564-bytes--0x234)
  - [GameRenderer (2024 bytes / 0x7E8)](#gamerenderer-2024-bytes--0x7e8)
- [TDataCacheAnimNode::DrawCacheRender — Render Pipeline](#tdatacacheanimnode-drawcacherender--render-pipeline)
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
- AnimNode (0x15C bytes) — field mapping complete (ctor + dtor + GetOverrideBuildForSymbol; not yet created as Ghidra struct)
- cEntityComponent vtable slots
- sRenderJobThread struct
- DontStarveInputHandler (720 bytes, embedded in cDontStarveSim)
- cPendingConnection (116 bytes, embedded in cNetworkManager)
- cConsoleInput (220 bytes, embedded in cNetworkManager)
- cLoggerImplementation (4180 bytes, embedded in cNetworkManager)
- MigrationInfo (72 bytes, embedded in cNetworkManager)

---

## TDataCacheAnimNode (248 bytes / 0xF8)

**Source**: `dontstarve_steam` macOS 32-bit, full symbols  
**Functions analyzed**: ctor `0x000c2d1e`, dtor `0x000c2cc6`, `GetOverrideBuildForSymbol` `0x000c2836`, `DrawCacheRender` `0x000c156a`, `CalculateScaleMatrix` `0x000c26e4`  
**Note**: TDataCacheAnimNode is a **snapshot/cache** of AnimNode data for render submission. Size = 0xF8 = 248 bytes. AnimNode+0xF8 (sortOrder) is deliberately NOT cached here — sortOrder is only used for render-queue ordering, not for actual rendering.

### Layout

| Offset | Size | Type | Name | Source / Notes |
|--------|------|------|------|----------------|
| 0x00 | 4 | `void*` | `vtable` | `PTR_DrawCacheRender_004563f8` |
| 0x04 | 4 | `void*` | `pAnimNode` | Pointer to source `AnimNode` (param_1) |
| 0x08 | 64 | `float[16]` | `matrix_0..15` | Transform `Matrix4` copy from param_2 |
| 0x48 | 4 | `float` | `scaleX` | `AnimNode+0xC0` (lo word of uint64) |
| 0x4C | 4 | `float` | `scaleY` | `AnimNode+0xC4` (hi word of uint64) |
| 0x50 | 4 | `uint` | `facingMode` | `AnimNode+0xB4`; `8` = mirrored/flipped. Checked by `CalculateScaleMatrix` and `DrawCacheRender` |
| 0x54 | 4 | `int` | `billboardType` | `AnimNode+0x124`; `0`=billboard, `1`=Y-axis rotation, else=normal |
| 0x58 | 4 | `float` | `rotation` | `AnimNode+0x128` |
| 0x5C | 4 | `float` | `lightOverride` | `AnimNode+0x12C`; 300.0 = no override sentinel |
| 0x60 | 4 | `float` | `finalOffsetX` | `AnimNode+0x130` |
| 0x64 | 4 | `float` | `finalOffsetY` | `AnimNode+0x134` |
| 0x68 | 4 | `float` | `finalOffsetZ` | `AnimNode+0x138`; used to select effect fallback branch |
| 0x6C | 4 | `float` | `depthFogParam` | `AnimNode+0x104`; controls shader effect selection (0.0 = use cached effect ID) |
| 0x70 | 4 | `undefined4` | `unk_70` | `AnimNode+0x94` |
| 0x74 | 4 | `void*` | `pBuild` | `sBuild*` primary build; `AnimNode+0x98`. Used as default in `GetOverrideBuildForSymbol` |
| 0x78 | 4 | `undefined4` | `unk_78` | `AnimNode+0xB8` |
| 0x7C | 4 | `undefined4` | `unk_7C` | `AnimNode+0xBC` |
| 0x80 | 4 | `undefined4` | `effectFallbackZ0` | `AnimNode+0xCC`; effect ID when `finalOffsetZ==0` and `depthFogParam==0` |
| 0x84 | 4 | `undefined4` | `effectFallbackZN` | `AnimNode+0xD0`; effect ID when `finalOffsetZ!=0` and `depthFogParam==0` |
| 0x88 | 4 | `float` | `effectOverride` | `AnimNode+0xD4`; NaN = use fallback effect ID |
| 0x8C | 4 | `uint` | `dwAddColour` | `AnimNode+0xFC`; packed RGBA additive colour |
| 0x90 | 4 | `uint` | `dwMultColour` | `AnimNode+0x100`; packed RGBA multiply colour |
| 0x94 | 4 | `float` | `unk_94` | `AnimNode+0x108`; passed as shader constant |
| 0x98 | 4 | `void*` | `pAnimNodeRef` | Back-pointer to source `AnimNode` (same as `param_1`) |
| 0x9C | 1 | `byte` | `bDepthWriteEnabled` | `AnimNode+0xF5` (**swapped** from AnimNode field order) |
| 0x9D | 1 | `byte` | `bDepthTestEnabled` | `AnimNode+0xF4` (**swapped** from AnimNode field order) |
| 0x9E | 2 | `byte[2]` | `pad_9E` | Padding |
| 0xA0 | 4 | `float` | `depthBias` | `AnimNode+0xC8` |
| 0xA4 | 4 | `uint` | `vertexDescHandle` | `AnimNode+0xD8`; vertex description handle |
| 0xA8 | 12 | `vector<int>` | `hiddenLayers` | `AnimNode+0xDC` (begin/end/cap ptrs); freed in dtor |
| 0xB4 | 12 | `vector<int>` | `hiddenSymbols` | `AnimNode+0xE8` (begin/end/cap ptrs); freed in dtor |
| 0xC0 | 24 | `_Rb_tree` | `symbolOverrideTree` | `map<cHashedString, AnimNode::sSymbolOverride>`; copied from `AnimNode+0x10C`; freed in dtor |
| — | — | — | `rbTree_comparator` @ 0xC0 | Comparator object (4B) |
| — | — | — | `rbTree_hdr_color` @ 0xC4 | `_M_header._M_color` / sentinel node |
| — | — | — | `rbTree_hdr_parent` @ 0xC8 | `_M_header._M_parent` (root) |
| — | — | — | `rbTree_hdr_left` @ 0xCC | `_M_header._M_left`; points to self when empty |
| — | — | — | `rbTree_hdr_right` @ 0xD0 | `_M_header._M_right`; points to self when empty |
| — | — | — | `rbTree_nodeCount` @ 0xD4 | `_M_node_count`; checked by `GetOverrideBuildForSymbol` |
| 0xD8 | 8 | `int+uint` | `overrideBankHandle1` / `overrideBankHash1` | `AnimNode+0x13C`; handle==-1 means no override. Checked in `DrawCacheRender` inner loop |
| 0xE0 | 8 | `int+uint` | `overrideBankHandle2` / `overrideBankHash2` | `AnimNode+0x144` |
| 0xE8 | 8 | `int+uint` | `overrideSymbolHandle1` / `overrideSymbolHash1` | `AnimNode+0x14C`; symbol frame indices matched against render symbols |
| 0xF0 | 8 | `int+uint` | `overrideSymbolHandle2` / `overrideSymbolHash2` | `AnimNode+0x154` |

### Key Design Notes

1. **`AnimNode+0xF8` (sortOrder, float) is NOT copied** into `TDataCacheAnimNode`. It is used only for render-queue ordering before cache construction, not during actual rendering.

2. **`overrideBankHandle` / `overrideSymbolHandle` pairs** (`+0xD8`–`+0xF7`): initialized to empty `cHashedString` pairs (`{0, mEmptyString}`) in ctor, then overwritten with AnimNode data. The `int` part acts as a handle/index (-1=invalid); the `uint` is the hash for lookup in the inner render loop.

3. **`bDepthWriteEnabled` / `bDepthTestEnabled` field order is swapped** from the AnimNode source:  
   - `AnimNode+0xF4` → TDC+0x9D (`bDepthTestEnabled`)  
   - `AnimNode+0xF5` → TDC+0x9C (`bDepthWriteEnabled`)

4. **`symbolOverrideTree`** (`+0xC0`): `std::map<cHashedString, AnimNode::sSymbolOverride>`. `GetOverrideBuildForSymbol` checks `rbTree_nodeCount` (+0xD4) first; if non-zero, traverses the tree to find a per-symbol build override.

5. **`CalculateScaleMatrix`** reads `this+0x50` (facingMode==8 branch), `in_stack_0000000c` = the input Matrix4, `in_stack_00000010` = the Vector2 scale. Output is an identity-based scale matrix, optionally negated for mirror.

### AnimNode Offset Cross-Reference (partial, from TDataCacheAnimNode ctor)

| AnimNode Offset | Copied To | Semantic |
|-----------------|-----------|---------|
| +0xB4 | TDC+0x50 | facingMode |
| +0xB8/0xBC | TDC+0x78/0x7C | unk |
| +0xC0 | TDC+0x48 | scaleX |
| +0xC4 | TDC+0x4C | scaleY |
| +0xC8 | TDC+0xA0 | depthBias |
| +0xCC/0xD0 | TDC+0x80/0x84 | effectFallback Z0/ZN |
| +0xD4 | TDC+0x88 | effectOverride |
| +0xD8 | TDC+0xA4 | vertexDescHandle |
| +0xDC | TDC+0xA8 | hiddenLayers vector |
| +0xE8 | TDC+0xB4 | hiddenSymbols vector |
| +0xF4 | TDC+0x9D | bDepthTestEnabled |
| +0xF5 | TDC+0x9C | bDepthWriteEnabled |
| +0xFC | TDC+0x8C | dwAddColour |
| +0x100 | TDC+0x90 | dwMultColour |
| +0x104 | TDC+0x6C | depthFogParam |
| +0x108 | TDC+0x94 | unk_94 (shader constant) |
| +0x10C | TDC+0xC0 | symbolOverrideTree |
| +0x124 | TDC+0x54 | billboardType |
| +0x128 | TDC+0x58 | rotation |
| +0x12C | TDC+0x5C | lightOverride |
| +0x130 | TDC+0x60 | finalOffsetX |
| +0x134 | TDC+0x64 | finalOffsetY |
| +0x138 | TDC+0x68 | finalOffsetZ |
| +0x13C | TDC+0xD8 | overrideBankHandle1 / overrideBankHash1 |
| +0x144 | TDC+0xE0 | overrideBankHandle2 / overrideBankHash2 |
| +0x14C | TDC+0xE8 | overrideSymbolHandle1 / overrideSymbolHash1 |
| +0x154 | TDC+0xF0 | overrideSymbolHandle2 / overrideSymbolHash2 |
| **+0xF8** | **NOT COPIED** | **sortOrder (float) — render queue only** |

---

## SceneGraphNode (145 bytes / 0x91)

> Source: `SceneGraphNode::SceneGraphNode` ctors (@ 0x000c53d6, 0x000c5514, 0x000c5542), `SceneGraphNode::~SceneGraphNode` (@ 0x000c563e), `SceneGraphNode::AddChild` (@ 0x000c575c), `SceneGraphNode::SetAABBDirty` (@ 0x000c54d0), `SceneGraphNode::RecalculateAABB` (@ 0x000c5d1c)  
> Created in Ghidra as `SceneGraphNode`.  
> Base class for all scene graph nodes including `AnimNode`.

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | vtable ptr | `vtable` | Points to `PTR_RendersAlpha_004564b8` vtable |
| 0x04 | 2 | `ushort` | `flags` | Init = 0x100 in `(cGame*, cHashedString)` ctor; 0 in no-arg ctor |
| 0x06 | 2 | `ushort` | `pad6` | Padding |
| 0x08 | 64 | 16×`float` | `matrix0`..`matrix15` | World transform matrix (4×4 float, identity init from `PTR_Identity_00450744`) |
| 0x48 | 4 | `uint` | `renderFlags` | Init = 3 |
| 0x4C | 1 | `byte` | `bFlag4C` | Init = 0; exact semantics TBD |
| 0x4D | 1 | `byte` | `pad4D` | Padding |
| 0x4E | 2 | `ushort` | `field4E` | Init = 0 |
| 0x50 | 4 | `pointer` | `pChildren_begin` | `std::vector<SceneGraphNode*>` begin; used by `AddChild`/dtor |
| 0x54 | 4 | `pointer` | `pChildren_end` | `std::vector<SceneGraphNode*>` end |
| 0x58 | 4 | `pointer` | `pChildren_cap` | `std::vector<SceneGraphNode*>` capacity; heap-freed in dtor |
| 0x5A | 2 | `ushort` | `field5A` | Init = 0 |
| 0x5C | 4 | `pointer` | `pGame` | `cGame*`; null in no-arg ctor |
| 0x60 | 4 | `uint` | `nameHash0` | `cHashedString` word 0 (node name); init = 0 |
| 0x64 | 4 | `uint` | `nameHash1` | `cHashedString` word 1 (COW string ptr); init = `mEmptyString` |
| 0x68 | 4 | `pointer` | `pParentNode` | Parent `SceneGraphNode*`; set by `AddChild`, read by `SetAABBDirty` |
| 0x6C | 4 | `uint` | `field6C` | Init = 0 |
| 0x70 | 4 | `float` | `sortDepth` | Init = 5.0f (`0x40A00000`) in `(cGame*, cHashedString)` ctor; 0 in no-arg |
| 0x74 | 4 | `uint` | `field74` | Init = 0 |
| 0x78 | 4 | `float` | `aabb_min_x` | AABB min X; init = `FLT_MAX` (`0x7f7fffff`) |
| 0x7C | 4 | `float` | `aabb_min_y` | AABB min Y |
| 0x80 | 4 | `float` | `aabb_min_z` | AABB min Z |
| 0x84 | 4 | `float` | `aabb_max_x` | AABB max X; init = `-FLT_MAX` (`0xff7fffff`) |
| 0x88 | 4 | `float` | `aabb_max_y` | AABB max Y |
| 0x8C | 4 | `float` | `aabb_max_z` | AABB max Z |
| 0x90 | 1 | `byte` | `bAABBDirty` | Set by `SetAABBDirty`; cleared after recalculation |

**Total size: 145 bytes / 0x91** (+ 3 bytes padding → AnimNode fields start at 0x94)

### QuadTree integration

`SetAABBDirty` also propagates up via `*(QuadTreeNode**)(this+0x68)` (same offset as `pParentNode`; actually the QuadTreeNode parent pointer). When `*(int*)(this+0x6c) != 0` it calls `QuadTreeNode::UpdateQuadTreeForNode` directly.

### Key Functions

| Function | Address | Notes |
|----------|---------|-------|
| ctor (no-arg) | 0x000c53d6 | Initialises all fields; pGame = null |
| ctor (cGame*, cHashedString) | 0x000c5542 | Full init with game ptr and node name |
| dtor | 0x000c563e | Frees children vector heap; removes from parent |
| `AddChild` | 0x000c575c | Appends child; sets child's `pParentNode` |
| `RemoveChild` | 0x000c5810 | |
| `SetAABBDirty` | 0x000c54d0 | Marks AABB dirty and propagates up |
| `RecalculateAABB` | 0x000c5d1c | Rebuilds AABB from children; writes `+0x78..+0x8F` |
| `GetWorldTransform` | 0x000c5974 | Returns matrix at `+0x08..+0x47` |
| `CacheForRender` | 0x000155ac | Builds `TDataCacheAnimNode` snapshot |

---

## AnimNode (~348 bytes / 0x15C)

> Source: `AnimNode::AnimNode` ctor (@ 0x000c0746), `AnimNode::~AnimNode` (@ 0x000c0a6e), `AnimNode::SetAnimInfo`, `AnimNode::GetOverrideBuildForSymbol` (@ 0x000c0f32)  
> Created in Ghidra as `AnimNode`.  
> Inherits from `SceneGraphNode` (first 0x91 bytes). Own fields start at +0x94 (after 3 bytes padding at 0x91..0x93).

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | vtable ptr | `vtable` | Points to `PTR_RendersAlpha_004563b8` vtable |
| 0x00–0x5B | 92 | `SceneGraphNode` | (base) | Base class; not fully mapped |
| 0x5C | 4 | `cGame*` | `pGame` | Back-pointer to game instance (ctor `param_2`) |
| 0x94 | 4 | `AnimationFile*` | `pAnimFile` | Set by `SetAnimInfo` via `AnimManager::GetAnimation` |
| 0x98 | 4 | `sBuild*` | `pBuild` | Set by `SetAnimInfo` via `AnimManager::GetBuild`; used as default in `GetOverrideBuildForSymbol` |
| 0x9C | 4 | `uint` | `bankHash0` | Bank name `cHashedString` word 0 |
| 0xA0 | 4 | COW str ptr | `bankHash1` | Bank name `cHashedString` word 1 (COW string) |
| 0xA4 | 4 | `uint` | `animHash0` | Anim name `cHashedString` word 0 |
| 0xA8 | 4 | COW str ptr | `animHash1` | Anim name `cHashedString` word 1 |
| 0xAC | 4 | `uint` | `buildHash0` | Build name `cHashedString` word 0 |
| 0xB0 | 4 | COW str ptr | `buildHash1` | Build name `cHashedString` word 1 |
| 0xB4 | 4 | `uint` | `facingMode` | `eFacing` enum; init = 8 |
| 0xB8 | 4 | `uint` | `playMode` | `ePlayMode` enum; init = 0 |
| 0xBC | 4 | `float` | `time` | Current playback time; init = 0 |
| 0xC0 | 4 | `float` | `scaleX` | Horizontal scale; init = 1.0f |
| 0xC4 | 4 | `float` | `scaleY` | Vertical scale; init = 1.0f |
| 0xC8 | 4 | `float` | `depthBias` | init = 0 |
| 0xCC | 4 | `uint` | `effectFallbackZ0` | init = 0xFFFFFFFF |
| 0xD0 | 4 | `uint` | `effectFallbackZN` | init = 0xFFFFFFFF |
| 0xD4 | 4 | `float` | `effectOverride` | init = 0xFFFFFFFF (bit-pattern) |
| 0xD8 | 4 | `uint` | `vertexDescHandle` | Renderer vertex description handle; sourced from `game+0x44+0x6C` |
| 0xDC | 12 | `vector<cHashedString>` | `hiddenLayers` | Hidden layer list (begin/end/cap); heap-freed in dtor |
| 0xE8 | 12 | `vector<cHashedString>` | `hiddenSymbols` | Hidden symbol list (begin/end/cap); heap-freed in dtor |
| 0xF4 | 1 | `byte` | `bDepthTestEnabled` | init = 0 |
| 0xF5 | 1 | `byte` | `bDepthWriteEnabled` | init = 0xFF |
| 0xF8 | 4 | `float` | `sortOrder` | Render-queue sort key; **NOT copied to TDataCacheAnimNode** |
| 0xFC | 4 | `uint` | `dwAddColour` | Additive tint; init = Transparent (0) |
| 0x100 | 4 | `uint` | `dwMultColour` | Multiplicative tint; init = White (0xFFFFFFFF) |
| 0x104 | 4 | `float` | `depthFogParam` | init = 0 |
| 0x108 | 4 | `float` | `randSeed` | `rand() % 0x400`; used as shader constant |
| 0x10C | 20 | `std::map<cHashedString,sSymbolOverride>` | `symbolOverride_tree` | Per-symbol build overrides; RbTree header at `+0x10C`, 20 bytes |
| 0x120 | 4 | `int` | `has_overrides` | Non-zero if `symbolOverride_tree` has entries; checked first in `GetOverrideBuildForSymbol` |
| 0x124 | 4 | `int` | `billboardType` | init = 0 |
| 0x128 | 4 | `float` | `rotation` | init = 0 |
| 0x12C | 4 | `float` | `lightOverride` | init = 0 |
| 0x130 | 4 | `float` | `finalOffsetX` | init = 0 |
| 0x134 | 4 | `float` | `finalOffsetY` | init = 0 |
| 0x138 | 4 | `float` | `finalOffsetZ` | init = 0 |
| 0x13C | 8 | `int+uint` | `overrideBankHandle1` / `overrideBankHash1` | init = empty cHashedString; handle = -1 means inactive |
| 0x144 | 8 | `int+uint` | `overrideBankHandle2` / `overrideBankHash2` | init = empty cHashedString |
| 0x14C | 8 | `int+uint` | `overrideSymbolHandle1` / `overrideSymbolHash1` | init = empty cHashedString |
| 0x154 | 8 | `int+uint` | `overrideSymbolHandle2` / `overrideSymbolHash2` | init = empty cHashedString |

**Total observed size**: at least 0x15C (348 bytes), based on the last fields written in ctor.

### sSymbolOverride (node struct in symbolOverride_tree)

Each rb-tree node has the standard `_Rb_tree_node` layout (color + parent + left + right at node+0x00..0x0F), followed by the value:

| Node Offset | Name | Notes |
|-------------|------|-------|
| +0x10 | (std::map value start) | |
| +0x20 | `overrideSymbolHash0` | `cHashedString` key word 0 |
| +0x24 | `overrideSymbolHash1` | `cHashedString` key word 1 |
| +0x28 | `pOverrideBuild` | `sBuild*`; non-null = active override |

### Key Functions

| Function | Address | Notes |
|----------|---------|-------|
| `AnimNode::AnimNode` (ctor) | 0x000c0746 | Initializes all fields above |
| `AnimNode::~AnimNode` | 0x000c0a6e | Frees `hiddenLayers`, `hiddenSymbols`, `symbolOverride_tree` |
| `AnimNode::SetAnimInfo` | — | Sets `pAnimFile` and `pBuild` via AnimManager |
| `AnimNode::GetOverrideBuildForSymbol` | 0x000c0f32 | Returns `sBuildSymbolFrame*` and populates `out_pBuild`; checks `has_overrides` before tree traversal |

---

## AnimationFile (40 bytes / 0x28)

> Source: `AnimationFile::AnimationFile` (ctor @ 0x0012f9dc), `AnimationFile::LoadFile` (@ 0x0012fbc0), `AnimationFile::~AnimationFile` (@ 0x0012fa88)
> Created in Ghidra as `AnimationFile`.

Loads and owns `anim.bin` + `build.bin` for one animation bank. The `pAnimArray` and `pFrameArray` pointers are heap-allocated counted arrays (prefix `uint count` at ptr-4).

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | COW string ptr | `filename_str_ptr` | Bank filename (macOS 32-bit COW std::string) |
| 0x04 | 4 | `sAnim*` | `pAnimArray` | Heap array of `sAnim` entries (stride 0x24). Count prefix at ptr-4 |
| 0x08 | 4 | `sAnimElement*` | `pAnimElemArray` | Heap array of `sAnimElement` entries (stride 0x54). Shared across all frames |
| 0x0C | 4 | `sFrame*` | `pFrameArray` | Heap array of `sFrame` entries (stride 0x28). Count prefix at ptr-4 |
| 0x10 | 4 | `uint*` | `pElemHashArray` | Heap array of element hash pairs (stride 8); count = `numElements` |
| 0x14 | 4 | `uint` | `numElements` | Total element entry count (anim.bin version > 2) |
| 0x18 | 4 | `uint` | `numAnims` | Number of `sAnim` entries |
| 0x1C | 4 | `uint` | `numFrames` | Total number of `sFrame` entries |
| 0x20 | 4 | `uint` | `numAnimElems` | Number of `sAnimElement` entries |
| 0x24 | 4 | `sBuild*` | `pBuild` | Pointer to `sBuild` (loaded from build.bin); freed in dtor |

---

## sAnim (36 bytes / 0x24)

> Source: `sAnim::GetFrame` (@ 0x0012f79c), `AnimationFile::LoadFile` inner loop, `AnimationFile::~AnimationFile`
> Created in Ghidra as `sAnim`.

One animation clip entry inside an `AnimationFile`. Points into the shared `pFrameArray` for its frame slice.

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | `AnimationFile*` | `pParent` | Back-pointer to owning `AnimationFile` |
| 0x04 | 4 | `sFrame*` | `pFrames` | Pointer into `AnimationFile::pFrameArray` for first frame |
| 0x08 | 4 | `float` | `fps` | Frames per second |
| 0x0C | 4 | `uint` | `bankHash0` | cHashedString bank name w0 (used by AnimManager::DoLoad as outer map key) |
| 0x10 | 4 | `uint` | `bankHash1` | cHashedString bank name w1 |
| 0x14 | 4 | `uint` | `numFrames` | Frame count (used by `GetFrame` for clamp/loop/pingpong) |
| 0x18 | 4 | COW string ptr | `name` | Animation name (COW std::string, read via `ReadString`) |
| 0x1C | 1 | `uchar` | `facingByte` | Facing flags; `0xFF` if anim.bin version < 2 |
| 0x1D | 3 | padding | — | Alignment bytes |
| 0x20 | 4 | `float` | `duration` | `numFrames / fps` (computed and stored) |

### PlayMode enum (ePlayMode, param to GetFrame)

| Value | Name | Behaviour |
|-------|------|-----------|
| 0 | `Clamp` | `frame = (int)(t * fps)`, clamped to `[0, numFrames-1]` |
| 1 | `Loop` | `frame = (int)(fmod(t, numFrames/fps) * fps)` |
| 2 | `PingPong` | Reflects at ends; maps `t` to `[0, numFrames-1]` round-trip |

---

## sFrame (40 bytes / 0x28)

> Source: `AnimationFile::LoadFile` frame-reading loop
> Created in Ghidra as `sFrame`.

One frame of an animation clip. Stores a 2-D AABB (bounding box) and slices into the shared element and object arrays.

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | `float` | `bb_min_x` | AABB min X, pivot-adjusted: `x - w*0.5` |
| 0x04 | 4 | `float` | `bb_min_y` | AABB min Y: `y - h*0.5` |
| 0x08 | 4 | `float` | `bb_min_z` | Always 0 |
| 0x0C | 4 | `float` | `bb_max_x` | AABB max X: `(x + w) - w*0.5` |
| 0x10 | 4 | `float` | `bb_max_y` | AABB max Y: `h*0.5 + y` |
| 0x14 | 4 | `float` | `bb_max_z` | Always 0 |
| 0x18 | 4 | `uint*` | `pElements` | Pointer into `AnimationFile::pElemHashArray` for this frame's elements |
| 0x1C | 4 | `uint` | `numElements` | Element count (written only if anim.bin version > 2) |
| 0x20 | 4 | `sAnimElement*` | `pObjects` | Pointer into `AnimationFile::pAnimElemArray` for this frame's objects |
| 0x24 | 4 | `uint` | `numObjects` | Object/element count |

---

## sAnimElement (84 bytes / 0x54)

> Source: `AnimationFile::LoadFile` inner object-writing loop
> Created in Ghidra as `sAnimElement`.

One rendered sprite element within a frame. Stores a 2-D affine transform matrix, two `cHashedString` identifiers, and the build frame index.

The "constants" rows (`+0x20..+0x3F`) are initialised from global constants `DAT_003c7e20` and `DAT_003c7e30` (identity-like 3rd/4th matrix rows, e.g. `{0,0,1,0}` and `{0,0,0,1}`).

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | `float` | `m_a` | Transform: scale×cos (col0, row0) |
| 0x04 | 4 | `float` | `m_c` | Transform: sin (col1, row0) |
| 0x08 | 4 | `float` | `pad08` | Always 0 |
| 0x0C | 4 | `float` | `m_tx` | Translation X |
| 0x10 | 4 | `float` | `m_b` | Transform: -sin (col0, row1) |
| 0x14 | 4 | `float` | `m_d` | Transform: scale×cos (col1, row1) |
| 0x18 | 4 | `float` | `pad18` | Always 0 |
| 0x1C | 4 | `float` | `m_ty` | Translation Y |
| 0x20 | 16 | 4×`uint` | `const20..2C` | Init from `DAT_003c7e20..2C` (row 3 of 4×4 matrix) |
| 0x30 | 16 | 4×`uint` | `const30..3C` | Init from `DAT_003c7e30..3C` (row 4 of 4×4 matrix) |
| 0x40 | 4 | `uint` | `layerHash` | Layer name hash (`cHashedString` word 0) |
| 0x44 | 4 | `uint` | `pad44` | `cHashedString` padding = 0 |
| 0x48 | 4 | `uint` | `symbolHash` | Symbol name hash (`cHashedString` word 0) |
| 0x4C | 4 | `uint` | `pad4C` | `cHashedString` padding = 0 |
| 0x50 | 4 | `uint` | `buildFrame` | Which build frame index to use for texture UV lookup |

---

## sBuild (76 bytes / 0x4C)

> Source: `sBuild::GetFrame` (@ 0x00135956), `sBuild::~sBuild` (@ 0x001359de), `sBuild::ApplyTextures` (@ 0x00135ab8), `AnimationFile::LoadFile` (build.bin section)
> **Note:** Not yet created as a Ghidra struct (the type is a Ghidra class node). Fields documented here are confirmed via multiple functions.

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | `AnimationFile*` | `pParent` | Back-pointer to owning `AnimationFile` |
| 0x04 | 4 | COW string ptr | `name` | Build name (COW std::string, from build.bin) |
| 0x08 | 12 | `std::vector<std::string>` | `textures` | Texture name list (begin/end/cap ptrs) |
| 0x14 | 4 | `uint*` | `pTextureHandles_begin` | Texture handle vector begin |
| 0x18 | 4 | `uint*` | `pTextureHandles_end` | Texture handle vector end |
| 0x20 | 4 | `sBuildSymbolEntry*` | `pSymbols` | Sorted array of symbol entries (each 0x10 bytes, sorted by hash) |
| 0x24 | 4 | `sBuildSymbolFrame*` | `pSymbolFrames` | Array of `sBuildSymbolFrame` entries |
| 0x28 | 4 | VB handle | `vbHandle` | Renderer vertex buffer handle (primary) |
| 0x2C | 4 | VB handle | `vbHandle2` | Renderer VB handle (secondary; only if build.bin version < 5) |
| 0x30 | 4 | `void*` | `pVertexData` | Heap copy of primary VB data |
| 0x34 | 4 | `void*` | `pVertexData2` | Heap copy of secondary VB data |
| 0x38 | 4 | `uint` | `numVerts` | Primary vertex count |
| 0x3C | 4 | `uint` | `numVerts2` | Secondary vertex count (version < 5 only) |
| 0x40 | 4 | `uint` | `numSymbolFrames` | Total `sBuildSymbolFrame` count |
| 0x44 | 4 | `uint` | `numSymbols` | Number of symbol entries |
| 0x48 | 1 | `bool` | `bTexturesLoaded` | Set to `true` after `ApplyTextures` loads all textures |

### sBuildSymbolEntry (0x10 bytes, inline array at pSymbols)

Each entry in the sorted symbol array (binary-searched by hash in `GetFrame`):

| Dword | Name | Notes |
|-------|------|-------|
| [0] | `hashValue` | `cHashedString` hash — sort key |
| [1] | `hashPad` | `cHashedString` padding = 0 |
| [2] | `pFrames` | Pointer to first `sBuildSymbolFrame` for this symbol |
| [3] | `numFrames` | Number of `sBuildSymbolFrame` entries for this symbol |

---

## sBuildSymbolFrame (52 bytes / 0x34)

> Source: `sBuild::GetFrame` (stride `0xd * 4 = 0x34`), `AnimationFile::LoadFile` symbol-frame loop
> Created in Ghidra as `sBuildSymbolFrame`.

One frame entry within a build symbol. Provides the mapping from animation frame index to texture atlas UV and optional bounding box.

`GetFrame` iterates entries with `puVar4 = puVar4 + 0xd` (i.e. +0x34 stride) and returns the first entry where `frameStart <= frameIndex < frameStart + frameCount`.

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | `uint` | `frameStart` | First animation frame index this entry covers |
| 0x04 | 4 | `uint` | `frameCount` | Number of frames covered |
| 0x08 | 4 | `uint` | `vertexStart` | Vertex start index within the VB (1st read from file; used as `Renderer::Draw` start) |
| 0x0C | 4 | `uint` | `vertexCount` | Vertex count for primary VB draw call (`vbHandle`); 0 = skip draw |
| 0x10 | 4 | `uint` | `vertexStart2` | Vertex start for secondary VB (`vbHandle2`; version < 5; init = `0xFFFFFFFF`) |
| 0x14 | 4 | `uint` | `vertexCount2` | Vertex count for secondary VB draw call; 0 = skip draw |
| 0x18 | 4 | `float` | `bb_min_x` | Bounding box min X, pivot-adjusted (written if version > 3) |
| 0x1C | 4 | `float` | `bb_min_y` | Bounding box min Y |
| 0x20 | 4 | `float` | `bb_min_z` | Always 0 |
| 0x24 | 4 | `float` | `bb_max_x` | Bounding box max X |
| 0x28 | 4 | `float` | `bb_max_y` | Bounding box max Y |
| 0x2C | 4 | `float` | `bb_max_z` | Always 0 |
| 0x30 | 4 | `float` | `radius` | `SQRT(dX² + dY²)` — bounding circle radius (version > 3) |

### Initial values (from LoadFile allocation loop)

```c
entry->frameStart   = 0;
entry->frameCount   = 0;
entry->vertexStart  = 0xFFFFFFFF; // invalid
entry->vertexCount  = 0;
entry->vertexStart2 = 0xFFFFFFFF; // invalid
entry->vertexCount2 = 0;
entry->bb_min_x    = -50.0f;  // 0xC2480000
entry->bb_min_y    = -50.0f;
entry->bb_min_z    = 0;
entry->bb_max_x    = 50.0f;   // 0x42480000
entry->bb_max_y    = 50.0f;
entry->bb_max_z    = 0;
entry->radius      = 0;
```

---

### sAnimEntry (44 bytes / 0x2C)

`sAnimEntry` is the value type stored inside each bank's inner `linear_map<cHashedString, sAnimEntry>`. It maps an animation name to up to 8 facing-specific `sAnim*` pointers.

**Source:** `AnimManager::DoLoad` (insertion path) + `AnimManager::GetAnimation` (read path, switch on `eFacing`).

**Ghidra struct:** `sAnimEntry` (44 bytes, 11 fields) ✓

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | uint | `animHash0` | cHashedString key w0 (anim name hash) |
| 0x04 | 4 | uint | `animHash1` | cHashedString key w1 |
| 0x08 | 4 | pointer | `animName` | std::string ptr (COW) — anim name string |
| 0x0C | 4 | pointer | `pAnim_face2` | `sAnim*` for `eFacing==2` |
| 0x10 | 4 | pointer | `pAnim_face1` | `sAnim*` for `eFacing==1` |
| 0x14 | 4 | pointer | `pAnim_face5` | `sAnim*` for `eFacing==5` |
| 0x18 | 4 | pointer | `pAnim_face4` | `sAnim*` for `eFacing==4` |
| 0x1C | 4 | pointer | `pAnim_face0` | `sAnim*` for `eFacing==0 or 8` (default/any) |
| 0x20 | 4 | pointer | `pAnim_face3` | `sAnim*` for `eFacing==3` |
| 0x24 | 4 | pointer | `pAnim_face7` | `sAnim*` for `eFacing==7` |
| 0x28 | 4 | pointer | `pAnim_face6` | `sAnim*` for `eFacing==6` |

`GetAnimation` returns the appropriate `sAnim*` field based on `eFacing` parameter (switch statement). Only facing slots whose bit is set in `sAnim::facingByte` are populated by `DoLoad`.

---

### AnimManager (116 bytes / 0x74)

`AnimManager` is the central registry for all loaded animation banks and builds. It inherits from `cResourceManager<AnimationFile, unsigned int, FakeLock>`.

**Functions analyzed:** `AnimManager::AnimManager` @ 0x00131efe, `AnimManager::~AnimManager` @ 0x00131fd8, `AnimManager::Initialize` @ 0x0013210e, `AnimManager::GetAnimation` @ 0x00132368, `AnimManager::GetBuild` @ 0x00132afc, `AnimManager::DoLoad` @ 0x001324a0, `AnimManager::SetErosionTexture` @ 0x00132e94.

**Ghidra struct:** `AnimManager` (116 bytes, 29 fields) ✓

| Offset | Size | Type | Name | Notes |
|--------|------|------|------|-------|
| 0x00 | 4 | pointer | `vtable` | → `PTR_GetResourceNameType_00456a38` |
| 0x04 | 4 | uint | `base_04` | `cResourceManager` base field |
| 0x08 | 4 | uint | `base_08` | init=0 |
| 0x0C | 4 | uint | `base_0C` | init=0 |
| 0x10 | 4 | uint | `base_10` | init=0 |
| 0x14 | 4 | uint | `pad14` | padding |
| 0x18 | 4 | pointer | `vec_begin` | vector begin (= `this+0x18` when empty) |
| 0x1C | 4 | uint | `field_1C` | init=0 |
| 0x20 | 4 | pointer | `vec_end` | vector end ptr (→ `this+0x18` when empty) |
| 0x24 | 4 | pointer | `vec_cap` | vector capacity ptr |
| 0x28 | 4 | uint | `field_28` | init=0 |
| 0x2C | 4 | uint | `field_2C` | init=0 |
| 0x30 | 4 | uint | `field_30` | init=0 |
| 0x34 | 4 | uint | `field_34` | init=0 |
| 0x38 | 4 | pointer | `strField38` | COW string ptr (empty string init) |
| 0x3C | 4 | pointer | `pRenderer` | `Renderer*` (constructor param) |
| 0x40 | 4 | pointer | `bankMap_begin` | `linear_map<cHashedString, bankInner>` begin |
| 0x44 | 4 | pointer | `bankMap_end` | end sentinel (checked in `GetAnimation` find) |
| 0x48 | 4 | pointer | `bankMap_cap` | capacity |
| 0x4C | 4 | pointer | `buildMap_begin` | `linear_map<cHashedString, sBuild*>` begin |
| 0x50 | 4 | pointer | `buildMap_end` | end sentinel (checked in `GetBuild` find) |
| 0x54 | 4 | uint | `field_54` | init=0 |
| 0x58 | 4 | uint | `hShader_anim` | `shaders/anim.ksh` handle |
| 0x5C | 4 | uint | `hShader_anim_fade` | `shaders/anim_fade.ksh` handle |
| 0x60 | 4 | uint | `hShader_anim_haunted` | `shaders/anim_haunted.ksh` (fallback: `anim.ksh`) |
| 0x64 | 4 | uint | `hShader_bloom` | `shaders/anim_bloom.ksh` (offset=0x64=100) |
| 0x68 | 4 | uint | `hShader_fade_haunted` | `shaders/anim_fade_haunted.ksh` (fallback: `anim_fade.ksh`) |
| 0x6C | 4 | uint | `hVertexDesc` | `VertexDescription` resource handle |
| 0x70 | 4 | uint | `hErosionTexture` | erosion texture handle (init=0xFFFFFFFF = invalid) |

**Data structures inside AnimManager:**

- **Bank map** (`+0x40`): `linear_map<cHashedString, linear_map<cHashedString, sAnimEntry>>` — two-level lookup: bank name → anim name → `sAnimEntry`.
- **Build map** (`+0x4C`): `linear_map<cHashedString, sBuild*>` — build name → `sBuild*`.

**Key flow — `DoLoad`:**

1. Calls `AnimationFile::LoadFile` on a new `AnimationFile` (0x28 bytes).
2. For each `sAnim` in the file, inserts into the bank map using the anim's bank hash (`sAnim+0x0C/+0x10`) as the outer key and anim name hash as the inner key.
3. If the file has a `pBuild`, inserts `sBuild*` into the build map by build name hash.

**Key flow — `GetAnimation(bankHash, animHash, eFacing)`:**

1. `find` in bank map → inner `linear_map<cHashedString, sAnimEntry>`.
2. `find` in inner map by anim hash → `sAnimEntry`.
3. Return `sAnimEntry.pAnim_faceN` for the requested `eFacing` (switch).

**`sAnim` bank hash fields (from `DoLoad` analysis):**

- `sAnim+0x0C` = `bankHash0` — cHashedString w0 of the bank name
- `sAnim+0x10` = `bankHash1` — cHashedString w1 of the bank name

---

## TDataCacheAnimNode::DrawCacheRender — Render Pipeline

> Source: `TDataCacheAnimNode::DrawCacheRender` @ 0x000c156a (macOS DS 32-bit)  
> Signature: `void DrawCacheRender(GameRenderer* renderer, Camera const& camera, TRenderCache* cache)`  
> Caller: render queue dispatch after `CacheForRender` snapshot is taken.

This is the core per-entity rendering function. It iterates over every `sAnimElement` in the current animation frame and emits one or two `Renderer::Draw` calls per visible element using the pre-built vertex buffers in `sBuild`.

---

### Phase 1 — Frame Selection

```c
sFrame* pFrame = sAnim::GetFrame(animNode->pAnim, playMode, time);
if (!pFrame) return;  // animation not active
```

Calls `sAnim::GetFrame` with `(playMode, time)` to get the current `sFrame*`. If null, aborts rendering.

---

### Phase 2 — Transform Matrix

`TDataCacheAnimNode::CalculateScaleMatrix` constructs a local scale+flip matrix from `TDC::scaleX`, `TDC::scaleY`, and the world transform matrix. Three branches:

| Condition | Matrix source |
|-----------|---------------|
| `GameRenderer+0x50 == 8` (billboard facing mode 8) | Use scale matrix as-is (no billboard) |
| `GameRenderer+0x54 == 0` (billboard type 0) | Build billboard from camera view matrix via `KleiMath::BuildBillboard`, then `operator*` |
| `GameRenderer+0x54 == 1` (cylindrical billboard) | Build XY rotation matrices, multiply together |

The resulting matrix is stored in a stack local `Matrix4 finalMatrix`.

---

### Phase 3 — Global Shader Setup (once per node)

Executed once for the whole `TDataCacheAnimNode`:

1. **Erosion texture** (`Renderer::SetTexture`) — bound to slot 0 via `AnimManager::hErosionTexture` (AnimManager@0x70).
2. **Texture state / filter** (`Renderer::SetTextureState`, `Renderer::SetTextureFilter`).
3. **Colour constants** — `dwAddColour` (`TDC+0x8C`) and `dwMultColour` (`TDC+0x90`) are unpacked from RGBA bytes to float `[0..1]` vectors using SSE `divps` and pushed as `AutoShaderConstant` uploads.
4. **Depth-fog / offset** — uploaded as shader constants (4-component float4 vectors).
5. **Effect shader selection** — reads `Camera+0x7C4` (is_haunted flag) and `TDC+0x88` (effectOverride) to select among `hShader_anim`, `hShader_anim_haunted`, `hShader_anim_fade`, or `hShader_bloom` via `Renderer::SetEffect`.
6. **Blend mode** — `Renderer::SetBlendMode`.
7. **Depth bias** — `Renderer::SetDepthBias` (only if `TDC+0x9C/0x9D` non-zero).
8. **Vertex description** — `Renderer::SetVertexDescription(TDC::vertexDescHandle)`.

---

### Phase 4 — Pass Loop

The outer loop iterates over passes (stencil passes). There are 1 or 2 passes:

| Pass index | Mode | Notes |
|---|---|---|
| 0 | Normal render | `EnableColourWrite(false)`, `EnableDepthWrite(false)`, `EnableStencilWrite(true)` — stencil mask write |
| 1 | Colour render | `EnableColourWrite(true)`, `EnableDepthWrite(false)`, `EnableStencilWrite(false)` — actual colour draw |

Pass count = 2 if `bDepthWriteEnabled == 0xFF` (default), else 1.

Per-pass setup:
- **Rotation matrix** via `KleiMath::BuildYRotation(TDC::rotation)` and `operator*` with `finalMatrix`.
- **Stencil func** set via `Renderer::SetStencilFunc` at pass boundaries.
- **Depth func** override if `TDC::bDepthTestEnabled` is set.
- **Model matrix** uploaded as `AutoShaderConstant`.

---

### Phase 5 — Hidden Layers / Symbols Pre-processing

Before iterating elements, if `TDC::hiddenLayers` or `TDC::hiddenSymbols` vectors are non-empty, the function scans the `sFrame::numObjects` elements to pre-compute visibility indices into per-override-slot locals (`fVar_1b`, `fVar_19`, `fVar_1a`, `fVar_14`, `fVar_16`, `fVar_13`). These map override bank/symbol handles (`TDC+0xD8..0xF7`) to element indices for fast skip/substitution in the inner loop.

Specifically:
- `TDC+0xD8` (`overrideBankHandle1`) and `TDC+0xE8` (`overrideSymbolHandle1/2`) are compared against each `sAnimElement::layerHash` and `symbolHash` to find the override slots.

---

### Phase 6 — Element Inner Loop

Main per-element loop iterates `sFrame::numObjects` times:

```c
for (int i = 0; i < pFrame->numObjects; i++) {
    sAnimElement* elem = &pFrame->pObjects[i];
    // hidden layer/symbol skip logic here
    // get override build for this symbol
    sBuildSymbolFrame* pSBSF;
    sBuild* pBuild;
    GetOverrideBuildForSymbol(elem->symbolHash, elem->buildFrame, &pBuild, &pSBSF);
    if (!pSBSF) continue;  // symbol not in build
    // ApplyTextures if new build
    if (pBuild != lastBuild) {
        sBuild::ApplyTextures(pBuild, renderer, ...);
        lastBuild = pBuild;
    }
    // Build element transform matrix
    // = perPassMatrix * elemMatrix (from sAnimElement m_a/m_b/m_c/m_d/m_tx/m_ty)
    Matrix4 elemFinal = perPassMatrix * elemAffine;
    // Upload as shader constant
    AutoShaderConstant::AutoShaderConstant(elemFinal, ...);
    // Draw primary VB
    if (pBuild->vbHandle2 != -1 && pSBSF->vertexCount2 != 0) {
        Renderer::SetVertexBuffer(pBuild->vbHandle2);
        Renderer::Draw(pSBSF->vertexStart2, pSBSF->vertexCount2, TRIANGLES);
    }
    // Draw secondary VB
    if (pBuild->vbHandle != -1 && pSBSF->vertexCount != 0) {
        Renderer::SetVertexBuffer(pBuild->vbHandle);
        Renderer::Draw(pSBSF->vertexStart, pSBSF->vertexCount, TRIANGLES);
    }
    AutoShaderConstant::~AutoShaderConstant();
}
```

Key observations:
- **Per-element `GetOverrideBuildForSymbol`** checks symbol override tree; falls back to `TDC::pBuild`.
- **`ApplyTextures`** called lazily — only when build pointer changes (tracked in `lastBuild` local). This avoids redundant texture rebinding.
- **`AutoShaderConstant`** is a RAII wrapper that uploads a constant to the shader and restores the previous value in dtor. Used for per-element model matrix and colour.
- **Draw order**: secondary VB (`vbHandle2`) drawn *before* primary (`vbHandle`). This matches the "underlay" pass pattern (e.g., bloom layer drawn first).
- `Renderer::Draw` signature: `(Renderer*, PrimitiveType, uint start, uint count, VertexBuffer*)`.

---

### Phase 7 — Post-Pass Cleanup

After all elements in a pass:
- Restore depth func (`Renderer::SetDepthFunc` with original func).
- Destroy pass-level `AutoShaderConstant`.

After all passes:
- Restore stencil func to default.
- Re-enable colour write (`Renderer::EnableColourWrite(true)`).
- Destroy all global `AutoShaderConstant` objects (6 destructor calls for the constants set in Phase 3).

---

### Key `TDataCacheAnimNode` Fields Used in DrawCacheRender

| TDC Offset | Name | Usage in DrawCacheRender |
|---|---|---|
| +0x04 | `pAnimNode` | Accessed for pass/override metadata |
| +0x48 | `scaleX` | Input to `CalculateScaleMatrix` |
| +0x4C | `scaleY` | Input to `CalculateScaleMatrix` |
| +0x50 | `facingMode` | Selects billboard branch |
| +0x54 | `billboardType` | 0=full billboard, 1=cylindrical |
| +0x58 | `rotation` | `BuildYRotation` per-pass |
| +0x6C | `depthFogParam` | Shader constant upload |
| +0x60/64/68 | `finalOffset X/Y/Z` | Shader constant (position offset) |
| +0x74 | `pBuild` | Default `sBuild*` (= `AnimNode::pBuild`) |
| +0x8C | `dwAddColour` | Additive colour constant |
| +0x90 | `dwMultColour` | Multiplicative colour constant |
| +0x9C | `bDepthWriteEnabled` | Controls pass count and `EnableDepthWrite` |
| +0x9D | `bDepthTestEnabled` | Controls `SetDepthFunc` override |
| +0xA0 | `depthBias` | `Renderer::SetDepthBias` |
| +0xA4 | `vertexDescHandle` | `Renderer::SetVertexDescription` |
| +0xA8 | `hiddenLayers` | Vector of hidden layer hashes |
| +0xB4 | `hiddenSymbols` | Vector of hidden symbol hashes |
| +0xC0 | `symbolOverrideTree` | Per-symbol build override rb-tree |
| +0xD8..0xF7 | `overrideBankHandle1/2`, `overrideSymbolHandle1/2` | Element override slot matching |

---

## Renderer Class Hierarchy

```
BaseRenderer  (empty base)
└── HWRenderer  (empty inheritance)
    └── Renderer  (0x234 bytes)
        └── GameRenderer  (0x7E8 bytes)
```

---

### BatchVertex (24 bytes / 0x18)

> `BatchVertex` — single vertex in the UI/2D batcher's dynamic vertex buffer.

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x00 | 4 | float | x | position X |
| +0x04 | 4 | float | y | position Y |
| +0x08 | 4 | float | z | position Z |
| +0x0C | 4 | float | u | texture coord U |
| +0x10 | 4 | float | v | texture coord V |
| +0x14 | 4 | uint  | color | packed RGBA8 |

Vertex description: slot0=pos(xyz float×3), slot1=uv(float×2), slot10=color(RGBA8).

---

### Batcher (68 bytes / 0x44)

> `Batcher` — UI/sprite 2D quad batcher. Collects `BatchVertex` quads and flushes when state changes.
>
> Source: `Batcher::Batcher` @ 0x000a7fd0, `Batcher::Flush` @ 0x000a81ca

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x00 | 4 | uint (GameRenderer*) | pRenderer | owning renderer |
| +0x04 | 4 | uint | texHandle0 | bound texture slot 0, init=0xFFFFFFFF |
| +0x08 | 4 | uint | texHandle1 | bound texture slot 1, init=0xFFFFFFFF |
| +0x0C | 4 | uint | texHandle2 | bound texture slot 2, init=0xFFFFFFFF |
| +0x10 | 4 | uint | vertDescHandle | vertex description resource handle |
| +0x14 | 4 | uint | blendMode | current blend mode, default=3 |
| +0x18 | 4 | uint | effectHandle | current effect handle, init=0xFFFFFFFF |
| +0x1C | 4 | float | alphaMin | alpha range min, default=0.0 |
| +0x20 | 4 | float | alphaMax | alpha range max, default=1.0 |
| +0x24 | 4 | float | effectParam0 | shader effect param Vector4[0] |
| +0x28 | 4 | float | effectParam1 | shader effect param Vector4[1] |
| +0x2C | 4 | float | effectParam2 | shader effect param Vector4[2] |
| +0x30 | 4 | float | effectParam3 | shader effect param Vector4[3] |
| +0x34 | 1 | byte  | hasEffectParams | 1=upload effectParam0..3 to shader in Flush |
| +0x35 | 3 | byte[3] | _pad35 | alignment padding |
| +0x38 | 4 | uint (BatchVertex*) | pVertBegin | vertex vector begin |
| +0x3C | 4 | uint (BatchVertex*) | pVertEnd | vertex vector end |
| +0x40 | 4 | uint (BatchVertex*) | pVertCap | vertex vector capacity |

**State-change methods** (each calls `Flush` if state differs):
- `Batcher::SetTexture` @ 0x000a8562
- `Batcher::SetBlendMode` @ 0x000a858e
- `Batcher::SetAlphaRange` @ 0x000a85b0
- `Batcher::SetEffect` @ 0x000a85ec
- `Batcher::SetEffectParams` @ 0x000a860e

**`Flush` logic summary:**
1. Guard: `pVertEnd == pVertBegin` → early-out.
2. `Renderer::SetEffect`, `SetVertexDescription`, `SetTexture`×3, `SetBlendMode`.
3. `Renderer::CreateVB` (transient VB from vertex array).
4. `GameRenderer::GetMatrix(1)` × `GetMatrix(0)` → MVP matrix → `PushShaderConstantHash`.
5. If `hasEffectParams`: additional `PushShaderConstantHash` for effect params.
6. `Renderer::SetVertexBuffer` + `Renderer::Draw`.
7. Release VB, `PopShaderConstantHash`, reset `pVertEnd = pVertBegin`.

---

### UIRenderAssetManager (32 bytes / 0x20)

> Owned by `GameRenderer+0x7BC`. Holds shared UI/anim shader handles and the `Batcher`.
>
> Source: `UIRenderAssetManager::UIRenderAssetManager` @ 0x000bcd15

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x00 | 4 | uint | vtable | |
| +0x04 | 4 | uint (GameRenderer*) | pRenderer | owning renderer |
| +0x08 | 4 | uint | vertDescHandle | pos+uv+color vertex description |
| +0x0C | 4 | uint | effectHandle_ui | `shaders/ui.ksh` |
| +0x10 | 4 | uint | effectHandle_yuv | `shaders/ui_yuv.ksh` |
| +0x14 | 4 | uint | effectHandle_anim | `shaders/ui_anim.ksh` |
| +0x18 | 4 | uint | vbHandle | pre-built UI VB |
| +0x1C | 4 | uint (Batcher*) | pBatcher | `new Batcher(pRenderer)` |

---

### AutoShaderConstant (9 bytes)

> RAII guard: pushes a shader constant in ctor, pops in dtor.
> Used throughout `DrawCacheRender` for per-element model matrix and colour.
>
> Source: ctor1 @ 0x001d500e, ctor2 @ 0x001d50a8, dtor @ 0x001d5164

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x00 | 4 | uint | dataOrType | ctor1: `Matrix4*`; ctor2: `ShaderConstant::Type` enum |
| +0x04 | 4 | uint (Renderer*) | pRenderer | owning renderer |
| +0x08 | 1 | byte | bPushed | 1 = pushed on construction → dtor calls Pop |

**Condition enum:**

| Value | Meaning |
|-------|---------|
| 0 | Always — push unconditionally |
| 1 | Never — skip push |
| 2 | ConditionCheckStack — compare with stack top; reuse if identical (float array overload only) |

**Relation to Renderer:**
- Push writes to `Renderer+0x184` (`pShaderConstantSet`).
- `Renderer+0x188` (`shaderPushCount`) incremented on each push.

---

### StencilState (28 bytes / 0x1C)

> `StencilState` — front-face or back-face stencil parameters inside `RenderState`.

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x00 | 4 | uint | compareFunc | stencil comparison function |
| +0x04 | 4 | uint | failOp | stencil fail action |
| +0x08 | 4 | uint | depthFailOp | stencil-pass / depth-fail action |
| +0x0C | 4 | uint | passOp | stencil-pass / depth-pass action |
| +0x10 | 4 | uint | ref | stencil reference value |
| +0x14 | 4 | uint | mask | stencil read/write mask |
| +0x18 | 1 | byte | dirty_op | ops dirty flag |
| +0x19 | 1 | byte | dirty_func | func dirty flag |
| +0x1A | 2 | byte[2] | _pad | alignment |

---

### TextureStage (24 bytes / 0x18)

> Per-texture-unit state stored in `RenderState::texStages[8]`.

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x00 | 4 | uint | filterMin | minification filter |
| +0x04 | 4 | uint | filterMag | magnification filter |
| +0x08 | 4 | uint | blendOp | blend operation |
| +0x0C | 4 | uint | combineRGB | RGB combine mode |
| +0x10 | 4 | uint | wrapMode | texture wrap mode |
| +0x14 | 4 | uint | field_14 | |

---

### Matrix4 (64 bytes / 0x40)

> Column-major 4×4 float matrix. 18 instances stored inside `GameRenderer`.

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x00 | 64 | float[16] | m | 4×4 column-major matrix data |

---

### RenderState (372 bytes / 0x174)

> Full GPU render state snapshot embedded inside `Renderer` at +0x10.
>
> Source: `RenderState::RenderState` @ 0x001db33a

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x00 | 68 | byte[68] | field_00 | misc state bytes |
| +0x44 | 192 | TextureStage[8] | texStages | 8 texture unit states |
| +0x104 | 12 | byte[12] | field_104 | |
| +0x110 | 1 | byte | alphaBlendSrc | alpha blend source factor |
| +0x111 | 1 | byte | alphaBlendDst | alpha blend destination factor |
| +0x112 | 1 | byte | alphaTestEnable | alpha test enable flag |
| +0x113 | 1 | byte | alphaRef | alpha test reference, init=0xFF |
| +0x114 | 4 | uint | activeTexUnit | active texture unit index |
| +0x118 | 12 | byte[12] | field_118 | |
| +0x124 | 1 | byte | depthWrite | depth write enable, init=1 |
| +0x125 | 1 | byte | depthTest | depth test enable, init=0 |
| +0x126 | 2 | byte[2] | _pad126 | alignment |
| +0x128 | 4 | uint | depthFunc | depth comparison func, init=8 |
| +0x12C | 4 | uint | field_12C | |
| +0x130 | 1 | byte | stencilEnable | front stencil enable |
| +0x131 | 1 | byte | stencilEnableBack | back stencil enable |
| +0x132 | 2 | byte[2] | _pad132 | alignment |
| +0x134 | 4 | uint | stencilRef | |
| +0x138 | 4 | uint | stencilMask | |
| +0x13C | 28 | StencilState | stencilFront | front-face stencil |
| +0x158 | 28 | StencilState | stencilBack | back-face stencil |

---

### CommandBuffer (120 bytes / 0x78)

> `RenderBuffer::CommandBuffer` — embedded in `Renderer` at +0x1BC.
>
> Source: `CommandBuffer::CommandBuffer` @ 0x001d3a0a

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x00 | 4 | uint | cmdVec0_begin | command vector 0 begin |
| +0x04 | 4 | uint | cmdVec0_end | command vector 0 end |
| +0x08 | 4 | uint | cmdVec0_cap | command vector 0 capacity |
| +0x0C | 4 | uint | cmdVec1_begin | command vector 1 begin |
| +0x10 | 4 | uint | cmdVec1_end | command vector 1 end |
| +0x14 | 4 | uint | cmdVec1_cap | command vector 1 capacity |
| +0x18 | 4 | uint | field_18 | |
| +0x1C | 4 | uint | field_1C | |
| +0x20 | 4 | uint | field_20 | init=0 |
| +0x24 | 4 | uint | field_24 | init=0xFFFFFFFF |
| +0x28 | 4 | uint | pSelf | self-pointer |
| +0x2C | 4 | uint | field_2C | |
| +0x30 | 64 | byte[64] | mutex | `pthread_mutex_t`-equivalent |
| +0x70 | 4 | uint | field_70 | init=0 |
| +0x74 | 4 | uint | capacity | init from ctor param |

---

### Renderer (564 bytes / 0x234)

> `Renderer` — base hardware renderer. `GameRenderer` inherits from this at +0x000.
>
> Source: `Renderer::Renderer` @ 0x001d415a

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x000 | 4 | uint | vtable | `&PTR__Renderer_00457948` |
| +0x004 | 4 | uint | dwField_04 | |
| +0x008 | 4 | uint | dwField_08 | |
| +0x00C | 1 | byte | bField_0C | |
| +0x00D | 3 | byte[3] | _pad0D | alignment |
| +0x010 | 372 | RenderState | renderState | full GPU state snapshot |
| +0x184 | 4 | uint (ShaderConstantSet*) | pShaderConstantSet | shader constant stack |
| +0x188 | 4 | uint | shaderPushCount | push counter incremented per `AutoShaderConstant` push |
| +0x18C | 4 | uint | pResManager | resource manager pointer |
| +0x190 | 4 | uint | vertDescMgr | vertex description manager |
| +0x194 | 4 | uint | dwField_194 | |
| +0x198 | 4 | uint | dwField_198 | |
| +0x19C | 4 | uint | dwField_19C | |
| +0x1A0 | 4 | uint | dwField_1A0 | |
| +0x1A4 | 4 | uint | dwField_1A4 | |
| +0x1A8 | 8 | byte[8] | _gap1A8 | |
| +0x1B0 | 4 | uint | dwField_1B0 | |
| +0x1B4 | 4 | uint (Renderer*) | dwListSentinel | self-referential linked-list sentinel |
| +0x1B8 | 4 | uint (Renderer*) | dwListNext | next renderer in list |
| +0x1BC | 120 | CommandBuffer | cmdBuf | render command buffer |

---

### GameRenderer (2024 bytes / 0x7E8)

> `GameRenderer` — main game renderer; extends `Renderer`. Holds 18 transform matrix slots, UI render manager, and erosion effect state.
>
> Source: `GameRenderer::GameRenderer` @ 0x000b31ec

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x000 | 564 | Renderer | base | inherited Renderer |
| +0x234 | 1152 | Matrix4[18] | matrices | 18 transform matrices (Model, View, Proj, etc.) |
| +0x6B4 | 72 | uint[18] | pMatrices | pointer array; index `i` → `this + i*4 + stack_layer*8 + 0x6B4` |
| +0x6FC | 72 | byte[72] | _pad6FC | padding / reserved |
| +0x744 | 4 | uint | field_744 | init=0 |
| +0x748 | 32 | byte[32] | _gap748 | |
| +0x768 | 4 | uint | field_768 | init=0 |
| +0x76C | 32 | byte[32] | _gap76C | |
| +0x78C | 4 | uint | ptr78C | obj ptr, dtor released |
| +0x790 | 4 | uint | ptr790 | obj ptr |
| +0x794 | 4 | uint | ptr794 | obj ptr |
| +0x798 | 4 | uint | ptr798 | obj ptr |
| +0x79C | 4 | uint | ptr79C | obj ptr |
| +0x7A0 | 4 | uint | ptr7A0 | obj ptr, dtor released |
| +0x7A4 | 4 | uint | ptr7A4 | obj ptr |
| +0x7A8 | 4 | uint | ptr7A8 | obj ptr, dtor released |
| +0x7AC | 4 | uint | ptr7AC | obj ptr |
| +0x7B0 | 4 | uint | ptr7B0 | obj ptr, dtor released |
| +0x7B4 | 4 | uint | ptr7B4 | init=0 |
| +0x7B8 | 4 | uint | ptr7B8 | init=0 |
| +0x7BC | 4 | uint (UIRenderAssetManager*) | pUIRenderMgr | UI asset manager (holds Batcher at +0x1C) |
| +0x7C0 | 4 | uint (cGame*) | pGame | owning game object (ctor param) |
| +0x7C4 | 4 | uint | erosionMode | 2=default, 1=camera erosion |
| +0x7C8 | 4 | uint | effectH_7C8 | init=0xFFFFFFFF |
| +0x7CC | 4 | uint | effectH_7CC | init=0xFFFFFFFF |
| +0x7D0 | 4 | byte[4] | _gap7D0 | |
| +0x7D4 | 4 | uint | effectH_7D4 | init=0xFFFFFFFF |
| +0x7D8 | 4 | uint | effectH_7D8 | init=0xFFFFFFFF |
| +0x7DC | 4 | uint | effectH_7DC | init=0xFFFFFFFF |
| +0x7E0 | 4 | byte[4] | _gap7E0 | |
| +0x7E4 | 4 | uint | effectH_7E4 | init=0xFFFFFFFF |

**`GetMatrix` formula:** `GetMatrix(type)` = `*(this + type*4 + stack_layer*8 + 0x6B4)`

