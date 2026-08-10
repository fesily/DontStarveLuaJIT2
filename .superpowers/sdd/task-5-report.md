# Task 5 Report: Split VmSwitch + ReplaceLuaModule + GameDbgExports; delete residual GameLua.cpp

**Status:** DONE_WITH_CONCERNS  
**Branch:** `feature/core-vm-module-split`  
**Worktree:** `C:/Users/fesil/DontStarveLuaJIT2/.worktrees/core-vm-module-split`  
**Date:** 2026-08-10

---

## What changed

| Path | Action |
|------|--------|
| `game/VmSwitch.cpp` | **Created** — coordinator, `GetContextForType` / `GetDefaultModuleName`, Request/Apply/Reinitialize, CreateState markers, `DS_LUAJIT_set_vm_type` / `get_vm_type_name` |
| `game/ReplaceLuaModule.cpp` | **Created** — `ReplaceLuaModule` only (behavior unchanged; degrade is Task 6) |
| `game/GameDbgExports.cpp` | **Created** — full `EXPORT_GAME_LUA_API` / `GameDbg_*` block |
| `GameLua.cpp` | **Deleted** — no residual root TU |
| `CMakeLists.txt` | **Modified** — final `PLUGIN_CORE_VM_GAME_SOURCES` (no `GameLua.cpp`) |
| `game/GameLuaInternal.hpp` | **Modified** — comments point at new definition homes |
| `GameLua.def` | **Unchanged path** (root) — still appended on MSVC to reduce churn |

### Layout after Task 5

```
plugin_core_vm/
  GameLua.hpp                 # re-export
  GameLua.def                 # MSVC export rename (kept at root)
  game/
    GameLuaContext.hpp
    GameLuaInternal.hpp
    GameLuaContextImpl.hpp
    GameLuaContext.cpp
    GameLuaContextLua51.hpp / .cpp
    GameLuaContextJit.cpp
    GameLuaContextGame.cpp
    VmSwitch.cpp
    ReplaceLuaModule.cpp
    GameDbgExports.cpp
```

### CMake (final)

```cmake
set(PLUGIN_CORE_VM_GAME_SOURCES
    game/GameLuaContext.cpp
    game/GameLuaContextGame.cpp
    game/GameLuaContextJit.cpp
    game/GameLuaContextLua51.cpp
    game/VmSwitch.cpp
    game/ReplaceLuaModule.cpp
    game/GameDbgExports.cpp
)
```

MSVC still: `list(APPEND PLUGIN_CORE_VM_SOURCES GameLua.def)`.

### Key design points

1. **VmSwitch owns lifecycle + public set_vm_type APIs** — same anonymous `VmSwitchCoordinator` + `ApplyPendingVmType` co-location as before.
2. **ReplaceLuaModule remains global** (declared in `GameLuaContext.hpp`); uses `NoteGameLuaExport*` + `RequestVmType` / `ReinitializeCurrentVm` / `CacheRuntimeSetup`.
3. **GameDbg exports keep `EXPORT_GAME_LUA_API` macros** and `GameLua.def` coupling; no path move of the `.def`.
4. **No behavior change** for Replace/Reinitialize (Task 6 owns degrade-to-game).
5. **`ReplaceLuaApi`** remains declared in the public header with no definition (pre-existing; not introduced here).

---

## Verification

### Residual file check

```text
test ! -f .../plugin_core_vm/GameLua.cpp  → PASS (deleted)
```

### Full target build / dumpbin

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target plugin_core_vm -j 8
dumpbin /exports .../plugin_core_vm.dll | findstr ...
```

**Result:** Worktree configure still incomplete (ANGLE / spirv-tools class of env limit as Tasks 2–4). No full `plugin_core_vm.dll` link in this worktree; dumpbin not run on a new DLL.

### Compile proof (accepted substitute)

Reused **main** tree `compile_commands.json` flags for `plugin_core_vm` (Debug), retargeted `-I` and sources to this worktree. Compiled the three new TUs with MSVC `cl /c`:

| TU | Object | Result |
|----|--------|--------|
| `game/VmSwitch.cpp` | `_verify_VmSwitch.obj` | OK |
| `game/ReplaceLuaModule.cpp` | `_verify_Replace.obj` | OK |
| `game/GameDbgExports.cpp` | `_verify_Dbg.obj` | OK |

Only pre-existing `LUA_GCCYCLE` macro redefinition warning from luajit headers. **No C/C++ errors.**  
Temporary `_verify_out/` removed after proof (not committed).

### Static checks

- Exactly one definition each: `RequestVmType`, `ApplyVmType`, `ReinitializeCurrentVm`, `CreateLuaStateForCurrentVm`, `ReplaceLuaModule`, `vmSwitchCoordinator`, `EXPORT_GAME_LUA_API` macro block, `GameDbg_lua_getinfo`.
- `DS_LUAJIT_set_vm_type` definition in `VmSwitch.cpp`; forward decl only in `GameLuaModule.cpp`.
- Root `GameLua.cpp` absent; CMake game list has no `GameLua.cpp`.
- `GameLua.def` still referenced from CMake root path.

---

## Self-review

| Check | Result |
|-------|--------|
| Three new game/ TUs | Pass |
| Root `GameLua.cpp` deleted | Pass |
| Final CMake game sources | Pass |
| `GameLua.def` path kept | Pass |
| EXPORT / set_vm_type coupling preserved | Pass |
| Replace/Reinitialize behavior unchanged | Pass (move only) |
| No main checkout edits | Pass |

**Concerns**

1. No full `plugin_core_vm` link / dumpbin in worktree (ANGLE/configure). Per-TU `cl /c` only.
2. `ReplaceLuaApi` still declared without a definition anywhere (pre-existing).
3. VmSwitch.cpp still carries some includes inherited from the monolith that are only lightly used; left as-is for safe move (not a cleanup pass).

---

## Commit

```
refactor(core.vm): finish game/ TU split; remove monolithic GameLua.cpp
```

Staged: new `game/{VmSwitch,ReplaceLuaModule,GameDbgExports}.cpp`, deleted `GameLua.cpp`, `CMakeLists.txt`, `GameLuaInternal.hpp` comments.

---

## Follow-ups (Task 6)

- Degrade-to-game behavior changes for Replace/Reinitialize (keep Task 5 move semantics until then).
- Optional: demote or co-locate `NoteGameLuaExport*` with Replace if desired.
