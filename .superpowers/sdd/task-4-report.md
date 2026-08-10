# Task 4 Report: Split GameLua contexts into game/* TUs

**Status:** DONE_WITH_CONCERNS  
**Branch:** `feature/core-vm-module-split`  
**Worktree:** `C:/Users/fesil/DontStarveLuaJIT2/.worktrees/core-vm-module-split`  
**Date:** 2026-08-10

---

## What changed

| Path | Action |
|------|--------|
| `game/GameLuaContextImpl.hpp` | **Created** — full `GameLuaContextImpl` + shared helpers decls (`LuaStackGuard`, framework, macros) |
| `game/GameLuaContext.cpp` | **Created** — GAME_IO detail helpers, framework, library names, `currentCtx`, `GetGameLuaContext`, `ds_core_vm_get_game_lua_context`, `wrapper_game_main_buffer` |
| `game/GameLuaContextLua51.hpp` | **Created** — `GameLua51Context` (needed as base for Game context TU) |
| `game/GameLuaContextLua51.cpp` | **Created** — `gameLua51Ctx` + `ctx_lua51()` |
| `game/GameLuaContextJit.cpp` | **Created** — `GameLuaContextJit`, **both** `gameLuajitCtx` / `gameLuajitGenCtx`, `ctx_jit` / `ctx_jit_gen`, out-of-line `LoadMyLuaApi` |
| `game/GameLuaContextGame.cpp` | **Created** — `GameLuaContextGame`, `gameLuaGameCtx`, `ctx_game`, `NoteGameLuaExport*`, `GameFindExportByName` |
| `game/GameLuaInternal.hpp` | **Modified** — Default* library name decls + NoteGame export helpers; Impl forward comment |
| `GameLua.cpp` | **Modified** — residual VmSwitch + Replace + GameDbg only; contexts removed |
| `CMakeLists.txt` | **Modified** — `PLUGIN_CORE_VM_GAME_SOURCES` lists four new game/*.cpp |

### Layout after Task 4

```
plugin_core_vm/
  GameLua.cpp                 # VmSwitch, ReplaceLuaModule, GameDbg_* (Task 5)
  game/
    GameLuaContext.hpp        # public types (Task 2)
    GameLuaInternal.hpp       # detail helpers (Task 3 + Task 4 decls)
    GameLuaContextImpl.hpp    # base impl complete type
    GameLuaContext.cpp
    GameLuaContextLua51.hpp / .cpp
    GameLuaContextJit.cpp     # jit + jit_gen share one class, two static instances
    GameLuaContextGame.cpp
```

### Key design points

1. **jit / jit_gen share implementation** — single `GameLuaContextJit` type, two static instances + `ctx_jit` / `ctx_jit_gen`.
2. **`GetGameLuaContext`** uses `ctx_jit()` instead of a same-TU static, so it can live in `GameLuaContext.cpp`.
3. **`ReplaceLuaModule`** (still in `GameLua.cpp`) records game exports via `NoteGameLuaExport` / `NoteGameLuaExportsForDebugSymbols` so it does not need the `GameLuaContextGame` complete type yet.
4. **`GameLua51Context` header** — required because `GameLuaContextGame` inherits it across TUs.
5. Framework embed include path: `#include "../GameLuaInjectFramework.c"` from `game/GameLuaContext.cpp`.

### CMake

```cmake
set(PLUGIN_CORE_VM_GAME_SOURCES
    GameLua.cpp
    game/GameLuaContext.cpp
    game/GameLuaContextGame.cpp
    game/GameLuaContextJit.cpp
    game/GameLuaContextLua51.cpp
)
```

---

## Verification

### Full target build

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target plugin_core_vm -j 8
```

**Result:** Worktree configure incomplete — `setup_angle()` rebuilds ANGLE via vcpkg and fails on `spirv-tools` (same class of env limit as Tasks 2–3). Junctioned `3rd/angle` from main; still not enough for full preset configure.

### Compile proof (accepted substitute)

Reused **main** tree `compile_commands.json` flags for `plugin_core_vm` (Debug), retargeted `-I` and sources to this worktree. Compiled all five TUs with MSVC `cl`:

| TU | Object | Result |
|----|--------|--------|
| `GameLua.cpp` | `_verify_GameLua.obj` | OK |
| `game/GameLuaContext.cpp` | `_verify_Context.obj` | OK (after `../GameLuaInjectFramework.c`) |
| `game/GameLuaContextLua51.cpp` | `_verify_Lua51.obj` | OK |
| `game/GameLuaContextJit.cpp` | `_verify_Jit.obj` | OK |
| `game/GameLuaContextGame.cpp` | `_verify_Game.obj` | OK |

Only pre-existing `LUA_GCCYCLE` macro redefinition warning from luajit headers. **No C errors.**  
Not a full link of `plugin_core_vm.dll` (new sources not in main ninja graph).

### Static checks

- Exactly one definition each for: `currentCtx`, `GetGameLuaContext`, `ds_core_vm_*`, `ctx_*`, `Default*LibraryName`, `NoteGame*`, `GetContextForType`, `ReplaceLuaModule`, `wrapper_game_main_buffer`, Jit `LoadMyLuaApi`, Game `GameFindExportByName`, framework instance.
- `GameLua.cpp` has **zero** remaining `gameLua*Ctx` / context struct definitions.
- Did **not** start Task 5 (VmSwitch/Replace/GameDbg still in `GameLua.cpp`).

---

## Self-review

| Check | Result |
|-------|--------|
| `GameLuaContextImpl.hpp` complete type | Pass |
| Context TUs + statics + `ctx_*` | Pass |
| jit + jit_gen share class / two instances | Pass |
| CMake game sources updated | Pass |
| Replace/Switch/Dbg left in GameLua.cpp | Pass |
| Consumes Task 3 Internal helpers | Pass |
| No main checkout edits | Pass |

**Concerns**

1. No full `plugin_core_vm` link in worktree (ANGLE/configure). Per-TU `cl /c` only.
2. `GameLuaContextImpl` / `GameLua51Context` methods remain header-inline (large headers; acceptable for this split).
3. Historical `HOOK_LUA_API` macro (`decltype(&#name)`) preserved as in longstanding sources.
4. Temporary worktree junction `3rd/angle` → main for configure attempts; not committed.

---

## Commit

```
refactor(core.vm): split GameLua contexts into game/* TUs
```

Staged: `game/*` new sources + headers, `GameLua.cpp`, `CMakeLists.txt`, `GameLuaInternal.hpp`.

---

## Follow-ups (Task 5)

- Move VmSwitch / ReplaceLuaModule / GameDbgExports out of `GameLua.cpp` and delete residual root TU.
- Optionally demote `NoteGameLuaExport*` once Replace lives next to `gameLuaGameCtx`.
