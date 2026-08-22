# Core.vm Module Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize `plugin_core_vm` into package-internal modules (`signature` / `game` / `io` / `injector` / `event` / `optional`) by splitting the ~1940-line `GameLua.cpp` into focused translation units, keeping one MODULE (`plugin_core_vm`, id `core.vm`) and pure external VM libs (`lua51DS` / `lua51DS_gengc` / `lua51Original`); missing selected VM lib degrades to `game` context.

**Architecture:** No new Host plugins. All behavior stays in `core.vm`. External overlays are pure Lua shared libraries only. Split is directory + TU boundaries inside one DLL. Peer includes of `GameLua.hpp` remain valid via a root re-export header.

**Tech Stack:** C++23, CMake ninja multi-vcpkg RelWithDebInfo, existing `ds_add_dynamic_plugin`, Frida Gum via Injector, L-G harness (`tests/plugin_server/run_dedicated_sim_pause.py`).

**Spec:** `docs/superpowers/specs/2026-08-10-core-vm-module-split-design.md` (approved)  
**Base HEAD at plan write:** `a2b3781`

## Global Constraints

- Plugin id remains **`core.vm`**; MODULE remains **`plugin_core_vm`**.
- **No** Host plugins `core.vm.jit` / `.gen` / `.lua51`; **no** overlay vtable ABI.
- External VM artifacts are **pure** shared libs: `lua51DS`, `lua51DS_gengc`, `lua51Original` (zero DS business symbols).
- Missing selected pure VM lib → **degrade to `GameLuaContextGame`** (still signature + replace to embedded Lua); log `VM library '{}' missing — degrade to game context`.
- Missing **`plugin_core_vm` DLL** still follows 2026-08-04 optional semantics (L0 soft-skip); this plan does **not** require fixing CoreVmBootstrap hard-require drift unless it blocks S2 verification.
- No second Frida Gum; no shim dual paths after each slice; clean cutover.
- modinfo keys unchanged: `LuaVmType`, `EnabledGenGC`, `DisableJITWhenServer`.
- Peer includes of `"GameLua.hpp"` / `"plugins/plugin_core_vm/GameLua.hpp"` must keep compiling (`plugin_sim_lagcomp`, `plugin_debug_profiler`, `util/lua_io2.cpp`).
- Each task: build `plugin_core_vm` (+ dependents if headers move); no project-wide format/lint mid-flight.
- YAGNI: no GameInjector/io/signature independent DLL this plan.

## File map (end state)

| Path | Role |
|---|---|
| `plugins/plugin_core_vm/plugin_core_vm.cpp` | entry (unchanged role) |
| `plugins/plugin_core_vm/GameLua.hpp` | **root re-export** of public API for peers (thin include of `game/GameLuaContext.hpp` + decls) |
| `plugins/plugin_core_vm/game/GameLuaContext.hpp` | `LuaApis`, `GameLuaContext`, public decls |
| `plugins/plugin_core_vm/game/GameLuaContext.cpp` | `GameLuaContextImpl` shared base + io open helpers used by base |
| `plugins/plugin_core_vm/game/GameLuaContextGame.cpp` | `GameLuaContextGame` + static `gameLuaGameCtx` |
| `plugins/plugin_core_vm/game/GameLuaContextJit.cpp` | `GameLuaContextJit` + static `gameLuajitCtx` / `gameLuajitGenCtx` |
| `plugins/plugin_core_vm/game/GameLuaContextLua51.cpp` | `GameLua51Context` + static `gameLua51Ctx` |
| `plugins/plugin_core_vm/game/VmSwitch.cpp` | `VmSwitchCoordinator`, `RequestVmType`, `ReinitializeCurrentVm`, degrade path |
| `plugins/plugin_core_vm/game/ReplaceLuaModule.cpp` | `ReplaceLuaModule` / `ReplaceLuaApi` |
| `plugins/plugin_core_vm/game/GameDbgExports.cpp` | `GameDbg_lua*` reexports (+ `GameLua.def` stay or move with CMake) |
| `plugins/plugin_core_vm/game/GameLuaInternal.hpp` | shared internals: `GameLuaContextImpl*`, static ctx accessors, forward decls for switch |
| `plugins/plugin_core_vm/injector/*` | `GameLuaModule.cpp`, `GameInjectorApply.*`, framework lua/c |
| `plugins/plugin_core_vm/event/*` | `LuaEvent.hpp`, `LuaEventBus.cpp` |
| `plugins/plugin_core_vm/optional/*` | debugger + fake |
| `plugins/plugin_core_vm/signature_load/` | keep path (no rename required; optional later) |
| `plugins/plugin_core_vm/io/` | already correct |
| `plugins/plugin_core_vm/CMakeLists.txt` | source groups for all of the above |

**Do not** invent Host overlay plugins. **Do not** leave a second full copy of `GameLua.cpp` after Task 5.

---

### Task 1: S0 — CMake source groups + create empty module dirs (zero behavior)

**Files:**
- Modify: `src/DontStarveInjector/plugins/plugin_core_vm/CMakeLists.txt`
- Create dirs (placeholders ok): `game/`, `injector/`, `event/`, `optional/` (empty `.gitkeep` only if needed for empty dirs; prefer adding files in later tasks)

**Interfaces:**
- Consumes: existing source list
- Produces: CMake variables `PLUGIN_CORE_VM_GAME_SOURCES`, `PLUGIN_CORE_VM_INJECTOR_SOURCES`, `PLUGIN_CORE_VM_EVENT_SOURCES`, `PLUGIN_CORE_VM_OPTIONAL_SOURCES` still pointing at **current** paths until moves land

- [ ] **Step 1: Rewrite CMake source grouping without moving files yet**

Replace the single `PLUGIN_CORE_VM_VM_SOURCES` blob with labeled groups that still list today’s paths:

```cmake
# Layout (design 2026-08-10):
#   signature_load/ → STATIC ds_signature
#   io/             → gameio + GameSteam
#   game/           → VM contexts + Replace + switch (files land in later tasks)
#   injector/       → GameInjector open
#   event/          → LuaEventBus
#   optional/       → debugger / fake
# External pure VM libs: lua51DS / lua51DS_gengc / lua51Original (Mod/deps) — not plugins.

set(PLUGIN_CORE_VM_GAME_SOURCES
    GameLua.cpp
)
set(PLUGIN_CORE_VM_INJECTOR_SOURCES
    GameLuaModule.cpp
    GameLuaInjectFramework.c
    GameInjectorApply.cpp
)
set(PLUGIN_CORE_VM_EVENT_SOURCES
    LuaEventBus.cpp
)
set(PLUGIN_CORE_VM_OPTIONAL_SOURCES
    lua_debugger_helper.cpp
    lua_fake.cpp
)
set(PLUGIN_CORE_VM_ENTRY_SOURCES
    plugin_core_vm.cpp
)
set(PLUGIN_CORE_VM_SOURCES
    ${PLUGIN_CORE_VM_ENTRY_SOURCES}
    ${PLUGIN_CORE_VM_GAME_SOURCES}
    ${PLUGIN_CORE_VM_INJECTOR_SOURCES}
    ${PLUGIN_CORE_VM_EVENT_SOURCES}
    ${PLUGIN_CORE_VM_OPTIONAL_SOURCES}
    ${PLUGIN_CORE_VM_IO_SOURCES}
)
```

Update the top comment: remove “force-loaded / required” wording; say optional Host plugin id `core.vm` + pure VM libs staged by `stage_core_vm_deps.cmake`.

- [ ] **Step 2: Build**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target plugin_core_vm -j 8
```

Expected: success, same outputs as before.

- [ ] **Step 3: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_core_vm/CMakeLists.txt
git commit -m "build(core.vm): group CMake sources for module split (S0)"
```

---

### Task 2: Public header split + root re-export (compile peers)

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_core_vm/game/GameLuaContext.hpp`
- Modify: `src/DontStarveInjector/plugins/plugin_core_vm/GameLua.hpp` → thin re-export
- Modify: CMake `target_include_directories` if needed so `"game/GameLuaContext.hpp"` resolves from plugin root include

**Interfaces:**
- Produces: identical public surface:
  - `struct LuaApis`
  - `class GameLuaContext`
  - `GameLuaContext &GetGameLuaContext()`
  - `extern "C" GameLuaContext &ds_core_vm_get_game_lua_context()`
  - `void ReplaceLuaApi(...)`
  - `void ReplaceLuaModule(...)`
- Consumes: existing `GameLua.hpp` body (move, do not redesign)

- [ ] **Step 1: Move current `GameLua.hpp` body into `game/GameLuaContext.hpp`**

Copy the full current content of `GameLua.hpp` into `game/GameLuaContext.hpp`. Adjust includes that assumed same-dir:

```cpp
// game/GameLuaContext.hpp
#pragma once
#include "config/InjectorHostConfig.hpp"
#include "LuaApi.hpp"                 // still package root for now
#include "DontStarveSignature.hpp"
#include "GameLuaType.hpp"
#include "LuaEvent.hpp"
// ... rest identical to current GameLua.hpp
```

Keep `DontStarveSignature.hpp` for this task (narrowing is Task 7 optional). Do **not** change method lists.

- [ ] **Step 2: Replace root `GameLua.hpp` with re-export**

```cpp
// GameLua.hpp — stable include path for peers (lagcomp, profiler, lua_io2)
#pragma once
#include "game/GameLuaContext.hpp"
```

- [ ] **Step 3: Build plugin + peers that include GameLua.hpp**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target plugin_core_vm plugin_sim_lagcomp plugin_debug_profiler Injector -j 8
```

Expected: no missing include for `GameLua.hpp`.

- [ ] **Step 4: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_core_vm/GameLua.hpp \
        src/DontStarveInjector/plugins/plugin_core_vm/game/GameLuaContext.hpp
git commit -m "refactor(core.vm): move public GameLua types to game/ with root re-export"
```

---

### Task 3: Extract `GameLuaInternal.hpp` + split static context accessors

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_core_vm/game/GameLuaInternal.hpp`
- Modify: `GameLua.cpp` only as needed to include it (still monolithic until Task 4–5)

**Interfaces:**
- Produces (internal, not for peers):

```cpp
// game/GameLuaInternal.hpp
#pragma once
#include "game/GameLuaContext.hpp"
#include "DontStarveSignature.hpp"
#include <optional>
#include <string>
#include <string_view>

struct GameLuaContextImpl; // defined in GameLuaContext.cpp

namespace ds::core_vm::detail {
GameLuaContextImpl *GetContextForType(GameLuaType type);
GameLuaContextImpl *&CurrentContext(); // or free functions matching existing statics
const char *GetDefaultModuleName(GameLuaType type);

// Static instances live in their TUs; declared here:
extern GameLuaContextImpl &game_lua51_ctx();   // or keep named globals in one TU first
// Prefer: declare the four statics in Internal and define in context TUs (Task 4).
}
```

**Practical approach for Task 3 (minimal):** introduce `GameLuaInternal.hpp` with **forward decls + free-function declarations** that already exist as `static` in `GameLua.cpp`, changing those `static` functions to internal linkage via anonymous namespace **or** `ds::core_vm::detail` so later TUs can call them:

Must become non-file-static (move to `detail`):
- `GetContextForType`
- `GetDefaultModuleName`
- `RequestVmType` / `ReinitializeCurrentVm` / `ApplyVmType` / `CacheRuntimeSetup`
- `CreateLuaStateForCurrentVm` / `PrepareForLuaStateCreate` / `MarkLuaStateCreated` / `MarkLuaStateClosed`
- `UseGameIO` / `load_game_fn_io_open` / `replace_game_io_open` if called across TUs

Keep `GameLuaContextImpl` class definition still in `GameLua.cpp` for this task if needed; only lift the **declarations** needed for multi-TU.

- [ ] **Step 1: Add `GameLuaInternal.hpp` with declarations matching current signatures**

Read `GameLua.cpp` lines ~31–36, ~88–99, ~1120–1270 and copy exact signatures into the header under `namespace ds::core_vm::detail` or file-level with `// internal`.

- [ ] **Step 2: In `GameLua.cpp`, remove `static` from those functions and include Internal.hpp; qualify definitions**

- [ ] **Step 3: Build `plugin_core_vm`**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target plugin_core_vm -j 8
```

Expected: link OK (still one TU defining everything).

- [ ] **Step 4: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_core_vm/game/GameLuaInternal.hpp \
        src/DontStarveInjector/plugins/plugin_core_vm/GameLua.cpp
git commit -m "refactor(core.vm): expose internal VM helpers for multi-TU split"
```

---

### Task 4: Split context TUs (Game / Jit / Lua51) — leave Replace/Switch/Dbg in GameLua.cpp temporarily

**Files:**
- Create: `game/GameLuaContext.cpp` — move `GameLuaContextImpl` + shared helpers (`UseGameIO`, inject framework host if tightly coupled, `wrapper_game_main_buffer` if only used by base)
- Create: `game/GameLuaContextLua51.cpp` — `GameLua51Context` + `gameLua51Ctx`
- Create: `game/GameLuaContextJit.cpp` — `GameLuaContextJit` + `gameLuajitCtx` + `gameLuajitGenCtx` + out-of-line `LoadMyLuaApi`
- Create: `game/GameLuaContextGame.cpp` — `GameLuaContextGame` + `gameLuaGameCtx`
- Create: `game/GameLuaContexts.hpp` (optional) — declares the four static instances for switch/GetGameLuaContext
- Modify: `GameLua.cpp` — remove moved code; keep switch + Replace + GameDbg for now
- Modify: `CMakeLists.txt` — list new game/*.cpp

**Interfaces:**
- Consumes: Task 3 `GameLuaInternal.hpp`
- Produces: four context TUs; `GetContextForType` must see all four instances

**Region map from current `GameLua.cpp` (line anchors at plan write, re-read before cut):**

| Region | Approx lines | Destination |
|---|---|---|
| GAME_IO helpers + inject framework + `GameLuaContextImpl` | ~88–591 | `GameLuaContext.cpp` |
| `GameLua51Context` | ~594–713 | `GameLuaContextLua51.cpp` |
| `GameLuaContextJit` + later `LoadMyLuaApi` | ~716–753, ~1048+ | `GameLuaContextJit.cpp` |
| `GameLuaContextGame` | ~755–991 | `GameLuaContextGame.cpp` |
| static four contexts | ~1032–1045 | respective context TUs |
| `GetGameLuaContext` / `ds_core_vm_get_game_lua_context` | ~1079–1097 | `GameLuaContext.cpp` or `VmSwitch.cpp` (prefer Context.cpp) |

- [ ] **Step 1: Move `GameLuaContextImpl` + helpers into `game/GameLuaContext.cpp`**

Include order sketch:

```cpp
#include "game/GameLuaContext.hpp"
#include "game/GameLuaInternal.hpp"
#include "VmConfig.hpp"
#include "io/gameio.h"
#include "lua_debugger_helper.hpp"
// ... same deps GameLua.cpp used for the base class
```

Ensure `GameLuaContextImpl` is **complete type** in a header if subclasses in other TUs need it:

**Required:** put `struct GameLuaContextImpl : GameLuaContext { ... };` in `game/GameLuaContextImpl.hpp` (new) so Jit/51/Game TUs can inherit. Out-of-line methods can stay in `.cpp`.

If putting the full class in a header is too large for one step, acceptable alternative: keep subclasses in the **same** TU as base for Task 4a, then split subclasses in Task 4b. Prefer full split if compile times allow.

**Recommended concrete split for agents:**

1. Create `game/GameLuaContextImpl.hpp` with the full `GameLuaContextImpl` class definition (from current struct body).
2. `GameLuaContext.cpp` defines out-of-line methods + `currentCtx` + `GetGameLuaContext`.
3. Subclass `.cpp` files include `GameLuaContextImpl.hpp` and define subclass + static instance.

- [ ] **Step 2: Move subclasses + static instances**

`GameLuaContextJit.cpp` must define **both**:

```cpp
static GameLuaContextJit gameLuajitCtx{ DefaultLuajitLibraryName(), GameLuaType::jit };
static GameLuaContextJit gameLuajitGenCtx{ DefaultLuajitGenLibraryName(), GameLuaType::jit_gen };
```

Expose for `GetContextForType` via functions in Internal:

```cpp
// GameLuaInternal.hpp
GameLuaContextImpl *ctx_lua51();
GameLuaContextImpl *ctx_jit();
GameLuaContextImpl *ctx_jit_gen();
GameLuaContextImpl *ctx_game();
```

Implemented next to each static (or in one `GameLuaContexts.cpp` if linkage is simpler — but design wants per-context files; functions can live beside statics).

- [ ] **Step 3: Update CMake**

```cmake
set(PLUGIN_CORE_VM_GAME_SOURCES
    GameLua.cpp
    game/GameLuaContext.cpp
    game/GameLuaContextGame.cpp
    game/GameLuaContextJit.cpp
    game/GameLuaContextLua51.cpp
)
```

- [ ] **Step 4: Build**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target plugin_core_vm -j 8
```

Expected: success. Fix ODR / incomplete type / missing symbols.

- [ ] **Step 5: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_core_vm/game \
        src/DontStarveInjector/plugins/plugin_core_vm/GameLua.cpp \
        src/DontStarveInjector/plugins/plugin_core_vm/CMakeLists.txt
git commit -m "refactor(core.vm): split GameLua contexts into game/* TUs"
```

---

### Task 5: Split `VmSwitch` + `ReplaceLuaModule` + `GameDbgExports`; delete residual `GameLua.cpp`

**Files:**
- Create: `game/VmSwitch.cpp` — coordinator + Request/Apply/Reinitialize/CreateState markers
- Create: `game/ReplaceLuaModule.cpp` — `ReplaceLuaModule`, `ReplaceLuaApi` if present
- Create: `game/GameDbgExports.cpp` — all `EXPORT_GAME_LUA_API` / `GameDbg_*` block (~1591–end)
- Delete or empty: root `GameLua.cpp` after moves
- Modify: CMake — remove `GameLua.cpp` from list; add the three new files
- Move: `GameLua.def` → `game/GameLua.def` **or** keep path and only update CMake comment (prefer keep path to reduce MSVC churn)

**Interfaces:**
- `ReplaceLuaModule` remains global as today (declared in `GameLuaContext.hpp`)
- `DS_LUAJIT_set_vm_type` / `get_vm_type_name` stay in VmSwitch.cpp

- [ ] **Step 1: Move switch coordinator block (~1101–1320 + set_vm_type APIs) to `VmSwitch.cpp`**

- [ ] **Step 2: Move `ReplaceLuaModule` (~1549–1589) to `ReplaceLuaModule.cpp`**

Keep behavior identical in this task (degrade is Task 6).

- [ ] **Step 3: Move GameDbg export block to `GameDbgExports.cpp`**

Preserve `EXPORT_GAME_LUA_API` macros and `GameLua.def` coupling on MSVC.

- [ ] **Step 4: Ensure no residual `GameLua.cpp`**

```bash
# after moves
test ! -f src/DontStarveInjector/plugins/plugin_core_vm/GameLua.cpp
```

- [ ] **Step 5: Final CMake game sources**

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

- [ ] **Step 6: Build + export smoke**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target plugin_core_vm -j 8
# Windows:
dumpbin /exports builds/ninja-multi-vcpkg/src/DontStarveInjector/RelWithDebInfo/plugins/plugin_core_vm/plugin_core_vm.dll ^
  | findstr /I "ds_core_vm_run_signature_and_replace ds_core_vm_get_game_lua_context DS_LUAJIT_set_vm_type"
```

Expected: those symbols still present (set_vm_type may be export via def/GameDbg path — if only GameInjector-bound, still need successful link).

- [ ] **Step 7: Commit**

```bash
git add -A src/DontStarveInjector/plugins/plugin_core_vm
git commit -m "refactor(core.vm): finish game/ TU split; remove monolithic GameLua.cpp"
```

---

### Task 6: S2 — Missing pure VM library degrades to `game`

**Files:**
- Modify: `game/VmSwitch.cpp` (`ReinitializeCurrentVm` and/or `RequestVmType` / `ReplaceLuaModule` startup path)
- Possibly: `game/ReplaceLuaModule.cpp` if selection should degrade before Request

**Interfaces:**
- Spec M8: load fail → warn + use `GameLuaContextGame` + still replace

**Current bug to fix:** `ReinitializeCurrentVm` does:

```cpp
if (!currentCtx->LoadLuaModule()) {
    return false;  // leaves replace incomplete
}
```

**Target behavior:**

```cpp
static bool ReinitializeCurrentVm(std::string_view reason) {
    // ... setup checks unchanged ...
    auto *currentCtx = GameLuaContextImpl::currentCtx;
    if (currentCtx == nullptr) { /* error */ return false; }

    if (!currentCtx->LoadLuaModule()) {
        // Pure VM lib missing — degrade to embedded game Lua (spec M8).
        if (currentCtx->luaType != GameLuaType::game) {
            spdlog::warn(
                "VM library '{}' missing — degrade to game context ({})",
                currentCtx->sharedlibraryName, reason);
            ApplyVmType(GameLuaType::game, std::nullopt, "degrade after LoadLuaModule failure");
            currentCtx = GameLuaContextImpl::currentCtx;
            if (currentCtx == nullptr || !currentCtx->LoadLuaModule()) {
                spdlog::error("Degrade to game failed: {}", reason);
                return false;
            }
        } else {
            spdlog::error("Game context LoadLuaModule failed: {}", reason);
            return false;
        }
    }
    currentCtx->LoadAllInterfaces();
    currentCtx->LoadMyLuaApi();
    if (!currentCtx->ReplaceApis(vmSwitchCoordinator.signatures, vmSwitchCoordinator.exports)) {
        // existing error path
        return false;
    }
    currentCtx->HotfixApis(vmSwitchCoordinator.mainPath);
    spdlog::info("Reinitialized Lua VM runtime: {} vm={}", reason,
                 GameLuaTypeToString(GetCurrentVmType()));
    return true;
}
```

Use the real field name for the library string (`sharedlibraryName` on `GameLuaContext` — verify in `GameLuaContext.hpp` before coding).

Also ensure `GetGameLuaContext()` default path does not hard-require jit without degrade if someone calls it before Replace (optional hardening; primary path is ReplaceLuaModule startup).

- [ ] **Step 1: Implement degrade in `ReinitializeCurrentVm`**

- [ ] **Step 2: Build**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target plugin_core_vm -j 8
```

- [ ] **Step 3: Manual / harness check when game available**

With staged deps present: L-G present still PASS (behavior unchanged when libs exist).

Optional negative test (document if game dir not available in CI):

```text
Rename/move Injector/deps/lua51DS.dll (or Mod/deps) away temporarily
Launch inject path with LuaVmType=jit
Expect log: VM library ... missing — degrade to game context
Expect process does not hard-crash at LoadLuaModule; game context used
```

- [ ] **Step 4: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_core_vm/game/VmSwitch.cpp
git commit -m "fix(core.vm): degrade to game context when pure VM library missing"
```

---

### Task 7: S3 — Physical move injector / event / optional + include cleanup

**Files:**
- Move:
  - `GameLuaModule.cpp`, `GameInjectorApply.cpp/.hpp`, `GameLuaInjectFramework.lua` (+ generated `.c` path) → `injector/`
  - `LuaEvent.hpp`, `LuaEventBus.cpp` → `event/`
  - `lua_debugger_helper.*`, `lua_fake.cpp` → `optional/`
- Modify: all `#include` sites inside plugin_core_vm and peers:
  - `"LuaEvent.hpp"` → `"event/LuaEvent.hpp"` **or** keep root re-export shims for one release — **prefer clean cutover with re-export shims at root** for peer stability:

```cpp
// LuaEvent.hpp (root re-export)
#pragma once
#include "event/LuaEvent.hpp"
```

Same pattern optional for `GameInjectorApply.hpp` if anything external includes it (grep first).

- Modify: `CMakeLists.txt` paths + `add_custom_command` OUTPUT path for framework `.c` under `injector/`
- Modify: `plugin_core_vm.cpp` includes
- Grep peers: `plugin_debug_profiler` includes `plugins/plugin_core_vm/LuaEvent.hpp` — root re-export keeps this working

- [ ] **Step 1: Grep external includes**

```bash
# use workspace grep tool, not shell grep, in agent sessions
```

Patterns: `LuaEvent.hpp`, `GameInjectorApply`, `lua_debugger_helper`, `GameLuaModule`.

- [ ] **Step 2: Move files + root re-exports for any peer-facing headers**

- [ ] **Step 3: Update CMake source paths and lua2c output**

```cmake
set(PLUGIN_CORE_VM_INJECTOR_SOURCES
    injector/GameLuaModule.cpp
    injector/GameLuaInjectFramework.c
    injector/GameInjectorApply.cpp
)
set(PLUGIN_CORE_VM_EVENT_SOURCES
    event/LuaEventBus.cpp
)
set(PLUGIN_CORE_VM_OPTIONAL_SOURCES
    optional/lua_debugger_helper.cpp
    optional/lua_fake.cpp
)
```

Update `add_custom_command` to write `injector/GameLuaInjectFramework.c` from `injector/GameLuaInjectFramework.lua`.

- [ ] **Step 4: Build dependents**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target plugin_core_vm plugin_sim_lagcomp plugin_debug_profiler Injector -j 8
```

- [ ] **Step 5: Commit**

```bash
git add -A src/DontStarveInjector/plugins/plugin_core_vm
git commit -m "refactor(core.vm): place injector/event/optional modules on disk"
```

---

### Task 8: Docs + stage comment — pure VM libs are not plugins

**Files:**
- Modify: `docs/plugin-system.md` — core.vm inventory row: package modules + pure VM deps
- Modify: `src/DontStarveInjector/plugins/plugin_core_vm/stage_core_vm_deps.cmake` — header comment
- Modify: `docs/superpowers/specs/2026-08-10-core-vm-module-split-design.md` Status → Approved/Implemented when done

- [ ] **Step 1: Update plugin-system.md core.vm section**

Add a short subsection:

```markdown
### core.vm internal modules
- signature (`signature_load/` → ds_signature)
- game/ (contexts, Replace, switch)
- io/ (gameio + Steam)
- injector/ (GameInjector open)
- event/, optional/
External pure VM libs in Mod/deps: lua51DS, lua51DS_gengc, lua51Original (not Host plugins).
Missing selected lib → degrade to game context.
```

- [ ] **Step 2: stage_core_vm_deps.cmake comment**

State explicitly: staged artifacts are pure Lua VMs; no business logic; not `plugin_*`.

- [ ] **Step 3: Commit**

```bash
git add docs/plugin-system.md \
        src/DontStarveInjector/plugins/plugin_core_vm/stage_core_vm_deps.cmake \
        docs/superpowers/specs/2026-08-10-core-vm-module-split-design.md
git commit -m "docs(core.vm): document package modules and pure VM overlays"
```

---

### Task 9: Verification gate (S1–S3 complete)

**Files:** none (commands only)

- [ ] **Step 1: Full relevant build**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target Injector plugin_core_vm plugin_sim_lagcomp plugin_debug_profiler -j 8
```

Expected: success.

- [ ] **Step 2: Tree check**

```text
No GameLua.cpp at plugin_core_vm root
game/ has Context* + VmSwitch + Replace + GameDbg*
injector/, event/, optional/ populated
signature_load/, io/ unchanged role
Root GameLua.hpp is re-export only
```

- [ ] **Step 3: L-G present (when game/deploy available)**

```bash
# existing project harness — match CI/docs for L-G present
# Expect PASS with vm=jit when lua51DS staged
```

- [ ] **Step 4: Final status note on spec**

Set design status to Implemented (or Partially if L-G not run — state evidence honestly).

---

## Spec coverage checklist

| Spec item | Task |
|---|---|
| M1 id `core.vm` | all (no rename) |
| M2 all behavior in plugin | all |
| M3 pure VM libs only | Task 8 docs; no overlay plugins anywhere |
| M4 game mode builtin | Task 4 Game context |
| M5 signature package module | keep signature_load; Task 1 comments |
| M6 context TUs | Task 4–5 |
| M7 io + injector placement | Task 7; io already |
| M8 degrade to game | Task 6 |
| M9 no dual path | Task 5 deletes GameLua.cpp |
| M10 YAGNI | no extra plugins |
| Success: no god GameLua.cpp | Task 5 |
| Success: L0 exports unchanged | Task 5 dumpbin / Task 9 |

## Self-review notes (plan author)

- Placeholder scan: none intentional; line numbers for GameLua.cpp are anchors — agents must re-read before cut.
- Type consistency: `GameLuaContextImpl` must be visible to subclass TUs via header.
- Peer include stability: root `GameLua.hpp` + root `LuaEvent.hpp` re-exports required.
- Degrade uses `ApplyVmType(game)` then Load — must not recurse infinitely (game Load uses main module, not missing DLL).

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-10-core-vm-module-split.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans + checkpoints  

Which approach?
