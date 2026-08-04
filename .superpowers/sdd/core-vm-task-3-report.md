# Core VM Task 3 Report — Move Signature + GameLua into plugin_core_vm

**Status:** DONE  
**Base:** `56834d5` (V-S1 stub)  
**Commit message:** `feat(core.vm): move Signature + GameLua into optional plugin_core_vm`

## Summary

Signature + ReplaceLuaModule now live entirely in optional `plugin_core_vm` (id `core.vm`). L0 `TryRunSignatureAndReplace` only calls the plugin export; missing module or soft failure logs and continues — **no in-process legacy fallback**. L-G PASS with `plugin_core_vm.dll` staged.

## Files

| Path | Change |
|------|--------|
| `plugins/plugin_core_vm/GameLua.cpp/.hpp/.def` | **moved** from Injector root |
| `plugins/plugin_core_vm/GameLuaInjectFramework.lua` (+ generated `.c`) | **moved**; lua2c custom command on plugin |
| `plugins/plugin_core_vm/LuajitVariantNames.hpp` | **moved** |
| `plugins/plugin_core_vm/DontStarveSignature.cpp/.hpp` | **moved** |
| `plugins/plugin_core_vm/SignatureJson.cpp/.hpp` | **moved** (exclusive to signature path; tools CMake paths updated) |
| `plugins/plugin_core_vm/lua_debugger_helper.cpp/.hpp` | **moved** (exclusive to VM open path) |
| `plugins/plugin_core_vm/plugin_core_vm.cpp` | Real `ds_core_vm_run_signature_and_replace` + branch-flag patch |
| `GameSignature.cpp` | Compiled into plugin only (not Injector SOURCES) |
| `GameLuaModule.cpp` | Compiled into plugin (`luaopen_GameInjector`); cascade loaders split out |
| `GameJitModConfigCascade.cpp` | **create** — L0 cascade loaders (must work without core.vm) |
| `GameLuaType.hpp` | **kept in L0** (`gameModConfig.hpp`) |
| `lua_fake.cpp` | **kept in L0** (`ENABLE_FAKE_API` optional; not exclusive to VM) |
| `core/CoreVmBootstrap.hpp/.cpp` | Remove `LegacySignatureAndReplaceInInjector`; TryRun soft-skip only |
| `DontStarveInjector.cpp` | Remove legacy block + branch-flag helpers |
| `core/GameLuaContextResolve.hpp` | **create** — `ds_core_vm_get_game_lua_context` via GetProcAddress |
| `plugins/plugin_sim_lagcomp/GameSimHook.cpp` | Resolve context from `plugin_core_vm`; no-op if missing |
| `GameProfilerHook.hpp` | Dynamic context resolve for frame GC |
| `CMakeLists.txt` | Injector SOURCES cleaned; full plugin_core_vm target + deps |
| `config.hpp` / util exports | Cross-DLL export macros for Hook/loadlib/gameio/lua51 helpers |
| `tools/Checker|Creater/CMakeLists.txt` | SignatureJson/DontStarveSignature paths under plugin dir |

## Interfaces

```cpp
// plugin export (C)
bool ds_core_vm_run_signature_and_replace(const ds::core_vm::BootstrapArgs *args);
GameLuaContext &ds_core_vm_get_game_lua_context(); // C ABI for lagcomp/L0

// L0
bool ds::core_vm::TryRunSignatureAndReplace(const BootstrapArgs &args);
// if export null → log skip, return false
// if export false → log skip, return false
// NO LegacySignatureAndReplaceInInjector
```

## Behavior

1. `VmPathEnabled` → `TryRunSignatureAndReplace`
2. Ensure/load `plugins/plugin_core_vm.dll` (optional)
3. Call export: load lua51 → scan → `SignatureUpdater` → `ReplaceLuaModule` → branch-flag
4. Hard fails (`can't load lua51`, signature errors): `showError` inside plugin (exit)
5. Soft miss (no luamodule base) / missing DLL: log + inject continues
6. PluginHost + DynamicPluginLoader always

## Verification

### CMake / dumps

- Injector SOURCES: **no** `GameLua.cpp`, `DontStarveSignature.cpp`, `SignatureJson.cpp`, `GameLua.def`, `GameLuaModule.cpp`, `GameSignature.cpp`
- `dumpbin Injector.dll`: no `ReplaceLuaModule` / `GameDbg_lua_*` / `GetGameLuaContext`
- `dumpbin plugin_core_vm.dll`: `ds_core_vm_run_signature_and_replace`, `ds_core_vm_get_game_lua_context`, `ds_plugin_module_*`, `lua_newstate=GameDbg_lua_newstate` (via GameLua.def)

### Build

All targets RelWithDebInfo: Injector + plugin_core_vm + lagcomp + network.* + render.* + save_fork + dummy — link OK.

### L-G

```
DST_GAME_DIR=…/Don't Starve Together LG_T_HOLD=5 LG_REQUIRE_GAME=1
python tests/plugin_server/run_dedicated_sim_pause.py
```

- Staged `Injector.dll` + `plugins/plugin_core_vm.dll` (+ other plugins)
- Tokens: `LG_MOD_LOADED`, `LG_INJECT_OK`, `LG_PLUGINS_OK`, `LG_WORLD_READY`, `LG_SIM_PAUSED`, `LG_STABLE`
- Server close log: `vm=jit` (ReplaceLuaModule path active)
- **Result: PASS**

## Audit notes

| Item | Decision |
|------|----------|
| `GameLuaType.hpp` | Stay L0 (gameModConfig) |
| `lua_fake.cpp` | Stay L0 (ENABLE_FAKE_API only) |
| `lua_debugger_helper` | Moved with GameLua (VM-only) |
| `lua_io2.cpp` | Compiled into plugin_core_vm only |
| `GameLuaModule.cpp` | In plugin for `luaopen_GameInjector` + GameDbg; cascade split to L0 |
| `GameProfilerHook` | Stays L0; uses dynamic GetGameLuaContext |
| Signature tools | Creater/Checker path updated to plugin dir sources |

## Checklist

- [x] Move TUs + fix includes
- [x] Real `ds_core_vm_run_signature_and_replace`
- [x] Delete legacy in-Injector path
- [x] lagcomp GetGameLuaContext from plugin_core_vm
- [x] Build all plugins; dumpbin checks
- [x] L-G PASS with core.vm staged
- [x] Commit

## Fix: Important review findings

**Date:** 2026-08-04
**Commit message:** `fix(core.vm): init function_relocation ctx and export GameDbg APIs`


1. **`function_relocation::init_ctx` in plugin_core_vm**
   - `run_signature_and_replace`: call `init_ctx()` before SignatureUpdater/disasm; pair with `deinit_ctx` via `create_defer`.
   - `CoreVmPlugin::load`: also `init_ctx()` (matches network_rpc / network_sim / render_vbpool per-DLL static-lib pattern).
   - `ctx.hpp` already included.

2. **`EXPORT_GAME_LUA_API` non-Windows visibility**
   - Was: `DONTSTARVEINJECTOR_API` which is empty under `DS_INJECTOR_CONSUMER` (not `DONTSTARVEINJECTOR_BUILD`), so GameDbg_* aliases would not get default visibility.
   - Now: `extern "C" __attribute__((visibility("default")))` on GameDbg definitions; Linux `alias` also marked `visibility("default")`.
   - Windows unchanged (GameLua.def).

### Verification

```text
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target Injector plugin_core_vm plugin_sim_lagcomp -j 16
# Linking CXX shared module .../plugins/plugin_core_vm.dll — OK

# Stage
cp Injector.dll + plugins/plugin_core_vm.dll (+ lagcomp) → DST bin64

DST_GAME_DIR=…/Don't Starve Together LG_T_HOLD=5 LG_REQUIRE_GAME=1 \
  python tests/plugin_server/run_dedicated_sim_pause.py
```

L-G output (abridged):

```text
[core.vm] module mapped: plugin_core_vm.dll
[plugin_core_vm] running signature + ReplaceLuaModule
… Applied Lua VM type: jit …
lua_newstate created lua state=… vm=jit
[lg] log-token LG_MOD_LOADED
[lg] log-token LG_INJECT_OK
[lg] log-token LG_PLUGINS_OK
[lg] log-token LG_WORLD_READY
[lg] log-token LG_SIM_PAUSED
[lg] LG_STABLE written
[lg] server exit code=0
[lg] PASS core profile
```

**Result: L-G PASS** (vm=jit path active with init_ctx fix).
