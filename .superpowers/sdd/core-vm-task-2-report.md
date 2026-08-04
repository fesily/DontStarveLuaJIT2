# Core.VM Task 2 Report: Optional core.vm loader shell (V-S1)

**Status:** DONE  
**Commit:** `feat(core.vm): optional module loader + stub plugin (V-S1)` (HEAD after Task 2)  
**Base:** `3292039` (Task 1 V-S0)  
**Date:** 2026-08-04

## Summary

L0 now loads optional `plugin_core_vm` via `ds::core_vm::CoreVmBootstrap` and calls `ds_core_vm_run_signature_and_replace` when present. The V-S1 stub export returns false, so inject always falls back to `LegacySignatureAndReplaceInInjector` (the previous lua51 / SignatureUpdater / ReplaceLuaModule / branch-flag path, still linked into Injector). Missing DLL never aborts inject.

## Files

| Path | Change |
|------|--------|
| `src/DontStarveInjector/core/CoreVmBootstrap.hpp` | **create** — `BootstrapArgs`, `EnsureCoreVmModuleLoaded`, `GetRunSignatureAndReplaceFn`, `TryRunSignatureAndReplace`, `LegacySignatureAndReplaceInInjector` |
| `src/DontStarveInjector/core/CoreVmBootstrap.cpp` | **create** — GetModuleHandle / LoadLibraryEx from `<injector_dir>/plugins/plugin_core_vm.dll` (dlopen on non-Win); never fail-fast |
| `src/DontStarveInjector/plugins/plugin_core_vm/plugin_core_vm.cpp` | **create** — id `core.vm`, AlwaysOn, EarlyNative priority 10; stub export returns false; `ds_plugin_module_init` / `abi_version` |
| `src/DontStarveInjector/DontStarveInjector.cpp` | Extract VM block into `LegacySignatureAndReplaceInInjector`; `VmPathEnabled` → `TryRunSignatureAndReplace` |
| `src/DontStarveInjector/CMakeLists.txt` | Add `core/CoreVmBootstrap.cpp` to Injector; `ds_add_dynamic_plugin(plugin_core_vm)` on all platforms + spdlog |

## Interfaces

```cpp
namespace ds::core_vm {
struct BootstrapArgs {
  bool is_client = true;
  uintptr_t lua_module_base = 0;
  const char *main_path = nullptr;
};
bool EnsureCoreVmModuleLoaded();
using RunSigReplaceFn = bool (*)(const BootstrapArgs *args);
RunSigReplaceFn GetRunSignatureAndReplaceFn();
bool LegacySignatureAndReplaceInInjector(const BootstrapArgs &args);
bool TryRunSignatureAndReplace(const BootstrapArgs &args);
}
// plugin export (C):
bool ds_core_vm_run_signature_and_replace(const BootstrapArgs *args); // stub → false
```

`TryRunSignatureAndReplace`: if export present and returns true, done; if missing/false, call `LegacySignatureAndReplaceInInjector`.

Legacy hard failures still `showError` (exit) for `can't load lua51` and signature errors. Soft miss (`can't find luamodule base`) returns false and inject continues with a warn.

## Inject order (VmPathEnabled)

1. Fill `BootstrapArgs{is_client}` (base/path resolved inside legacy if zero/null).
2. `TryRunSignatureAndReplace` → optional module + stub false → **legacy path**.
3. `LoadGameModConfig` + PluginHost / DynamicPluginLoader / resolve / EarlyNative (unchanged; always).

Note: bootstrap may map `plugin_core_vm` **before** DynamicPluginLoader `load_all`. Loader still finds the already-mapped DLL and runs `ds_plugin_module_init` (register `core.vm`).

## Build + stage

```text
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector plugin_core_vm
# Linking CXX shared library .../Injector.dll — OK
# Linking CXX shared module .../plugins/plugin_core_vm.dll — OK
```

Staged RelWithDebInfo:

- `…/bin64/Injector.dll`
- `…/bin64/plugins/plugin_core_vm.dll`

## L-G

### With stub staged

```text
DST_GAME_DIR=…/Don't Starve Together LG_T_HOLD=5 LG_REQUIRE_GAME=1 \
  python tests/plugin_server/run_dedicated_sim_pause.py
# EXIT 0 — [lg] PASS core profile
```

Observed:

- `[core.vm] module mapped: plugin_core_vm.dll`
- `[plugin_core_vm] ds_core_vm_run_signature_and_replace stub — implementation still in Injector`
- `[core.vm] ds_core_vm_run_signature_and_replace returned false — using legacy Injector signature/replace`
- DynamicPluginLoader loaded `plugin_core_vm` + existing plugins
- EarlyNative: `core.vm` stub load, network.rpc, save.fork, debug.dummy
- Tokens: `LG_MOD_LOADED`, `LG_INJECT_OK`, `LG_PLUGINS_OK`, `LG_WORLD_READY`, `LG_SIM_PAUSED`, `LG_STABLE`
- Server exit 0

### Without stub (DLL renamed away)

```text
# plugin_core_vm.dll → plugin_core_vm.dll.off
# EXIT 0 — [lg] PASS core profile
```

Observed:

- `[core.vm] module not found (optional): plugin_core_vm.dll`
- Legacy path still runs; inject + plugins continue
- Tokens + PASS as above

DLL restored after test.

## Acceptance checklist

- [x] `CoreVmBootstrap.hpp` / `.cpp` created
- [x] `EnsureCoreVmModuleLoaded` optional load (GetModuleHandle / LoadLibrary plugins dir)
- [x] `GetRunSignatureAndReplaceFn` → `ds_core_vm_run_signature_and_replace`
- [x] `TryRunSignatureAndReplace` + legacy fallback
- [x] VM block extracted to `LegacySignatureAndReplaceInInjector` (still in Injector)
- [x] Inject uses TryRun when `VmPathEnabled`; missing module does not abort
- [x] Stub `plugin_core_vm` (core.vm, AlwaysOn, EarlyNative, priority 10, export returns false)
- [x] CMake: CoreVmBootstrap in Injector; `ds_add_dynamic_plugin(plugin_core_vm)` all platforms
- [x] Build OK; staged
- [x] L-G PASS with stub
- [x] L-G PASS without stub
- [x] Commit `feat(core.vm): optional module loader + stub plugin (V-S1)`
- [x] Report `.superpowers/sdd/core-vm-task-2-report.md`
