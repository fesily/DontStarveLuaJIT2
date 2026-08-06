# Task 2 Report: Wire DynamicPluginLoader + CoreVmBootstrap + manager inventory

**Status:** DONE_WITH_CONCERNS  
**Commit:** `66d7acb` — `feat(plugin): load plugins from mod dir + deps DLL search`  
**Base:** `7d8340c` (Task 1 PluginPath helpers)  
**Branch:** `master`  
**Date:** 2026-08-06

## Summary

Wired loader, core.vm bootstrap, and plugin_manager inventory onto the shared `ds::plugin` PluginPath search policy from Task 1. Production modmain path is supplied via `set_modmain_path_provider` after `LoadGameModConfig()` and before `DynamicPluginLoader::load_all`. Windows loads use `LOAD_LIBRARY_SEARCH_USER_DIRS` together with `configure_plugin_dll_search` so `plugins/` and `plugins/deps/` are visible to dependent DLLs.

## Files

| Path | Action |
|------|--------|
| `src/DontStarveInjector/core/DynamicPluginLoader.cpp` | Replace private search/`injector_module_dir` with `default_plugin_search_dirs`; configure DLL search in `load_all` + `load_directory`; add `LOAD_LIBRARY_SEARCH_USER_DIRS` |
| `src/DontStarveInjector/core/CoreVmBootstrap.cpp` | Probe all `default_plugin_search_dirs()` for `plugin_core_vm.*`; same LoadLibraryEx flags; drop private `injector_module_dir` |
| `src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.cpp` | `resolve_plugins_dir` uses shared search dirs + fallback; remove private path helpers / platform includes |
| `src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.hpp` | Document shared `plugins_dir_from_module_dir` / new resolve policy |
| `src/DontStarveInjector/plugins/plugin_manager/CMakeLists.txt` | Compile `core/PluginPath.cpp` into plugin_manager (symbols not exported from Injector import lib) |
| `src/DontStarveInjector/DontStarveInjector.cpp` | Register production `ModmainPathProvider` from `luajit_config::read_from_file()->modmain_path` before `load_all` |
| `tests/CMakeLists.txt` | Link `PluginPath.cpp` into `test_dynamic_plugin_loader` and `test_plugin_local_inventory` |

## Behavior changes

### Search policy (single source)

1. `DS_LUAJIT_PLUGIN_DIR` if set and is a directory  
2. `parent(modmain_path)/plugins` via provider/override when that dir exists  
3. `plugins_dir_from_module_dir(injector_module_dir())` when that dir exists  

`DynamicPluginLoader::default_search_dirs()` is now a thin wrapper around `default_plugin_search_dirs()`.

### DLL search (Windows)

- `load_all`: `configure_plugin_dll_search(dirs)` once before scanning roots.  
- `load_directory`: also `configure_plugin_dll_search({dir})` so the test seam registers that root’s `deps/`.  
- `LoadLibraryExW` flags:  
  `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS`  
  with plain `LoadLibraryW` fallback unchanged.  
- Core.vm bootstrap uses the same flags when mapping `plugin_core_vm` from each search root.

### Production modmain provider

```cpp
LoadGameModConfig();
ds::plugin::set_modmain_path_provider([]() -> std::string {
    if (auto cfg = luajit_config::read_from_file(); cfg) {
        return cfg->modmain_path;
    }
    return {};
});
// then DynamicPluginLoader::load_all(...)
```

Test override (`set_modmain_path_override_for_test`) remains the unit-test seam; production never uses it.

### Plugin manager inventory

```cpp
std::filesystem::path resolve_plugins_dir() {
    auto dirs = default_plugin_search_dirs();
    if (!dirs.empty()) return dirs.front();
    return plugins_dir_from_module_dir(injector_module_dir()); // may not exist yet
}
```

`plugins_dir_from_module_dir` is no longer defined in this TU; declaration stays in the public header and the definition comes from `PluginPath.cpp` (linked into plugin_manager and inventory unit tests).

## Build + verification

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target Injector plugin_core_vm plugin_manager \
           test_plugin_path test_dynamic_plugin_loader test_plugin_local_inventory -j 4
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_plugin_path.exe
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_dynamic_plugin_loader.exe
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_plugin_local_inventory.exe
```

Results:

```text
PASS: plugins_dir_from_modmain
PASS: search_order_env_wins
PASS: search_order_mod_without_env
PASS: deps_dir_name
PASS: configure_dll_search_idempotent
ALL PASS: plugin_path

PASS: empty_dir
PASS: noise_ignored
PASS: bad_library_skipped
ALL PASS dynamic_plugin_loader

PASS: scan_meta_and_module
...
PASS: plugins_dir_from_module_dir
ALL PASS plugin_local_inventory
```

Also linked successfully: `Injector.dll`, `plugin_core_vm.dll`, `plugin_manager.dll`.

## Link note (plugin_manager)

First link of `plugin_manager` failed with unresolved `default_plugin_search_dirs` / `injector_module_dir` / `plugins_dir_from_module_dir` because Injector does not export those C++ symbols on its import lib. Fixed by compiling `core/PluginPath.cpp` into the `plugin_manager` MODULE (and into `test_plugin_local_inventory`). This duplicates the TU in process when both Injector and plugin_manager are loaded; provider state lives in Injector’s copy (production load path), while inventory path resolution in the manager MODULE uses its own PluginPath globals (env + module-dir still work; modmain provider set in Injector is not visible to the manager’s copy).

## Self-review

- Private `injector_module_dir` / `try_push_dir` duplicates removed from DynamicPluginLoader and CoreVmBootstrap.  
- Inventory no longer reimplements leaf/`plugins` path logic.  
- Provider registration order is after `LoadGameModConfig` and before `load_all`.  
- Focused unit tests all pass; no install.bat / CMake install policy changes (Tasks 3–4).  
- `DynamicPluginLoader.hpp` left unchanged (wrapper stays in `.cpp` only).

## Concerns (original Task 2)

1. ~~**Duplicate PluginPath TU**~~ — **FIXED** (see below).  
2. **MSVC C4819** on some plugin_manager headers remains (pre-existing code-page noise); not introduced as functional breakage.  
3. **No in-game L-G smoke** in this task — unit + link only, per brief Step 6.  
4. ~~**`plugins_dir_from_module_dir` still declared from inventory header**~~ — **FIXED**: inventory header now includes `core/PluginPath.hpp` and reuses the exported declaration.

## Commit (original)

```text
66d7acb feat(plugin): load plugins from mod dir + deps DLL search
```

7 files, +72 / −163.

---

## Follow-up fix: share PluginPath state with plugin_manager

**Status:** DONE  
**Commit:** `fix(plugin): share PluginPath state with plugin_manager`  
**Date:** 2026-08-06  
**Finding:** Important — unshared PluginPath globals between Injector and plugin_manager.

### Problem

`plugin_manager/CMakeLists.txt` compiled its own `core/PluginPath.cpp`. Injector’s `set_modmain_path_provider` only mutated Injector’s statics. Manager `resolve_plugins_dir()` → `default_plugin_search_dirs()` never saw `modmain_path`, so `parent(modmain)/plugins` was skipped when only that root differed from injector-module plugins.

### Fix (preferred path)

Process-wide sharing via Injector export:

1. **`PluginPath.hpp`**: mark all free functions with `DS_INJECTOR_CXX_API` (existing Injector C++ export macro from `InjectorHostConfig.hpp`). Document that plugins must import, not recompile, PluginPath.
2. **`plugin_manager/CMakeLists.txt`**: stop compiling `PluginPath.cpp`; rely on `ds_add_dynamic_plugin` → link against Injector import lib.
3. **`PluginLocalInventory.hpp`**: include `core/PluginPath.hpp` so `plugins_dir_from_module_dir` / search helpers come from the exported header (no local re-declaration that clashed with dllimport).
4. **`tests/CMakeLists.txt`**: `test_plugin_local_inventory` still compiles `PluginPath.cpp` statically and sets `DS_PLUGIN_HOST_STATIC` so export macros are empty in the test image.

Unit tests (`test_plugin_path`, `test_dynamic_plugin_loader`) already used `DS_PLUGIN_HOST_STATIC` + static PluginPath — unchanged and still valid.

### Files

| Path | Action |
|------|--------|
| `src/DontStarveInjector/core/PluginPath.hpp` | Export all PluginPath APIs with `DS_INJECTOR_CXX_API`; process-wide ownership notes |
| `src/DontStarveInjector/plugins/plugin_manager/CMakeLists.txt` | Remove `PluginPath.cpp` from MODULE sources |
| `src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.hpp` | Include `core/PluginPath.hpp`; drop local `plugins_dir_from_module_dir` redeclare |
| `src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.cpp` | Drop redundant `PluginPath.hpp` include (via inventory header) |
| `tests/CMakeLists.txt` | `DS_PLUGIN_HOST_STATIC` on `test_plugin_local_inventory` |

### Verification

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target Injector plugin_manager test_plugin_path \
           test_dynamic_plugin_loader test_plugin_local_inventory -j 4
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_plugin_path.exe
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_dynamic_plugin_loader.exe
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_plugin_local_inventory.exe
```

Results:

```text
PASS: plugins_dir_from_modmain
PASS: search_order_env_wins
PASS: search_order_mod_without_env
PASS: deps_dir_name
PASS: configure_dll_search_idempotent
ALL PASS: plugin_path

PASS: empty_dir
PASS: noise_ignored
PASS: bad_library_skipped
ALL PASS dynamic_plugin_loader

PASS: scan_meta_and_module
PASS: module_without_meta_version_unknown
PASS: missing_dir_empty
PASS: status_override_update_available
PASS: status_local_only_ok
PASS: plan_mismatch_and_prefer_present
PASS: plan_missing_override
PASS: status_with_channel_cache
PASS: plugins_dir_from_module_dir
ALL PASS plugin_local_inventory
```

Link evidence:

- `Injector.dll` exports mangled PluginPath symbols (`default_plugin_search_dirs`, `set_modmain_path_provider`, `injector_module_dir`, `plugins_dir_from_module_dir`, …).
- `plugin_manager.dll` imports those symbols from Injector (no private PluginPath TU).

### Self-review

- Preferred process-wide share path taken (not the dual-provider alternative).
- Fail-fast: no silent wrong root from a second set of PluginPath globals.
- Tests that need a static image still compile PluginPath with `DS_PLUGIN_HOST_STATIC`.
- No change to production provider registration order in `DontStarveInjector.cpp`.
