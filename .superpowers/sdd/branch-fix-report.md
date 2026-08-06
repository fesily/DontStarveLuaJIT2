# Branch fix report: mod-local plugins Important findings

**Date:** 2026-08-06  
**Range:** `ca20048..` (mod-local plugins work)  
**Fix agent:** BranchFixer  

## Findings addressed

### 1. First boot / empty `modmain_path` → zero plugins

**Problem:** Install stages plugins under mod `plugins/`, but search only used `parent(modmain_path)/plugins` when config already had `modmain_path`. First client boot and dedicated often have empty config → only injector fallback (or nothing).

**Fix:** In `default_plugin_search_dirs()`, when `resolve_modmain_path()` is empty, discover known mod roots:

- Game `mods/` (exe/injector parent → `mods/`)
- Steam UGC `…/workshop/content/322330`
- Folder aliases: `workshop-3444078585`, `3444078585`, `luajit`, `luajit2`, `DontStarveLuaJit2`, `DontStarveLuaJIT2`

Prefer roots that contain `plugins/` (and preferably `modmain.lua` / `modinfo.lua` / install scripts). Env `DS_LUAJIT_PLUGIN_DIR` still wins; injector `…/plugins` remains last-resort compat.

**Files:** `src/DontStarveInjector/core/PluginPath.cpp`, `PluginPath.hpp`

### 2. Missing diagnostics

**Fix:** stderr `log_once` in path helpers (safe before spdlog):

- warn when `modmain_path` set but `parent/plugins` missing
- warn when `modmain_path` empty and discovery finds nothing
- info when discovery succeeds
- warn when injector `plugins` is used as fallback / migration scan

### 3. Deps resolution test gate

**Fix:** Extended `tests/plugin/test_plugin_path.cpp`:

- `test_deps_registration_contract`: `plugins_deps_dir` identity, configure succeeds with/without `deps/`, deps never appears as a plugin search root
- `test_empty_modmain_does_not_crash`
- existing search-order / idempotent configure tests retained

**Residual gap:** No full PE `LoadLibrary` of a stub plugin that imports a DLL only present under `plugins/deps`. Unit gate fails if deps path naming/registration contract regresses; true import resolution still relies on Windows `AddDllDirectory` + `LoadLibraryEx` USER_DIRS (verified by loaders using those flags; L-G present exercises real plugin loads).

### 4. `SetDefaultDllDirectories` blast radius

**Fix:** Removed process-wide `SetDefaultDllDirectories` from `configure_plugin_dll_search`.

- Still calls `AddDllDirectory(root/deps)` and `AddDllDirectory(root)` when dirs exist
- Logs once if `AddDllDirectory` fails (`GetLastError`)
- `DynamicPluginLoader` / `CoreVmBootstrap` already pass  
  `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | DEFAULT_DIRS | USER_DIRS`

This keeps USER_DIRS resolution without changing default `LoadLibrary` behavior for the whole game process.

## Verification

```text
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target Injector plugin_core_vm plugin_manager \
           test_plugin_path test_dynamic_plugin_loader test_plugin_host_graph -j 4

test_plugin_path.exe              → ALL PASS (incl. deps_registration_contract)
test_dynamic_plugin_loader.exe    → ALL PASS
test_plugin_host_graph.exe        → All host graph tests passed!

L-G present (DS_LUAJIT_PLUGIN_DIR=…/RelWithDebInfo/plugins):
  [lg] PASS core profile scenario=present
  Observed: env plugins loaded first; injector plugins migration fallback warn;
            core.vm signature/replace; LG_INJECT_OK / LG_PLUGINS_OK / stable pause
```

## Commits

- `fix(plugin): discover mod plugins root when modmain_path empty`
- `fix(plugin): log empty modmain and injector plugins fallback`
- `fix(plugin): avoid process-wide SetDefaultDllDirectories when possible`
- `test(plugin): tighten deps path registration gates`

(Combined into one or few commits depending on staging; all changes live in PluginPath + test_plugin_path.)

## Residual risks

1. Discovery is best-effort over known aliases / standard Steam layout; nonstandard mod folder names still need `modmain_path` or `DS_LUAJIT_PLUGIN_DIR`.
2. Dual-root loads (env + leftover `bin64/plugins`) still possible on machines with old install copies — design keeps injector fallback; duplicate `plugin_core_vm` init can fail secondary with service conflict (seen in L-G, primary load OK).
3. No automated PE import-from-deps unit test (see §3 residual).
4. `AddDllDirectory` cookies are not removed (Windows API / process lifetime); test seam only clears bookkeeping.
