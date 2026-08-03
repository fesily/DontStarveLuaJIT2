# Task 3 Report — M1 migrate `save.fork` dual-face plugin

**Status:** DONE  
**Date:** 2026-08-03  
**Commit:** `b0ebb63` — `feat(plugin): migrate save.fork Lua face to PluginHost (M1 Task 3)`

## Summary

Migrated the Lua face of dual-face plugin `save.fork` onto the pure-Lua PluginHost. `Mod/plugins/save_fork.lua` is registered from `plugins/init.lua` with option `EnableForkSave`, priority 60, and `when` = dedicated + has_luajit. The hard-wired `modmain` `EnableForkSave` / `modimport("scripts/fork_save")` block is removed; host `load_phase(AfterModMain)` owns that path. Native `GameForkSave` already exports `DS_LUAJIT_fork_save*` — no EarlyNative plugin required. L-E enable-matrix rows green; `fork_save_lua` still green.

## Changes

### Created
| File | Role |
|---|---|
| `Mod/plugins/save_fork.lua` | Lua plugin: id `save.fork`, options `EnableForkSave`, priority 60, when dedicated+has_luajit, load → `AddGamePostInit` + `modimport("scripts/fork_save")` |
| `.superpowers/sdd/task-3-report.md` | This report |

### Modified
| File | Change |
|---|---|
| `Mod/plugins/init.lua` | Explicit registry returns `save_fork` (kleiloadlua under MODROOT; `require` in tests) |
| `Mod/modmain.lua` | Removed hard-wired EnableForkSave block; host comment notes migrated features |
| `tests/plugin/plugin_host_lua_spec.lua` | L-E matrix: EnableForkSave true/false + when gates (client / no luajit); replaces empty-registry assertion |

## Behavior (production)

```text
HookGetModConfigData()
→ PluginHost: register_all([save.fork]) → resolve(GetModConfigData, {has_luajit, is_client})
→ load_phase(AfterModMain)
   when EnableForkSave on + dedicated + has_luajit:
     print + AddGamePostInit → modimport("scripts/fork_save")
   else: Disabled, no load
→ … remaining hard-wired features (lagcomp, netsim, HideGlobalJIT, …)
```

Native face: APIs already registered on `GameInjector` by injector bridge (`GameForkSave.cpp`); Lua face only wraps `SaveGame` when native symbols exist (`scripts/fork_save.lua` early-returns if missing).

## Verification

```text
python tests/plugin/run_lua_host.py
→ PASS: empty_registry … sticky_and_reload, config_function_getmodconfigdata
→ PASS: save_fork_enable_matrix
→ PASS: option_rules_unit
→ plugin_host_lua_spec: all tests passed

# fork_save runner lacks project-build probe on PATH; direct project luajit:
builds/.../luajit/Release/luajit.exe tests/fork_save/fork_save_spec.lua
→ PASS: unsupported falls back
→ PASS: parent postsaves after child idle
→ PASS: parent truncates when empty
→ PASS: child saves and exits
→ PASS: other result falls back
→ PASS: child save failure exits
→ PASS: isshutdown uses main process
→ PASS: isshutdown ignores child fork result
→ fork_save_spec: all tests passed
```

Runtime: project `builds/ninja-multi-vcpkg/luajit/Release/luajit.exe`.

## L-E matrix rows covered

| Config / gate | Expected |
|---|---|
| EnableForkSave=true, has_luajit, dedicated (`is_client=false`) | Loaded, load_count=1, PostInit → `scripts/fork_save` |
| EnableForkSave=false, same gates | Disabled, load_count=0, no modimport |
| EnableForkSave=true, client | Disabled |
| EnableForkSave=true, no luajit | Disabled |

## Intentionally deferred

- Native sticky no-op plugin for API documentation (optional per brief; APIs already exported).
- `sim.lagcomp` / `network.sim` still hard-wired in modmain (Task 4).
- Dual-face shared host state with C++ PluginHost (not required; Lua face independent).

## Acceptance checklist

- [x] Step 1: L-E enable-matrix rows for save.fork (true/false + when)
- [x] Step 2: Register plugin; remove hard-wired modmain path
- [x] Step 3: fork_save_lua + lua host tests green
- [x] Step 4: Commit + report at `.superpowers/sdd/task-3-report.md`
