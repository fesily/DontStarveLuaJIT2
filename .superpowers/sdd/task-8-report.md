# Task 8 Report — M5 trunk surface + L-F check

**Status:** DONE  
**Date:** 2026-08-03  
**Commit:** `93dc0c0` — `test(plugin): add L-F trunk surface check (M5 Task 8)`

## Summary

M5 L-F trunk surface gate is in place and green. Feature entrypoints already live only in PluginHost plugins (Tasks 1–7); trunks required no further slim edits.

| Check | Target | Result |
|---|---|---|
| Inject() | no `GameNetWorkHookRpc4` / `InitGameOpenGl` / `DS_LUAJIT_set_vbpool_enabled` | clean |
| LoadGameModConfig() | no VBPool / OpenGL side effects | clean (L0 thread-name only on Win) |
| modmain `_M:Main` | no direct `modimport` of `scripts/fork_save`, `lag_compensation`, `netsim` | clean |

## Changes

### Created
| File | Role |
|---|---|
| `tests/plugin/check_trunk_surface.py` | L-F static check: brace-aware Inject/LoadGameModConfig scan + modmain Main modimport banlist; exit 0/1 |
| `.superpowers/sdd/task-8-report.md` | This report |

### Modified
| File | Change |
|---|---|
| `tests/CMakeLists.txt` | `add_test(NAME plugin_trunk_surface … check_trunk_surface.py ${CMAKE_SOURCE_DIR})` |

### Slim (already done by M1–M4; verified no remaining violations)
| File | Host-only path |
|---|---|
| `DontStarveInjector.cpp` `Inject()` | `LoadGameModConfig` → `RegisterBuiltinPlugins` → resolve → `load_phase(EarlyNative)` → `DisableScriptZip` |
| `gameModConfig.cpp` `LoadGameModConfig()` | resolve cascade via `GameJitModConfig`; Win `repalce_set_thread_name` only |
| `Mod/modmain.lua` `_M:Main` | PluginHost AfterModMain; no feature modimports |

## L-F rules enforced

1. **Inject forbidden:** identifier call sites of `GameNetWorkHookRpc4`, `InitGameOpenGl`, `DS_LUAJIT_set_vbpool_enabled` inside `Inject(bool)` body (comments/strings ignored).
2. **LoadGameModConfig forbidden:** same for `DS_LUAJIT_set_vbpool_enabled`, `InitGameOpenGl` (VBPool/OpenGL side effects).
3. **modmain forbidden:** `modimport("scripts/fork_save"|"scripts/lag_compensation"|"scripts/netsim")` and bare name variants inside `_M:Main`.

Allowed: L0 + PluginHost (`ReplaceLuaModule`, signatures, crash guard, `RegisterBuiltinPlugins`, `PluginHost::*`).

## Verification

```text
python tests/plugin/check_trunk_surface.py .
→ L-F trunk surface OK

builds/test_plugin_host_graph.exe
→ All host graph tests passed!

builds/test_plugin_option_rules.exe
→ All option rule tests passed!

builds/test_plugin_config_bridge.exe
→ All plugin config bridge tests passed!

python tests/plugin/run_lua_host.py
→ plugin_host_lua_spec: all tests passed

builds/ninja-multi-vcpkg/luajit/Release/luajit.exe tests/fork_save/fork_save_spec.lua
→ fork_save_spec: all tests passed
```

## Acceptance checklist

- [x] Step 1: Write L-F script (`check_trunk_surface.py`)
- [x] Step 2: Fix trunks until L-F green (already green; no source slim needed)
- [x] Step 3: Full unit suite relevant tests + lua host + fork_save_lua green
- [x] Step 4: Commit + this report
- [x] Wire ctest `plugin_trunk_surface`

## Notes

1. No production trunk edits this task — migrations in Tasks 3–7 already removed hard-wires.
2. Feature implementations remain in plugins / `RegisterBuiltinPlugins` / `Mod/plugins/*`; L-F only guards the three trunks.
3. L-G dedicated sim pause is out of Task 8 scope (M-G / Task 10).
4. CMake configure not re-run; `plugin_trunk_surface` lands on next cmake gen. Script is runnable standalone.
