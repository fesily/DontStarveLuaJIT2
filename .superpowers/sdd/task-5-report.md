# Task 5 Report — M2 `network.rpc` + `network.entity` with depends

**Status:** DONE  
**Date:** 2026-08-03  
**Commit:** `90114ba` — `feat(plugin): migrate network.rpc + network.entity with hard depends (M2 Task 5)`

## Summary

Migrated dual-face `network.rpc` and Lua `network.entity` onto PluginHost.

- **Native:** `RegisterBuiltinPlugins` installs `network.rpc` EarlyNative; when `NetworkOpt` is enabled it calls `GameNetWorkHookRpc4()`. Unconditional dual-call removed from `Inject()`.
- **Lua:** `network_rpc.lua` applies former modmain NetWorkOpt channel wraps; `network_entity.lua` wraps `SpawnPrefab` and **hard-depends** `network.rpc`. Fail-fast `MissingHardDep` when entity is on and rpc is off.
- Priority 40 for both Lua faces (§7.3). Config bridge still supplies `NetworkOpt=true` default for EarlyNative (Lua resolve uses `GetModConfigData`).

## Changes

### Created
| File | Role |
|---|---|
| `Mod/plugins/network_rpc.lua` | Lua face: id `network.rpc`, option `NetworkOpt`, priority 40, TheNet SendRPC wraps |
| `Mod/plugins/network_entity.lua` | Lua face: id `network.entity`, option `NetworkOptEntity`, depends `network.rpc`, SpawnPrefab wrap |
| `.superpowers/sdd/task-5-report.md` | This report |

### Modified
| File | Change |
|---|---|
| `src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp` | Register static `NetworkRpcPlugin` EarlyNative → `GameNetWorkHookRpc4` when NetworkOpt |
| `src/DontStarveInjector/core/RegisterBuiltinPlugins.hpp` | Comment update |
| `src/DontStarveInjector/DontStarveInjector.cpp` | Remove unconditional `GameNetWorkHookRpc4()` after EarlyNative |
| `Mod/plugins/init.lua` | Registry adds `network_rpc`, `network_entity` |
| `Mod/modmain.lua` | Remove hard-wired `NetWorkOpt` function + call site |
| `tests/plugin/test_plugin_host_graph.cpp` | L-E NetworkOpt matrix + entity hard-dep matrix |
| `tests/plugin/test_plugin_config_bridge.cpp` | Bridge default enables network.rpc stand-in; off disables |
| `tests/plugin/plugin_host_lua_spec.lua` | L-E matrix for rpc on/off + entity×rpc (MissingHardDep) |
| `tests/CMakeLists.txt` | Bridge unit binary no longer links RegisterBuiltinPlugins (avoids GameNetwork) |

## Behavior (production)

```text
Inject:
  LoadGameModConfig
  → RegisterBuiltinPlugins (network.rpc)
  → FromGameJitModConfig (NetworkOpt default true)
  → resolve → load_phase(EarlyNative)
       when NetworkOpt: GameNetWorkHookRpc4()
  → DisableScriptZip
  // no dual-call GameNetWorkHookRpc4

modmain AfterModMain:
  host:register_all([save.fork, sim.lagcomp, network.sim, network.rpc, network.entity])
  → resolve(GetModConfigData, gate_ctx)
  → load_phase(AfterModMain)
       NetworkOpt on → network.rpc Lua wraps TheNet SendRPC*
       NetworkOptEntity on + network.rpc candidate → network.entity SpawnPrefab wrap
       NetworkOptEntity on + NetworkOpt off → network.entity Failed MissingHardDep
```

## Verification

```text
builds/test_plugin_host_graph.exe
→ PASS: … network_rpc_option_matrix, network_entity_hard_dep_on_rpc
→ All host graph tests passed!

builds/test_plugin_config_bridge.exe
→ PASS: … network_rpc_standin_from_bridge_default, network_rpc_standin_disabled_when_off
→ All plugin config bridge tests passed!

luajit tests/plugin/plugin_host_lua_spec.lua
→ PASS: … network_rpc_enable_matrix, network_entity_enable_matrix
→ plugin_host_lua_spec: all tests passed
```

## L-E matrix rows covered

| Plugin | Config | Expected |
|---|---|---|
| `network.rpc` (native) | NetworkOpt=true | EarlyNative Loaded (hook installed) |
| `network.rpc` (native) | NetworkOpt=false | Disabled, no hook |
| `network.rpc` (Lua) | NetworkOpt=true | AfterModMain Loaded, SendRPC wraps |
| `network.rpc` (Lua) | NetworkOpt=false | Disabled |
| `network.entity` | NetworkOptEntity=true, NetworkOpt=true | Loaded after rpc |
| `network.entity` | NetworkOptEntity=true, NetworkOpt=false | Failed MissingHardDep |
| `network.entity` | NetworkOptEntity=false, NetworkOpt=true | Disabled; rpc still loads |

## Intentionally deferred

- Native cascade ownership of NetworkOpt from save file (still bridge default true; Lua face uses GetModConfigData).
- Dual-face shared host instance across C++/Lua (independent faces, same id by convention).
- L-F trunk surface check (Task 8).

## Acceptance checklist

- [x] Step 1: L-E entity cannot load when rpc off; hard dep test
- [x] Step 2: Native+Lua faces; remove unconditional Inject / modmain hard-wires
- [x] Step 3: Host graph + lua host tests green
- [x] Step 4: Commit + report
