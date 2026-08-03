# Task 4 Report — M1 migrate `sim.lagcomp` and `network.sim`

**Status:** DONE  
**Date:** 2026-08-03  
**Commit:** `c595fab` — `feat(plugin): migrate sim.lagcomp and network.sim Lua faces (M1 Task 4)`

## Summary

Migrated the Lua faces of dual-face plugins `sim.lagcomp` and `network.sim` onto the pure-Lua PluginHost. Both are registered from `plugins/init.lua` with priority 60 and option gates matching the former modmain hard-wires. Hard-wired `EnableLagCompensation` / `EnableNetSim` `modimport` blocks are removed; host `load_phase(AfterModMain)` owns those paths. Native `GameSimHook` / `GameNetworkSim` stay as lazy API backends (unchanged). L-E enable-matrix rows green for both options; lua host suite green.

## Changes

### Created
| File | Role |
|---|---|
| `Mod/plugins/sim_lagcomp.lua` | Lua plugin: id `sim.lagcomp`, option `EnableLagCompensation`, priority 60, when has_luajit+windows+mastersim → `modimport("scripts/lag_compensation")` |
| `Mod/plugins/network_sim.lua` | Lua plugin: id `network.sim`, option `EnableNetSim`, priority 60, when has_luajit+windows+not mastersim → `modimport("scripts/netsim")` |
| `.superpowers/sdd/task-4-report.md` | This report |

### Modified
| File | Change |
|---|---|
| `Mod/plugins/init.lua` | Registry returns `save_fork`, `sim_lagcomp`, `network_sim` |
| `Mod/modmain.lua` | Extended `gate_ctx` with `is_windows` / `is_mastersim`; removed hard-wired lagcomp/netsim blocks |
| `tests/plugin/plugin_host_lua_spec.lua` | L-E matrix: EnableLagCompensation / EnableNetSim true/false + when gates; save.fork lookup by id |

## Behavior (production)

```text
HookGetModConfigData()
→ PluginHost: register_all([save.fork, sim.lagcomp, network.sim])
→ resolve(GetModConfigData, {has_luajit, is_client, is_windows, is_mastersim})
→ load_phase(AfterModMain)
   when EnableLagCompensation on + has_luajit + windows + mastersim:
     modimport("scripts/lag_compensation")
   when EnableNetSim on + has_luajit + windows + not mastersim:
     modimport("scripts/netsim")
   else for each: Disabled, no load
→ … remaining hard-wired features (HideGlobalJIT, GC policy, …)
```

`gate_ctx.is_mastersim` is `TheWorld and TheWorld.ismastersim` so boolean `false` (client shard with world) is distinct from `nil` (world not ready). Plugins fall back to `TheWorld` when the field is unset — same readiness requirement as the former hard-wires.

Native faces: lag-comp / netsim symbols remain exported by injector bridge; Lua faces only wrap game APIs when those backends exist (`scripts/*.lua` early-return if missing).

## Verification

```text
python tests/plugin/run_lua_host.py
→ PASS: empty_registry … sticky_and_reload, config_function_getmodconfigdata
→ PASS: save_fork_enable_matrix
→ PASS: sim_lagcomp_enable_matrix
→ PASS: network_sim_enable_matrix
→ PASS: option_rules_unit
→ plugin_host_lua_spec: all tests passed
```

## L-E matrix rows covered

| Plugin | Config / gate | Expected |
|---|---|---|
| `sim.lagcomp` | EnableLagCompensation=true, has_luajit, windows, mastersim | Loaded, load_count=1, modimport `scripts/lag_compensation` |
| `sim.lagcomp` | EnableLagCompensation=false, same gates | Disabled, load_count=0 |
| `sim.lagcomp` | option on, not mastersim | Disabled |
| `sim.lagcomp` | option on, not windows | Disabled |
| `sim.lagcomp` | option on, no luajit | Disabled |
| `network.sim` | EnableNetSim=true, has_luajit, windows, not mastersim | Loaded, load_count=1, modimport `scripts/netsim` |
| `network.sim` | EnableNetSim=false, same gates | Disabled, load_count=0 |
| `network.sim` | option on, mastersim | Disabled |
| `network.sim` | option on, not windows | Disabled |
| `network.sim` | option on, no luajit | Disabled |

## Intentionally deferred

- Native sticky no-op plugins for API documentation (optional; APIs already exported).
- Remaining hard-wired modmain features (jit/gc/HideGlobalJIT, network.rpc/entity, …).
- Dual-face shared host state with C++ PluginHost (not required; Lua face independent).

## Acceptance checklist

- [x] Step 1: L-E enable-matrix rows for sim.lagcomp + network.sim (true/false + when)
- [x] Step 2: Register plugins; remove hard-wired modmain paths
- [x] Step 3: lua host tests green
- [x] Step 4: Commit + report at `.superpowers/sdd/task-4-report.md`
