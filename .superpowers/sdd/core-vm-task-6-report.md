# Core VM Task 6 Report — Docs + deploy (V-S5)

**Status:** DONE  
**Base:** `120e339` (`test(core.vm): optional module degradation matrix`)  
**Commit:** `docs(plugin): core.vm optional deployment and plugin-system notes`  
**Date:** 2026-08-04

## Summary

Documented optional `plugin_core_vm` (id `core.vm`) as the JIT path: recommended for deploy, not required for inject or most feature plugins. Architecture D3 is annotated as **superseded for VM implementation ownership** only — AlwaysEnableMod + VM path *gate* remain L0. `RegisterBuiltinPlugins` comment lists `plugin_core_vm` but keeps the static registry empty. Injector CMake `SOURCES` greps clean of `GameLua.cpp` / `DontStarveSignature.cpp` (they live only under `PLUGIN_CORE_VM_SOURCES`). Unit gates + L-G `present` PASS.

## Docs

### `docs/plugin-system.md`

| Change | Detail |
|---|---|
| §1 L0 table | VM selection no longer listed as L0 `GameLua.cpp`; `DisableJITWhenServer` documented as **VM-path-only** gate |
| §1 D3 note | Implementation ownership superseded → optional `plugin_core_vm`; gate/AlwaysEnableMod still L0 |
| §2 load phases | `VmPathEnabled` → `CoreVmBootstrap` before config/plugins; soft-skip if DLL missing |
| §3 shipped modules | `plugin_core_vm` first row — **optional, recommended for JIT** |
| §3.3 static registry | Explicit: do not register `core.vm` in builtins |
| §6.1 inventory | `core.vm` AlwaysOn priority 10; save.fork / sim.lagcomp rows |
| §10 paths | `CoreVmBootstrap`, `plugin_core_vm/`, core.vm design spec |
| §11.1 deploy list | `Injector.dll` required; `plugins/plugin_core_vm.dll` recommended for JIT; feature plugins independent |

### Architecture D3

`docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` D3 row: gate + AlwaysEnableMod stay L0; VM **implementation** (Signature + ReplaceLuaModule + GameLua) lives in optional `plugin_core_vm` per `2026-08-04-core-vm-plugin-design.md`.

### `RegisterBuiltinPlugins.cpp`

Comment list includes `plugin_core_vm → core.vm (optional JIT)`; body remains empty extension point.

## Grep (CMake SOURCES)

```text
Injector set(SOURCES …): no GameLua.cpp / DontStarveSignature.cpp
PLUGIN_CORE_VM_SOURCES only:
  plugins/plugin_core_vm/GameLua.cpp
  plugins/plugin_core_vm/DontStarveSignature.cpp
→ GREP CLEAN
```

## Gates

### ctest `-R "plugin_|config_" -E "plugin_dedicated|plugin_client"`

Built missing RelWithDebInfo unit binaries, then:

| Test | Result |
|---|---|
| plugin_host_graph | PASS |
| plugin_option_rules | PASS |
| config_schema | PASS |
| config_view_build | PASS |
| plugin_config_bridge | PASS (alias) |
| plugin_dynamic_loader | PASS |
| plugin_host_lua | PASS |
| plugin_trunk_surface | PASS |

### L-G present

```bash
python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
```

Evidence:

```text
[core.vm] module mapped: plugin_core_vm.dll
[plugin_core_vm] running signature + ReplaceLuaModule
Applied Lua VM type: jit …
lua_newstate … vm=jit
TOKEN LG_MOD_LOADED / LG_INJECT_OK / LG_PLUGINS_OK / LG_WORLD_READY / LG_SIM_PAUSED
LG_STABLE
[lg] PASS core profile scenario=present
server exit code=0
```

(Parallel ctest dedicated run collided on port 10999 with the direct L-G; direct present run is the authoritative PASS.)

## Files

| Path | Change |
|---|---|
| `docs/plugin-system.md` | Optional core.vm, deploy, D3 note, inventory, paths |
| `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` | D3 supersession for VM implementation |
| `src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp` | Comment list + core.vm optional note |
| `.superpowers/sdd/core-vm-task-6-report.md` | this report |
| `.superpowers/sdd/core-vm-progress.md` | Task 6 complete |

## Checklist

- [x] Docs: core.vm optional; deploy recommended for JIT; feature plugins work without it
- [x] DisableJITWhenServer only skips VM path
- [x] D3 superseded for VM **implementation** ownership
- [x] RegisterBuiltinPlugins comment list includes core.vm (still empty body)
- [x] Grep: Injector SOURCES free of GameLua.cpp / DontStarveSignature.cpp
- [x] ctest plugin_/config_ unit gates green
- [x] L-G present PASS
- [x] Commit `docs(plugin): core.vm optional deployment and plugin-system notes`
- [x] Report + progress
