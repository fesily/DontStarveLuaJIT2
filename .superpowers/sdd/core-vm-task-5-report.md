# Core VM Task 5 Report — degradation matrix (V-S5)

**Status:** DONE  
**Base:** `c2a5cfa` (`fix(core.vm): init function_relocation ctx and export GameDbg APIs`)  
**Commit:** `test(core.vm): optional module degradation matrix`

## Summary

Verified optional `plugin_core_vm` degradation on dedicated L-G for three cells:

| Scenario | Expect | Result |
|---|---|---|
| core.vm present, VM enabled | Signature+replace; L-G PASS; vm=jit | **PASS** |
| core.vm absent, VM enabled | Warn skip; plugins still load; L-G PASS | **PASS** |
| VM disabled (`DisableJITWhenServer` / force env) | No signature; plugins load; L-G PASS | **PASS** |

Missing core.vm never aborts inject. `DynamicPluginLoader` continues. `GameInjector` is absent when VM path does not run (expected).

## Harness / env flags

`tests/plugin_server/run_dedicated_sim_pause.py`:

- `--scenario present|absent|vm_disabled` (or `LG_SCENARIO`)
- `absent`: renames `bin64/plugins/plugin_core_vm.dll` → `.off` (restored in `finally`) and sets `DS_LUAJIT_FORCE_NO_CORE_VM=1`
- `vm_disabled`: sets `DS_LUAJIT_FORCE_DISABLE_VM=1` (equivalent gate to `DisableJITWhenServer` without mutating `luajit_config.json`)
- Degradation cells require **native** plugin load evidence (`[DynamicPluginLoader] loaded:` / plugin init lines), not `LG_INJECT_OK` (GameInjector is core.vm-owned)

Native helpers:

| Env | Effect |
|---|---|
| `DS_LUAJIT_FORCE_NO_CORE_VM=1` | `EnsureCoreVmModuleLoaded` soft-miss (no map) |
| `DS_LUAJIT_FORCE_DISABLE_VM=1` | `VmPathEnabled` false on dedicated (same as `DisableJITWhenServer`) |

Stderr mirrors added so L-G capture sees skip/disabled lines even at default spdlog `err` level.

## How to re-run

```bash
export DST_GAME_DIR="C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together"
export LG_REQUIRE_GAME=1
export LG_T_HOLD=5

python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
python tests/plugin_server/run_dedicated_sim_pause.py --scenario absent
python tests/plugin_server/run_dedicated_sim_pause.py --scenario vm_disabled
```

## Scenario evidence (this machine, 2026-08-04)

### 1) present — core.vm present, VM enabled

```text
[core.vm] module mapped: plugin_core_vm.dll
[plugin_core_vm] running signature + ReplaceLuaModule
Applied Lua VM type: jit …
Reinitialized Lua VM runtime: ReplaceLuaModule startup vm=jit
[DynamicPluginLoader] loaded: …/plugin_core_vm.dll
[DynamicPluginLoader] loaded: …/plugin_dummy.dll
… (network.rpc, network.sim, render.angle, render.vbpool, save.fork, sim.lagcomp)
lua_newstate … vm=jit
TOKEN LG_MOD_LOADED
TOKEN LG_INJECT_OK GameInjector
TOKEN LG_PLUGINS_OK
TOKEN LG_WORLD_READY
TOKEN LG_SIM_PAUSED
LG_STABLE
[lg] PASS core profile scenario=present
server exit code=0
```

### 2) absent — rename + FORCE_NO_CORE_VM

```text
[lg] renamed plugin_core_vm.dll -> plugin_core_vm.dll.off
[core.vm] module not found (optional): plugin_core_vm.dll (DS_LUAJIT_FORCE_NO_CORE_VM=1)
[core.vm] ds_core_vm_run_signature_and_replace missing — skipping VM signature/replace
[core.vm] signature/replace path skipped — continuing inject
[DynamicPluginLoader] loaded: …/plugin_dummy.dll
… (all feature plugins; no plugin_core_vm.dll)
TOKEN LG_MOD_LOADED
TOKEN LG_INJECT_MISSING GameInjector nil
TOKEN LG_WORLD_READY
TOKEN LG_SIM_PAUSED
LG_STABLE
[lg] scenario[absent]: soft skip on missing core.vm
[lg] scenario[absent]: GameInjector absent (expected without core.vm)
[lg] scenario[absent]: native plugins still loaded
[lg] PASS core profile scenario=absent
[lg] restored plugin_core_vm.dll from plugin_core_vm.dll.off
server exit code=0
```

No crash / access violation. Inject continues after soft skip.

### 3) vm_disabled — DS_LUAJIT_FORCE_DISABLE_VM=1

```text
[core.vm] Lua VM path disabled — skipping signature/replace; native plugins continue
[plugin_core_vm] module init registered core.vm   # DLL may still map via DynamicPluginLoader
[DynamicPluginLoader] loaded: …/plugin_core_vm.dll
[DynamicPluginLoader] loaded: …/plugin_dummy.dll
… (feature plugins)
# NO: running signature + ReplaceLuaModule
# NO: vm=jit from ReplaceLuaModule
TOKEN LG_MOD_LOADED
TOKEN LG_INJECT_MISSING GameInjector nil
TOKEN LG_WORLD_READY
TOKEN LG_SIM_PAUSED
LG_STABLE
[lg] scenario[vm_disabled]: VmPathEnabled false / DisableJIT path
[lg] scenario[vm_disabled]: no signature/replace
[lg] scenario[vm_disabled]: GameInjector absent (expected)
[lg] scenario[vm_disabled]: native plugins still loaded
[lg] PASS core profile scenario=vm_disabled
server exit code=0
```

Note: with VM path disabled, `plugin_core_vm` may still register via `DynamicPluginLoader` / EarlyNative, but **signature + ReplaceLuaModule is not invoked**. That matches V-S0: gate only the VM path, not plugin load.

`DisableJITWhenServer` from `luajit_config.json` uses the same `VmPathEnabled` branch; force env avoids mutating the live config file during matrix runs.

## Files

| Path | Change |
|---|---|
| `src/DontStarveInjector/DontStarveInjector.cpp` | `DS_LUAJIT_FORCE_DISABLE_VM`; stderr mirror for skip/disabled |
| `src/DontStarveInjector/core/CoreVmBootstrap.cpp` | `DS_LUAJIT_FORCE_NO_CORE_VM`; `#include <cstdlib>` |
| `tests/plugin_server/run_dedicated_sim_pause.py` | `--scenario` matrix; rename/restore; degradation PASS criteria |
| `tests/plugin_server/README.md` | scenario docs |
| `.superpowers/sdd/core-vm-task-5-report.md` | this report |
| `.superpowers/sdd/core-vm-progress.md` | Task 5 complete |

## Checklist

- [x] present: signature+replace, vm=jit, L-G PASS, GameInjector
- [x] absent: rename plugin_core_vm.dll, soft skip, plugins load, L-G PASS, no crash
- [x] vm_disabled: no signature, plugins load, L-G PASS
- [x] harness `--scenario` + env flags for CI
- [x] report + progress
- [x] commit `test(core.vm): optional module degradation matrix`
