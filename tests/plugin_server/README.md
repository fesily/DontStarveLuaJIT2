# plugin_server (L-G harness)

Automated dedicated-server proof for plugin architecture (§12.10).

## Contract

1. Launch `dontstarve_dedicated_server_nullrenderer_x64` with inject  
2. Load probe mod `plugin_lg_probe`  
3. Markers: `LG_MOD_LOADED` → `LG_INJECT_OK` / `LG_PLUGINS_OK` → `LG_WORLD_READY` → `LG_SIM_PAUSED`  
4. Hold paused ≥ `LG_T_HOLD` (default 30s) → `LG_STABLE`  
5. Graceful shutdown  

## Run

```bash
# Skip without game (exit 0 unless LG_REQUIRE_GAME=1)
python tests/plugin_server/run_dedicated_sim_pause.py

# With game
set DST_GAME_DIR=C:\Program Files (x86)\Steam\steamapps\common\Don't Starve Together
set LG_REQUIRE_GAME=1
python tests/plugin_server/run_dedicated_sim_pause.py --cluster LGPluginTest
```

## core.vm degradation matrix (Task 5)

```bash
python tests/plugin_server/run_dedicated_sim_pause.py --scenario present      # default
python tests/plugin_server/run_dedicated_sim_pause.py --scenario absent       # rename plugin_core_vm.dll + FORCE_NO_CORE_VM
python tests/plugin_server/run_dedicated_sim_pause.py --scenario vm_disabled  # DS_LUAJIT_FORCE_DISABLE_VM=1
```

| Scenario | Env / staging | Expect |
|---|---|---|
| `present` | full plugins | signature+replace; `LG_INJECT_OK`; vm=jit |
| `absent` | rename `plugin_core_vm.dll` → `.off` + `DS_LUAJIT_FORCE_NO_CORE_VM=1` | soft skip; native plugins load; `LG_INJECT_MISSING` OK |
| `vm_disabled` | `DS_LUAJIT_FORCE_DISABLE_VM=1` (same gate as `DisableJITWhenServer`) | no signature; plugins load; `LG_INJECT_MISSING` OK |

`LG_SCENARIO` env overrides default scenario when CLI flag omitted.

## Prerequisites

- Built Injector at the mod root; inject shell in game `bin64` (Windows `Winmm.dll` / Linux stub `LD_PRELOAD`)
  — the harness resolves the mod-root module via `DS_LUAJIT_INJECTOR`
- Pause API: probe uses `TheNet:SetServerPaused(true)` (pinned on first green run)

The harness creates its own isolated cluster: an absolute temporary
`-persistent_storage_root` plus `offline_server = true` (`tests/harness/cluster.py`).
No pre-created `LGPluginTest` and no Klei `cluster_token.txt` are needed, and the
user's `~/.klei` tree is never touched. A relative `-persistent_storage_root`
(e.g. `APP:Klei/`) makes the native config-write probe fail on Linux
(`Check for write access: FALSE`) and aborts startup before mod load.

## CTest

`plugin_dedicated_sim_pause` — without `DST_GAME_DIR` prints SKIP and exits 0 unless `LG_REQUIRE_GAME=1`.
