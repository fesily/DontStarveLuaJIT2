# plugin_client (L-C client inject smoke)

Phase-1 automated client proof for Injector + mod/plugins + world stability.

Spec: `docs/superpowers/specs/2026-08-03-client-inject-smoke-design.md`

## Contract tokens

Log lines:

```text
[lc_probe] TOKEN LG_CLIENT_MOD_LOADED ...
[lc_probe] TOKEN LG_CLIENT_INJECT_OK ...
[lc_probe] TOKEN LG_CLIENT_PLUGINS_OK ...
[lc_probe] TOKEN LG_CLIENT_WORLD_READY ...
```

Orchestrator then holds `LC_T_HOLD` (default 30s) and prints `LG_CLIENT_STABLE`.

## Default mode (P1b)

1. Start dedicated cluster `LGPluginTest` (same offline cluster as L-G).  
2. Install `plugin_lc_probe` + `stress_test_bot`.  
3. Launch `dontstarve_steam_x64` with inject (`Injector.dll` / `Winmm.dll` in `bin64`), `-offline -debug_random_data -force_enable_mods=plugin_lc_probe,stress_test_bot`.  
4. Stress bot LAN-joins and auto-spawns; probe emits tokens.  
5. Hold + kill.

## Run

```bash
# Skip without game
python tests/plugin_client/run_client_inject_smoke.py

# With game
set DST_GAME_DIR=C:\Program Files (x86)\Steam\steamapps\common\Don't Starve Together
set LC_T_HOLD=15
python tests/plugin_client/run_client_inject_smoke.py --cluster LGPluginTest
```

Exit: `0` PASS, `1` FAIL, `2` SKIP (mapped to 0 for ctest unless `LG_REQUIRE_GAME=1` / `LC_REQUIRE_GAME=1`).

## Prerequisites

- Built Injector installed to game `bin64`  
- Cluster `LGPluginTest` under Klei (offline) — create via L-G / design notes  
- Steam client binary present  
- GPU/desktop session for client window  

## Phase-2 (later)

`mod_config.py` + profiles under `profiles/` to rewrite `modconfiguration_*` before launch.
