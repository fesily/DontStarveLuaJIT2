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

## Prerequisites

- Pre-created DST cluster `LGPluginTest` (or `--cluster`) under Klei `DoNotStarveTogether` with `offline_server = true` recommended  
- Injector installed into game `bin64` (Windows winmm layout / Linux `LD_PRELOAD`)  
- Pause API: probe uses `TheNet:SetServerPaused(true)` (pinned on first green run)

## CTest

`plugin_dedicated_sim_pause` — without `DST_GAME_DIR` prints SKIP and exits 0 unless `LG_REQUIRE_GAME=1`.
