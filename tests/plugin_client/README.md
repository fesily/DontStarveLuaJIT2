# plugin_client (L-C client inject smoke)

Automated client proof for Injector + mod/plugins + world stability + optional config profiles.

Spec: `docs/superpowers/specs/2026-08-03-client-inject-smoke-design.md`

## Contract tokens

```text
[lc_probe] TOKEN LG_CLIENT_MOD_LOADED ...
[lc_probe] TOKEN LG_CLIENT_INJECT_OK ...
[lc_probe] TOKEN LG_CLIENT_PLUGINS_OK ...
[lc_probe] TOKEN LG_CLIENT_CONFIG_SRC <main-modname>
[lc_probe] TOKEN LG_CLIENT_CONFIG key=value
[lc_probe] TOKEN LG_CLIENT_WORLD_READY ...
```

Orchestrator then holds `LC_T_HOLD` (default 30s) and prints `LG_CLIENT_STABLE`.

Every launched run also prints `[lc] TIMINGS {...}` with separate server and
client readiness times and the total test time. `--timings-json <path>` (or
`LC_TIMINGS_JSON`) saves those measurements. Readiness excludes the stability
hold and teardown; total time includes them. Paired worldgen/startup performance
profiles are documented in `tests/performance/README.md`.

## Default mode (P1b)

1. Create an isolated offline dedicated cluster `LGPluginTest` in a temporary
   absolute save directory (same helper as L-G), then launch with `-offline`.
   No existing cluster or `cluster_token` is needed.
2. Install `plugin_lc_probe` + `stress_test_bot`.
3. Launch `dontstarve_steam_x64` with the inject shell (`Winmm.dll` in `bin64`; real `Injector.dll` at the mod root),
   `-offline -debug_random_data -force_enable_mods=plugin_lc_probe;stress_test_bot`
   (**`;` separator** — Injector `split_string` in `GameLua.cpp`).
4. Wait for the dedicated world's session identifier. Stress bot disables saved
   AutoLogin for this offline run, enters offline mode, then connects via
   `c_connect("127.0.0.1", 10999)` (`STRESS_LAN_OFFLINE=1`,
   `STRESS_CONNECT_IP=127.0.0.1`, `STRESS_CONNECT_PORT=10999`) and auto-spawns;
   probe emits tokens. Dedicated and client share `AppVersionDevPatch=1` so the
   native version check sees the same branch on Windows.
5. Hold + kill + remove temporary dedicated save directory.

## Phase-2: mod config profiles

`mod_config.py` rewrites the client `modconfiguration_*` KLEI Lua file **before** launch
(path: `Documents/Klei/DoNotStarveTogether/<steam_id>/client_save/mod_config_data/`).

Profiles:

| Profile | File | Intent |
|---|---|---|
| `defaults` | `profiles/defaults.json` | no-op (`{}`) |
| `minimal` | `profiles/minimal.json` | risk-off: VBPool/NetSim/LagComp/ForkSave/NetworkOpt off |

```bash
# inspect current saved options
python tests/plugin_client/mod_config.py show

# apply profile only
python tests/plugin_client/mod_config.py apply --profile minimal

# restore first backup (original before first apply)
python tests/plugin_client/mod_config.py restore

# smoke with profile (applies then asserts LG_CLIENT_CONFIG)
set LC_T_HOLD=15
python tests/plugin_client/run_client_inject_smoke.py --cluster LGPluginTest --profile minimal
```

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

## Mode: host (client-hosted)

Single process: steam client hosts offline world (`TheNet:StartServer` + LOAD_SLOT).
No dedicated. No stress_test_bot force_enable.

```bash
set LC_T_HOLD=15
set LC_HOST_SLOT=1
python tests/plugin_client/run_client_inject_smoke.py --mode host

# with profile
python tests/plugin_client/run_client_inject_smoke.py --mode host --profile minimal

# empty-slot auto worldgen (new free local slot)
set LC_HOST_SLOT=new
python tests/plugin_client/run_client_inject_smoke.py --mode host

# force wipe slot then worldgen (destructive)
set LC_HOST_SLOT=1
set LC_HOST_FORCE_EMPTY=1
python tests/plugin_client/run_client_inject_smoke.py --mode host
```

Tokens: existing `LG_CLIENT_*` plus:

- `LG_CLIENT_HOST_BEGIN` / `LG_CLIENT_HOST_STARTED`
- `LG_CLIENT_HOST_EMPTY_SLOT` when slot empty → `SetServerShardData` worldgen path
- `LG_CLIENT_HOST_OK` / `LG_CLIENT_HOST_FAIL`

`LC_HOST_SLOT`: numeric slot (default `1`), or `new`/`0` for first free local slot.
`LC_HOST_FORCE_EMPTY=1`: delete chosen slot before host (worldgen).
`LC_T_HOST`: host-ok wait window (default 120s). Worldgen may need higher `LC_T_WORLD`.

CTest: `plugin_client_host_smoke` (`LC_MODE=host` / `--mode host`, TIMEOUT 900; SKIP without game same as sibling).


## Prerequisites

- Built Injector at the mod root (mod root `Injector.dll`)
- `bin64/steam_appid.txt` (contents `322330`) — required for the direct (non-Steam) client
  launch; the harness writes it when missing
- Steam client binary present
- GPU/desktop session for client window
- For `--profile`: existing `modconfiguration_workshop-3444078585_dev` (launch client once with mod)
