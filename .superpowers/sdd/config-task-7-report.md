# Config Task 7 Report: Schema-driven save/overrides parse (C-S6)

**Status:** DONE
**Commit:** `cadec46` — `refactor(config): schema-driven save/overrides parse (C-S6)`
**Base:** `9cd1c63` (Task 6 real EnableNetSim/NetworkOpt gates)
**Date:** 2026-08-04

## Summary

Replaced per-option `if (option_name == ModConfigurationOptions::X)` business parse branches with a schema-driven loop. L0 registers core option schema (AlwaysEnableMod / DisableJITWhenServer / LuaVmType / EnabledGenGC) plus builtin business keys for cascade parse before Host plugins load. Invalid values log an error and keep prior/default; unknown keys are ignored.

## Files

| Path | Change |
|------|--------|
| `src/DontStarveInjector/core/ConfigSchema.hpp` | Declare pure coerce helpers + `RegisterCoreOptionSchema` + `RegisterBuiltinBusinessOptionSchema` |
| `src/DontStarveInjector/core/ConfigSchema.cpp` | Implement coerce (Bool/String/Number) + core/business schema registration from modinfo defaults |
| `src/DontStarveInjector/core/PluginHost.hpp/.cpp` | Non-const `option_schema()` for Inject-time L0 registration |
| `src/DontStarveInjector/DontStarveInjector.cpp` | Register core + builtin business schema on Host before `load_all` / `BuildConfigView` |
| `src/DontStarveInjector/GameLuaModule.cpp` | Cascade schema + `try_coerce_saved_value` + schema loop for save and modoverrides; remove business if-chains |
| `tests/plugin/test_config_schema.cpp` | Coerce + core/business register + unknown-key-ignore unit tests |

## Design

### Cascade schema (save/overrides, pre-plugin)

```cpp
RegisterCoreOptionSchema(r);              // AlwaysEnableMod, DisableJITWhenServer, LuaVmType, EnabledGenGC
RegisterBuiltinBusinessOptionSchema(r);   // AngleBackend, EnableVBPool, NetworkOpt, EnableNetSim
```

`cascade_option_schema()` is a process-static registry used by `LoadGameJitModConfigFromSaveFile` / `LoadGameJitModConfigFromModOverridesFile`.

### Host schema (Inject, BuildConfigView)

```
RegisterCoreOptionSchema(host.option_schema())
RegisterBuiltinBusinessOptionSchema(host.option_schema())
load_all → plugins re-register same business keys (idempotent)
BuildConfigView(host.option_schema(), *modcfg)
```

Core keys always exist even with zero plugins.

### Coerce contract

| Type | Accepted raw | Failure |
|------|--------------|---------|
| Bool | bool, 0/1 number, "true"/"false"/"0"/"1" | return false |
| String | string; membership in `allowed` when non-empty; modoverrides may use 0-based index | return false |
| Number | number | return false |

On failure: `spdlog::error("invalid value for option {}", name)` and skip (keep prior/default). Unknown key: skip silently.

### Apply path

- Core keys → typed `GameJitModConfig` fields + `*Source = save_file`
- Business keys → `business_options[name] = value`

### Write-back

Unchanged parity: client save still writes core fields + AngleBackend + EnableVBPool. NetworkOpt/EnableNetSim remain read-path only (same as Task 4/6).

## Tests

### Unit (`ctest -R config_schema|plugin_config_bridge|plugin_host_graph|plugin_option_rules`)

All PASS:

- `register_core_option_schema` / `register_builtin_business_schema`
- `try_coerce_bool` / `try_coerce_string_allowed` / `try_coerce_number`
- `unknown_key_ignored_pattern`
- Existing bridge / host graph / option rule suites green

### L-G

Staged `Injector.dll` + `plugins/plugin_*.dll` to game `bin64`.

```text
DST_GAME_DIR=…/Don't Starve Together LG_T_HOLD=5 LG_REQUIRE_GAME=1 \
  python tests/plugin_server/run_dedicated_sim_pause.py
```

**Result:** PASS core profile (server exit 0).

Observed:

- Schema keys include core (AlwaysEnableMod, DisableJITWhenServer, LuaVmType, EnabledGenGC) **and** business (NetworkOpt, EnableNetSim, EnableVBPool, AngleBackend)
- Dynamic load: dummy, network.rpc, network.sim, render.angle, render.vbpool
- EarlyNative load: `network.rpc` + `debug.dummy` (EnableNetSim still default false → no sim load)
- Tokens: LG_MOD_LOADED, LG_INJECT_OK, LG_PLUGINS_OK, LG_WORLD_READY, LG_SIM_PAUSED, LG_STABLE

## Notes / follow-ups

1. **Task 8:** cleanup docs / optional gut of residual bridge naming; verify `rg` allowlist of business keys.
2. Client write-back still hardcodes AngleBackend/EnableVBPool (+ core). Schema-driven write of all business keys with save source is optional future polish (brief Step 4 kept parity).
3. New plugin option path: register schema in `ds_plugin_module_init` (+ cascade business register if cascade must parse before Host load). No new `GameJitModConfig` field required for business keys already in schema.

## Acceptance checklist

- [x] `RegisterCoreOptionSchema` with modinfo defaults
- [x] Core schema registered on Host before BuildConfigView
- [x] Pure coerce helpers for Bool/String/Number + allowed set
- [x] Save/overrides schema loop; unknown skip; invalid → error log + keep default
- [x] Dead business if-chains removed (AngleBackend/EnableVBPool/NetworkOpt/EnableNetSim)
- [x] Unit tests for coerce + unknown key
- [x] ctest unit gates PASS
- [x] L-G PASS
- [x] Commit `refactor(config): schema-driven save/overrides parse (C-S6)`
- [x] Report at `.superpowers/sdd/config-task-7-report.md`

## Fix: Important review findings

**Date:** 2026-08-04
**Commit:** `f4c70ba` — `fix(config): correct modinfo include and nil save coerce logging`

### Changes

1. **`ConfigSchema.cpp` include path**
   - Was: `#include "../modinfo.hpp"` (resolves to `src/DontStarveInjector/modinfo.hpp`, missing)
   - Now: `#include "../../modinfo.hpp"` (generated header at `src/modinfo.hpp`)

2. **Nil/absent saved values no longer error-log**
   - `LoadGameJitModConfigFromSaveFile` and `LoadGameJitModConfigFromModOverridesFile` now skip when the raw value is nil/absent (`is_nil_object`) without `spdlog::error`.
   - `spdlog::error("invalid value for option …")` only fires when a value is present but `try_coerce_saved_value` fails.

### Verification

```text
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_config_schema Injector -j 16
# [1/6]…[6/6] Linking Injector.dll — OK

ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo \
  -R "config_schema|plugin_config_bridge|plugin_host_graph" --output-on-failure -V
```

| Test | Result |
|------|--------|
| `plugin_host_graph` | Passed |
| `config_schema` | Passed |
| `plugin_config_bridge` | Passed |

`test_config_schema.exe` (direct): all 10 cases PASS including `register_core_option_schema`, coerce helpers, `unknown_key_ignored_pattern`.
