# Task 3 Report: IConfigSource adapters + single resolve entry (CF-S2)

**Status:** DONE  
**Commit:** `67cd2e8` — `feat(config): IConfigSource cascade resolve behind GameJitModConfig::instance`  
**Base:** `2712b54` (Task 2 apply_partial)  
**Date:** 2026-08-05

## Summary

Introduced `IConfigSource` / `ResolvedConfig` / `ds::config::resolve`, four production source adapters, and routed `GameJitModConfig::instance` through resolve + `map_to_game_jit_mod_config` for compatibility. Path discovery remains under temporary `config/ConfigPathAccess.*` (physical `config/path/` move is Task 4).

## Files

| Path | Action |
|------|--------|
| `src/DontStarveInjector/config/IConfigSource.hpp` | Create — `CascadeContext`, `ConfigPartial`, `IConfigSource` |
| `src/DontStarveInjector/config/ResolvedConfig.hpp` | Create — `view` + `source_of` + ctx snapshot |
| `src/DontStarveInjector/config/CascadeEngine.hpp/.cpp` | Add injection `resolve(schema, ctx, sources)` |
| `src/DontStarveInjector/config/ConfigResolve.cpp` | Production `resolve(schema, ctx)` builds fixed layers |
| `src/DontStarveInjector/config/Compat.hpp` | `map_to_game_jit_mod_config` + `ToGameJitConfigSource` |
| `src/DontStarveInjector/config/ConfigPathAccess.hpp/.cpp` | Path/identity helpers extracted for sources |
| `src/DontStarveInjector/config/sources/ConfigSources.hpp` | Source class declarations |
| `src/DontStarveInjector/config/sources/ModinfoDefaultSource.cpp` | Schema defaults layer |
| `src/DontStarveInjector/config/sources/LuajitConfigSource.cpp` | `luajit_config.json` + identity |
| `src/DontStarveInjector/config/sources/SaveFileSource.cpp` | Client save (id=SaveFile) |
| `src/DontStarveInjector/config/sources/ModOverridesSource.cpp` | Server overrides (id=SaveFile) |
| `src/DontStarveInjector/config/sources/EnvOrCmdSource.cpp` | LuaVmType + AngleBackend env |
| `src/DontStarveInjector/config/sources/SaveParse.hpp/.cpp` | Shared sol2 coerce/read helpers |
| `src/DontStarveInjector/gameModConfig.cpp` | `load_resolved_game_mod_config` → resolve + map + client write-back |
| `src/DontStarveInjector/CMakeLists.txt` | Add new config sources |
| `tests/plugin/test_config_resolve.cpp` | Fake-source order/whitelist unit test |
| `tests/CMakeLists.txt` | `test_config_resolve` target |

## API

```cpp
namespace ds::config {
struct CascadeContext { bool is_client; uint32_t steam_account_id;
    std::string modname, modid, modmain_path; std::vector<std::string> aliases;
    std::optional<std::string> ownerdir_hint; std::optional<std::string> save_file; };
struct ConfigPartial { ds::plugin::ConfigView values; };
struct IConfigSource {
    virtual ~IConfigSource() = default;
    virtual ConfigSource id() const = 0;
    virtual ConfigPartial read(CascadeContext &ctx) const = 0;
};
struct ResolvedConfig {
    ds::plugin::ConfigView view;
    std::unordered_map<std::string, ConfigSource> source_of;
    CascadeContext ctx;
};
ResolvedConfig resolve(const ConfigSchemaRegistry &schema, CascadeContext ctx,
                       const std::vector<const IConfigSource *> &sources);
ResolvedConfig resolve(const ConfigSchemaRegistry &schema, CascadeContext ctx);
GameJitModConfig map_to_game_jit_mod_config(const ResolvedConfig &resolved);
}
```

**Layer order:** ModinfoDefault → LuajitConfig → SaveFile|ModOverrides → EnvOrCmd.  
Each layer: `read` → `apply_partial`.

## TDD evidence

### RED
- Added `test_config_resolve.cpp` + CMake target referencing missing `IConfigSource.hpp`.
- Failure: `fatal error C1083: config/IConfigSource.hpp: No such file or directory`.

### GREEN
```text
PASS: resolve_respects_source_order_and_whitelist
PASS: resolve_empty_sources_yields_empty_view
ALL PASS: config_resolve

PASS: whitelist_blocks_env / priority_when_all_allowed / unknown_key_ignored
All config schema tests passed!
```

Injector + `plugin_core_vm` linked RelWithDebInfo.

## L-G present

```bash
cp Injector.dll + plugins/*.dll → DST/bin64/
DST_GAME_DIR=... LG_T_HOLD=5 LG_REQUIRE_GAME=1 \
  python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
```

Result: `[lg] PASS core profile scenario=present` (exit 0).

## Self-review

- Fake-source resolve overload used by unit test; production builds four sources.
- Save and overrides share `id()==SaveFile`; only one applies per role.
- Compat mapper copies core keys to struct fields, remainder to `business_options`, provenance via `source_of`.
- Client write-back after resolve preserved.
- Path discovery not moved to `config/path/` yet (Task 4).

## Concerns (pre-fix)

- ~~Env LuaVmType aliases (`lua51`/`51`/…) normalize to `"game"` so `apply_partial` accepts them against schema.allowed; `jit_gen` leaves LuaVmType unchanged (EnabledGenGC is separate). Slightly different from legacy raw write of unsupported strings.~~ **Fixed** — see Review fix below.
- `IConfigSource::read` takes non-const `CascadeContext &` so layers can fill identity/save_file (deviation from brief `const` signature — necessary for path discovery without globals).
- `LoadGameJitModConfigFromSaveFile` / overrides still exist for write-back path and legacy callers; cascade load now goes through sources.
- Identity still uses `GameJitConfigSource::luajit_config` for modname/modid even when only static defaults apply.

## Review fix: EnvOrCmdSource VM aliases (Important)

**Commit:** `fix(config): preserve env lua_vm_type aliases (jit_gen, lua51)`

### Changes

1. **`EnvOrCmdSource.cpp`**
   - `jit_gen` → emit `LuaVmType="jit"` **and** `EnabledGenGC=true` (matches `GetLuaVmType()` which checks `EnabledGenGC` first).
   - `lua51` / `51` / `5.1` / `_51` / `jit` / `game` → store **raw** supported alias in `LuaVmType` (legacy `update_string_field` + `GameLuaTypeFromString` behavior). No more remap to `"game"`.

2. **`ConfigSchema.cpp` `RegisterCoreOptionSchema`**
   - Extend `LuaVmType.allowed` beyond modinfo `{jit, game}` with env aliases: `lua51`, `51`, `5.1`, `_51`, `jit_gen` so `apply_partial` does not reject them.

3. **Tests**
   - `test_config_resolve`: `resolve_env_lua_vm_type_aliases` covers raw `lua51`, jit_gen→jit+EnabledGenGC, and `_51` via fake EnvOrCmd source.
   - `test_config_schema`: asserts core schema allowed set includes all env aliases.

### Verification

```text
$ cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_config_resolve test_config_schema test_config_source_whitelist Injector
[12/12] Linking CXX shared library .../Injector.dll

$ ./builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_config_resolve.exe
PASS: resolve_respects_source_order_and_whitelist
PASS: resolve_empty_sources_yields_empty_view
PASS: resolve_env_lua_vm_type_aliases
ALL PASS: config_resolve

$ ./builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_config_schema.exe
...
PASS: register_core_option_schema
...
All config schema tests passed!

$ ./builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_config_source_whitelist.exe
PASS: whitelist_blocks_env
PASS: priority_when_all_allowed
PASS: unknown_key_ignored
ALL PASS: config_source_whitelist

Injector.dll linked (RelWithDebInfo).
```

L-G present not re-run (unit + Injector link sufficient for this review fix).
