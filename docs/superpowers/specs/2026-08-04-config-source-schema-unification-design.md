# Config Source + Schema Unification (Approach B)

**Date:** 2026-08-04  
**Status:** Approved (user confirmed). Implementation plan: `docs/superpowers/plans/2026-08-04-config-source-schema-unification.md`  
**Scope:** Unify the four game-option config sources under one schema-driven cascade; each option declares **allowed sources** (whitelist); move all game-config read machinery into one directory.

Related:

- ConfigView SSOT: `docs/superpowers/specs/2026-08-04-gamejitmodconfig-pluginization-design.md`
- Plugin architecture: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md`
- Current types: `gameModConfig.hpp` (`GameJitConfigSource`), `core/ConfigSchema.hpp`, `GameJitModConfigCascade.cpp`, `luajit_config.*`, `core/PluginConfigBridge.*`
- Process flags (out of scope): `config.hpp` `InjectorConfig` (DisableGameScriptsZip, debugger flags, …)

---

## 1. Problem

Game options today are resolved by **four physical readers** scattered across L0, with **hard-coded merge order** and **per-field Source tracking**, not schema-owned policy.

| Source (today) | Code home | What it feeds |
|---|---|---|
| **modinfo_default** | `make_default_game_mod_config` + `Register*OptionSchema` defaults | Core + business defaults |
| **luajit_config** | `luajit_config.cpp` + `load_resolved_game_mod_config` | `modmain_path`, `AlwaysEnableMod`, `DisableJITWhenServer`, identity |
| **save_file** (client) / **modoverrides** (server) | `GameJitModConfigCascade.cpp` | Schema keys via sol parse → typed/business map |
| **env_or_cmd** | `read_env_or_cmd_value` + `InjectorConfig::lua_vm_type` + Angle env | `LuaVmType`, `AngleBackend`, path hints |

Pain:

1. **Source policy is not declared** — a key can be overwritten by any layer that happens to know it; no per-option allowlist.
2. **Readers are split** — identity, luajit file, save, overrides, env live in different TUs; hard to see one pipeline.
3. **Dual bags remain** — `GameJitModConfig` typed core + `business_options` + later `BuildConfigView`; still two-ish truths before Host.
4. **Builtin business schema still in L0** — `RegisterBuiltinBusinessOptionSchema` pre-seeds plugin keys so cascade can parse before DLL load; couples L0 to plugin inventory.
5. **Source enum exists but is passive** — `*Source` fields only for logging/debug, never filter writes.

User decisions (this session):

- **Allowed sources = whitelist** — if a source is not listed on the option, values from that source are **ignored**.
- **Approach B** — full `ConfigView` + pluggable `IConfigSource` / SourceReader; core keys also schema-driven.

---

## 2. Decisions

| # | Choice |
|---|---|
| D1 | **Runtime truth = `ConfigView`** (`unordered_map<string, ConfigValue>`) + optional **provenance map** `source_of[key]` |
| D2 | **Four game sources only** for option cascade: `modinfo_default`, `luajit_config`, `save_file` (includes server modoverrides as same layer), `env_or_cmd` |
| D3 | **Global layer order is fixed** (low → high): `modinfo_default` → `luajit_config` → `save_file` → `env_or_cmd`. Higher wins **only if** key allows that source |
| D4 | **`OptionSchemaEntry.allowed_sources`** is a bitset/flags; empty means **all four** (backward compatible default) |
| D5 | **Registrar owns allowed_sources** — core options registered by L0; business options by plugins (or bootstrap seed with same keys) |
| D6 | **Unknown keys in save/overrides: ignore** (unchanged C4). **Known key + disallowed source: ignore (log debug)**. **Known key + allowed source + bad type/value: fail-fast** (unchanged C5) |
| D7 | **Identity paths** (`modmain_path`, `modname`, `modid`, `save_file` path) are **schema keys** with L0 registrar + restricted sources (not free-form plugin options) |
| D8 | **`InjectorConfig` process flags stay outside** this cascade (different product surface: injector diagnostics). Only **game option** keys that already cross into `GameJitModConfig` (e.g. `LuaVmType` via `lua_vm_type` env) are SourceReaders feeding the cascade |
| D9 | **Physical home:** `src/DontStarveInjector/config/` owns all game-option cascade code |
| D10 | **Incremental slices** — each step builds + unit tests; L-G green before next |
| D11 | **YAGNI:** no remote schema, no per-source versioning, no mid-session full re-cascade unless already required |

### 2.1 Source enum (canonical)

```cpp
enum class ConfigSource : uint8_t {
    None            = 0,
    ModinfoDefault  = 1 << 0,
    LuajitConfig    = 1 << 1,
    SaveFile        = 1 << 2,  // client modconfiguration_*.lua OR server modoverrides.lua
    EnvOrCmd        = 1 << 3,
};
using ConfigSourceMask = uint8_t;
constexpr ConfigSourceMask kConfigSourceAll =
    ModinfoDefault | LuajitConfig | SaveFile | EnvOrCmd;
```

Rename from `GameJitConfigSource`; keep a one-release alias if needed for logs.

**Note on save vs overrides:** same **priority layer** (`SaveFile`). Client and server differ only in **path discovery + Lua table shape**, implemented as two adapters behind one `IConfigSource` (or one source with strategy). They never both apply in one process role.

### 2.2 Schema entry (extended)

```cpp
struct OptionSchemaEntry {
    std::string key;
    ConfigValueType type = ConfigValueType::None;
    ConfigValue default_value{};
    std::vector<std::string> allowed;     // empty = any string
    ConfigSourceMask allowed_sources = kConfigSourceAll;
};
```

Examples:

| Key | Owner | allowed_sources (example) |
|---|---|---|
| `AlwaysEnableMod` | L0 core | All |
| `DisableJITWhenServer` | L0 core | All |
| `LuaVmType` | L0 core | Default \| LuajitConfig \| SaveFile \| EnvOrCmd |
| `EnabledGenGC` | L0 core | Default \| SaveFile \| EnvOrCmd |
| `modmain_path` | L0 identity | LuajitConfig (primary); optional EnvOrCmd later if needed |
| `AngleBackend` | render.angle | Default \| SaveFile \| EnvOrCmd (**not** luajit_config file) |
| `EnableNetSim` | network.sim | Default \| SaveFile \| EnvOrCmd |
| `NetworkOpt` | network.rpc | Default \| SaveFile \| EnvOrCmd |

Exact masks for each key are set by the **registrar** in implementation; table above is normative default intent.

---

## 3. Target architecture

```
                    ┌──────────────────────────┐
                    │  ConfigSchemaRegistry    │
                    │  (key → type/default/    │
                    │   allowed/allowed_sources)│
                    └────────────┬─────────────┘
                                 │
     ┌───────────────────────────┼───────────────────────────┐
     ▼                           ▼                           ▼
 IConfigSource              IConfigSource              IConfigSource
 ModinfoDefault             LuajitConfigFile           SaveOrOverrides
 (schema defaults)          (unsafedata/luajit_*.json) (client save /
                                                       server overrides)
     │                           │                           │
     └─────────────┬─────────────┴─────────────┬─────────────┘
                   ▼                           ▼
              CascadeEngine.apply(source, partial_view)
                   │  for each (key,value):
                   │    schema = find(key); if !schema skip
                   │    if !(source ∈ allowed_sources) skip
                   │    coerce+validate; fail-fast on bad typed value
                   │    view[key]=v; provenance[key]=source
                   ▼
              IConfigSource EnvOrCmd  (highest)
                   ▼
              ResolvedConfig { ConfigView view; provenance; paths… }
                   │
                   ▼
              PluginHost::resolve(view) / Inject core gates
```

### 3.1 Directory layout (merge)

Target under Injector:

```
src/DontStarveInjector/config/
  ConfigSource.hpp          // enum + masks
  OptionSchema.hpp/cpp      // OptionSchemaEntry, Registry, RegisterCore…
  CascadeEngine.hpp/cpp     // apply layer + resolve orchestration
  ResolvedConfig.hpp        // ConfigView + provenance (+ thin accessors)
  sources/
    ModinfoDefaultSource.cpp
    LuajitConfigSource.cpp  // moves luajit_config.*
    SaveFileSource.cpp      // client modconfiguration
    ModOverridesSource.cpp  // server (same layer id SaveFile)
    EnvOrCmdSource.cpp
  path/
    ModIdentity.cpp         // build_mod_identity, aliases
    ConfigPaths.cpp         // client/server path candidates
  Compat.hpp                // GameJitModConfig alias / instance() shim (temporary)
```

**Move in:**

| From | To |
|---|---|
| `core/ConfigSchema.*` | `config/OptionSchema.*` (or keep name ConfigSchema under config/) |
| `core/PluginConfigBridge.*` | fold into `CascadeEngine` / `ResolvedConfig` (`BuildConfigView` becomes “view is already resolved” or thin alias) |
| `GameJitModConfigCascade.cpp` | `sources/SaveFileSource` + `ModOverridesSource` + coerce helpers |
| `luajit_config.*` | `sources/LuajitConfigSource` |
| game-option parts of `gameModConfig.cpp` | `CascadeEngine` + `path/*` + `ResolvedConfig` |
| `gameModConfig.hpp` types | `ResolvedConfig.hpp` + `ConfigSource.hpp` |

**Stay outside `config/`:**

| Item | Why |
|---|---|
| `config.hpp` / `config.cpp` (`InjectorConfig`, `InjectorCtx`) | Process/injector flags + gum ctx — not game option cascade |
| GAME_API exports in old `gameModConfig.cpp` (`set_target_fps`, …) | Not config; relocate later with owning plugins if needed |
| `modinfo.hpp` generated | Input to defaults only |

### 3.2 `IConfigSource`

```cpp
struct ConfigPartial {
    ConfigView values; // raw candidates before whitelist (or already filtered)
};

struct IConfigSource {
    virtual ~IConfigSource() = default;
    virtual ConfigSource id() const = 0;
    // May use identity/paths from previous layers (e.g. modname for save path).
    virtual ConfigPartial read(const CascadeContext &ctx) const = 0;
};
```

`CascadeEngine::resolve(schema, ctx)`:

1. Register sources in fixed order.
2. Start with empty view.
3. For each source: `partial = read(ctx)`; `apply(schema, source, partial, view, provenance)`.
4. Return `ResolvedConfig`.

`apply` is the **only** place that enforces whitelist + coerce.

### 3.3 Bootstrap schema timing (chicken/egg)

Save parse needs schema **before** all plugins load. Keep:

1. **L0 seeds** core + **bootstrap business** keys (same as today's `RegisterBuiltinBusinessOptionSchema`) so cascade can parse known keys early.
2. **Plugins re-register** identical entries in `ds_plugin_module_init` (conflict rules unchanged: same type/default/allowed/allowed_sources OK; mismatch fail/log).
3. Future: optional `ds_plugin_module_option_schema` pre-pass without full init — **not required for v1** if bootstrap seed stays.

`allowed_sources` must match between bootstrap seed and plugin re-register (part of conflict check).

### 3.4 Inject order (target)

```
gum_init / InjectorCtx
→ schema seed (core + bootstrap business)
→ CascadeEngine::resolve()          // single entry; replaces load_resolved_game_mod_config
→ core.vm bootstrap (uses LuaVmType / DisableJITWhenServer from ResolvedConfig)
→ DynamicPluginLoader (plugins re-register schema + services)
→ PluginHost::resolve(ResolvedConfig.view)
→ load_phase(EarlyNative)
```

`GameJitModConfig::instance()` becomes a **compat shim** returning a view-backed object or is deleted after call-site migration.

### 3.5 Provenance

```cpp
struct ResolvedConfig {
    ConfigView view;
    std::unordered_map<std::string, ConfigSource> source_of;
    // Convenience (optional typed getters for L0 hot path):
    // std::string_view lua_vm_type() const;
    // bool always_enable_mod() const;
};
```

Logging: `lj_ds_print_game_configs` / debug dump prints `key=value (source)`.

---

## 4. Error handling

| Case | Behavior |
|---|---|
| Key not in schema (save/overrides) | Ignore |
| Key in schema, source not allowed | Ignore + `spdlog::debug` |
| Key in schema, source allowed, type/value invalid | **Fail-fast** (log error; cascade returns nullopt or aborts resolve — same severity as current invalid schema coerce) |
| Duplicate schema register, compatible | Idempotent OK |
| Duplicate schema register, incompatible (incl. allowed_sources) | Reject / log conflict (plugin init false if from plugin) |
| Missing save file | Layer contributes empty partial |

---

## 5. Testing

| Test | Asserts |
|---|---|
| `config_source_whitelist` | Key with `SaveFile` only: env value does not overwrite |
| `config_source_priority` | Default < luajit < save < env when all allowed |
| `config_unknown_key_ignored` | Extra save key no-ops |
| `config_invalid_value_fails` | Bad type on allowed source fails coerce |
| `config_schema_conflict_sources` | Re-register different `allowed_sources` conflicts |
| Existing `config_schema` / `config_view_build` | Updated to new headers/paths |
| L-G present | Still PASS after each migration slice |

---

## 6. Migration slices

| Slice | Work | Done when |
|---|---|---|
| **CF-S0** | `ConfigSource` + `allowed_sources` on `OptionSchemaEntry`; conflict includes mask; unit tests for mask helpers | tests green |
| **CF-S1** | `CascadeEngine::apply` whitelist filter; wire into current cascade without directory move | existing save parse respects masks; tests |
| **CF-S2** | Introduce `IConfigSource` adapters wrapping current readers; single `resolve()` entry called from `GameJitModConfig::instance` | one entry, old files thin |
| **CF-S3** | Physical move to `src/DontStarveInjector/config/`; CMake; fix includes | build all targets |
| **CF-S4** | Collapse `GameJitModConfig` business path: Host consumes `ResolvedConfig.view` only; delete dual-write leftovers / shrink `BuildConfigView` | no business field bag |
| **CF-S5** | Core identity as schema keys + accessors; deprecate `GameJitModConfig` public surface | Inject uses ResolvedConfig |
| **CF-S6** | Docs + delete shims; remove `RegisterBuiltinBusiness` duplication only if plugin pre-schema exists (optional) | cleanup |

Each slice: RelWithDebInfo + unit tests + L-G present when touching runtime load path.

---

## 7. Non-goals

- Changing modinfo.lua user surface or option names.
- Unifying `InjectorConfig` process flags into game option schema.
- Hot-reload of full cascade mid-session.
- Cross-process config IPC.
- Making SourceReaders dynamically loaded plugins (they are **internal L0 strategies**, not `plugin_*.dll`).

---

## 8. Risks

| Risk | Mitigation |
|---|---|
| Bootstrap schema vs plugin `allowed_sources` drift | Conflict check; single shared registration helper used by L0 seed and plugins |
| Path discovery order regressions | Keep existing candidate lists byte-for-byte in `ConfigPaths` move |
| sol/lua51 cascade only in L0 | Sources stay in Injector `config/`; still use stock lua51original for parse |
| Call sites of `GameJitModConfig::instance` | Compat shim until CF-S5 |
| Over-filtering breaks existing env overrides | Default mask = all; tighten per-key only with explicit registrar intent |

---

## 9. Success criteria

1. One directory `src/DontStarveInjector/config/` owns game-option cascade.
2. Every option has schema including **allowed_sources**; disallowed sources cannot change the value.
3. Four readers implement one interface; one `resolve()` builds `ConfigView`.
4. Host gates read only `ConfigView` (no hand-maintained business field list).
5. Unit tests cover whitelist + priority; L-G present green.

---

## 10. Open points (defaults if unstated)

| Point | Default for implementation |
|---|---|
| Exact mask per business key | All except where table §2.2 says otherwise; AngleBackend excludes LuajitConfig file |
| Server modoverrides layer id | `SaveFile` (same bit) |
| Fail-fast on invalid: abort inject vs skip key | **Skip key + error log** for save parse (match “unknown ignore” spirit); **abort** only if core identity unusable |
| `InjectorConfig::lua_vm_type` | EnvOrCmd SourceReader maps into `LuaVmType` key |

---

**Next:** execute plan CF-S0…CF-S6 (Tasks 1–7).
