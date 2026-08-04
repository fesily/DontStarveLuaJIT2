# GameJitModConfig Pluginization — ConfigView as Single Source of Truth

**Date:** 2026-08-04  
**Status:** Approved approach (user: 完整 ConfigView 为唯一真相)  
**Scope:** Replace hard-coded `GameJitModConfig` business fields + `PluginConfigBridge` field lists with a schema-driven `ConfigView`. Plugin-owned types (e.g. `DstAngleBackend`) leave L0.

Related:

- Plugin architecture: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md`
- Dynamic impl migration: `docs/superpowers/specs/2026-08-04-dynamic-plugin-impl-migration-design.md`
- Current bridge: `src/DontStarveInjector/core/PluginConfigBridge.cpp`
- Current typed config: `src/DontStarveInjector/gameModConfig.hpp`
- Angle type stuck in L0: `src/DontStarveInjector/DstAngleBackend.hpp` (used by `config.hpp` env/cmd + save parse)

---

## 1. Problem

Implementation plugins moved out of Injector; **config did not**.

| Symptom | Root cause |
|---|---|
| `DstAngleBackend.hpp` still in Injector root | L0 env/cmd + save cascade parse Angle as typed enum |
| `EnableNetSim` / `NetworkOpt` missing from native cascade | `GameJitModConfig` has no fields; bridge hardcodes `NetworkOpt=true` |
| `network.sim` native forced `AlwaysOn` | Missing key → `AllOf` fails (`is_bool_on` treats absent as false) |
| New plugin option requires C++ struct field + bridge line + save parser branch | Config is a closed typed bag, not plugin-extensible |
| `PluginConfigBridge` is a hand-maintained allowlist | Couples Host gates to L0 knowledge of every business option |

`modinfo.lua` remains the **user-facing** surface. Native EarlyNative plugins need the **same keys** before Lua runs. Today only a subset is resolved natively; the rest is invented or AlwaysOn-faked.

---

## 2. Decisions

| # | Choice |
|---|---|
| C1 | **`ConfigView` is the only runtime truth** for plugin option gates (`PluginHost::resolve`) |
| C2 | **L0 owns the cascade engine**, not business option inventory |
| C3 | **Plugins declare option schema** (key, type, default, optional allowed values) |
| C4 | **Unknown keys in save/overrides are ignored** (no fail on extra modinfo options not yet registered) |
| C5 | **Known schema keys with invalid values fail-fast** at resolve time (project rule) |
| C6 | **Plugin-owned types** (`DstAngleBackend`, future enums) live with the plugin; L0 stores strings/bools/numbers only |
| C7 | **Identity / paths stay L0-typed** (`modmain_path`, `modname`, `modid`, `save_file`) — not plugin options |
| C8 | **Core VM / always-on gates stay L0** (`AlwaysEnableMod`, `DisableJITWhenServer`, `LuaVmType`, `EnabledGenGC`) — Host + Inject need them before plugins load |
| C9 | **Incremental, reversible slices** — each step builds + L-G green |
| C10 | **YAGNI:** no remote schema market, no version negotiation of option packages, no forced hot-reload of config mid-session |

---

## 3. Target architecture

```
modinfo.lua  (user surface — unchanged)
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│ L0 Config Cascade Engine                                │
│  defaults(schema) → save/overrides → env/cmd            │
│  identity: modmain_path / modname / modid / save_file   │
│  core: AlwaysEnableMod, DisableJITWhenServer,           │
│        LuaVmType, EnabledGenGC                          │
│  output: ConfigView  (unordered_map<string, ConfigValue>)│
└─────────────────────────────────────────────────────────┘
     │
     │  PluginHost::resolve(config, gate_ctx)
     ▼
┌─────────────────────────────────────────────────────────┐
│ Plugins (schema contributors + consumers)               │
│  network.rpc     → NetworkOpt (bool)                    │
│  network.sim     → EnableNetSim (bool)                  │
│  render.vbpool   → EnableVBPool (bool)                  │
│  render.angle    → AngleBackend (string enum)           │
│  … future plugins add keys without touching L0 struct   │
└─────────────────────────────────────────────────────────┘
```

### 3.1 What L0 keeps (typed or identity)

| Key / field | Why L0 |
|---|---|
| `modmain_path`, `modname`, `modid`, `save_file` | Process identity / path resolution before plugins |
| `AlwaysEnableMod` | Inject / mod force-enable before feature plugins |
| `DisableJITWhenServer` | Early exit in `Inject()` for dedicated servers |
| `LuaVmType`, `EnabledGenGC` | VM selection in L0 Lua bridge |

These may remain a small `GameJitCoreConfig` (rename of slimmed `GameJitModConfig`) **or** live as reserved keys inside `ConfigView` with L0-owned schema entries. Prefer **one `ConfigView` plus a thin typed accessor for core keys** to avoid dual sources.

### 3.2 What leaves L0

| Today | After |
|---|---|
| `GameJitModConfig::AngleBackend` (+ Source) | schema key `AngleBackend` (string); parse/validate in `plugin_render_angle` |
| `GameJitModConfig::EnableVBPool` (+ Source) | schema key `EnableVBPool` |
| Hardcoded `NetworkOpt = true` in bridge | schema key `NetworkOpt` with modinfo default |
| Missing `EnableNetSim` | schema key `EnableNetSim` with modinfo default `false` |
| `DstAngleBackend.hpp` in Injector + `config.hpp` env enum | plugin-local type; env/cmd override injects **string** into ConfigView |
| `PluginConfigBridge` field-by-field copy | delete or reduce to `ConfigView merge_core(core)` only |

### 3.3 Option schema (plugin-declared)

Minimal shape (C++ EarlyNative plugins; Lua plugins already use `options = { all_of = {...} }`):

```cpp
struct OptionSchemaEntry {
    std::string key;
    ConfigValueType type;           // Bool | String | Number
    ConfigValue default_value;
    // Optional: allowed string set (empty = any)
    std::vector<std::string> allowed;
};
```

**Registration timing:**

1. **Static / compile-time table** for EarlyNative modules that must gate **before** `ds_plugin_module_init` is awkward if schema lives only inside the DLL.  
2. **Preferred:** each dynamic plugin exports optional  
   `ds_plugin_module_option_schema(const OptionSchemaEntry **out, size_t *count)`  
   called by `DynamicPluginLoader` **after** load, **before** `PluginHost::resolve` if resolve needs full schema — **or** resolve runs after all modules register plugins, and schema is registered in `ds_plugin_module_init` before Host resolve.

Current order in `Inject()`:

```
LoadGameModConfig()           // builds GameJitModConfig today
DynamicPluginLoader::load_all // register plugins
PluginHost::resolve(config)
PluginHost::load_phase(EarlyNative)
```

**Target order:**

```
// 1) Discover modules + collect schema (init may only register schema + plugin)
DynamicPluginLoader::load_all → ds_plugin_module_init (register plugin + schema)
// 2) L0 core defaults + cascade into ConfigView using full schema registry
ConfigView cfg = ResolveConfigView(schema_registry, identity, paths, env)
// 3) Host resolve + EarlyNative load
PluginHost::resolve(cfg, gate)
PluginHost::load_phase(EarlyNative)
```

**Chicken-and-egg:** schema is needed to fill ConfigView defaults, but schema is in plugins.  
**Resolution:** `DynamicPluginLoader` loads modules and runs `init` (register schema + plugin) **before** final config resolve. Core L0 keys use a **built-in L0 schema** always present without plugins. Business keys only appear when the plugin DLL is present.

If a plugin DLL is missing, its keys are absent → `AllOf` fails → plugin not loaded (fail-closed for option-gated features). Optional: log “schema unavailable, key X missing”.

### 3.4 Cascade rules (unchanged priority, new storage)

Priority (high wins), same as today:

1. env / cmd (`DST_ANGLE_BACKEND`, `ANGLE_DEFAULT_PLATFORM`, `lua_vm_type`, …)  
2. client save file / server modoverrides  
3. `luajit_config` file (AlwaysEnableMod, DisableJITWhenServer, modmain_path)  
4. schema / modinfo defaults  

Storage: all values land in `ConfigView` as `ConfigValue`. Source tracking (`GameJitConfigSource`) becomes optional debug metadata (`ConfigValue.source`) — keep if useful for write-back; not required for Host gates.

### 3.5 Env/cmd and `DstAngleBackend`

Today `InjectorConfig::DST_ANGLE_BACKEND` is a typed enum via `ENV_OR_CMD_OPT_ENUM1` and forces `#include "DstAngleBackend.hpp"` into `config.hpp`.

**After:**

- Env/cmd layer writes **string** key `AngleBackend` into ConfigView (or a temporary override map merged at resolve).  
- Validation against allowed values uses **schema.allowed** from `plugin_render_angle` when that schema is registered; if plugin not loaded yet at env parse time, accept any non-empty string and re-validate at Host resolve / plugin `load`.  
- `DstAngleBackend.hpp` moves to `plugins/plugin_render_angle/`.  
- `GameOpenGl.cpp` includes local header and converts string → enum at use site (fail-fast on unknown if feature active).

### 3.6 Save / overrides parser

Today `LoadGameJitModConfigFromSaveFile` / `FromModOverridesFile` switch on `ModConfigurationOptions::*` names and fill struct fields.

**After:**

- Parser walks saved options as `key → raw value`.  
- For each key present in **schema registry**, coerce to `ConfigValue` (bool/string/number) and apply cascade.  
- Keys not in schema: ignore (modinfo-only / Lua-only options still work in game UI).  
- Write-back (client save rewrite): write **core keys + registered schema keys** that have sources ≥ save_file; do not invent keys.

`ModConfigurationOptions` (generated from modinfo) remains the **name/default/options** source for codegen defaults where convenient, but L0 must not hard-code business field assignments one-by-one forever — prefer iterating a schema list.

### 3.7 Lua dual-face plugins

Unchanged contract:

- Lua `options = { all_of = { "EnableNetSim" } }` continues to read mod config via existing Lua gate_ctx.  
- Native EarlyNative `AllOf{"EnableNetSim"}` must see the **same** key in ConfigView after this work.  
- `network.sim` reverts from native `AlwaysOn` to `AllOf{EnableNetSim}` once the key is real.

---

## 4. Non-goals

- Changing modinfo.lua UX or option names  
- Full package manager / option versioning across plugin DLLs  
- Hot-reload of config mid-session  
- Moving LuaVmType / AlwaysEnableMod into feature plugins  
- Making Signature / FunctionRelocation user plugins  

---

## 5. Migration slices

Each slice: build + unit gates + L-G green; reversible.

| Slice | Work | Exit criteria |
|---|---|---|
| **C-S0** | Document + schema API types in `core/` (`OptionSchemaEntry`, registry on `PluginHost` or `ConfigSchemaRegistry`) | Compiles; no behavior change |
| **C-S1** | Plugins register schema in `ds_plugin_module_init`; registry populated after `load_all` | Dump/log registered keys; L-G PASS |
| **C-S2** | Build `ConfigView` from **schema defaults + existing GameJitModConfig fields** (dual-write); Host uses ConfigView only | Host gates identical; L-G PASS |
| **C-S3** | Cascade writes business keys **only** into ConfigView; delete `EnableVBPool` / `AngleBackend` from struct; delete bridge allowlist | Struct slimmed; vbpool/angle still gate correctly |
| **C-S4** | Add `NetworkOpt`, `EnableNetSim` (and any other EarlyNative-needed keys) via schema defaults from modinfo | `network.rpc` / `network.sim` true AllOf; remove AlwaysOn hack |
| **C-S5** | Move `DstAngleBackend.hpp` into `plugin_render_angle`; env/cmd as string override | Injector tree free of angle enum; L-G PASS |
| **C-S6** | Save/overrides parser schema-driven loop; remove per-field `if (option_name == …)` business branches | New plugin option = schema only |

Suggested order: S0 → S1 → S2 → S3 → S5 (unblocks “move DstAngleBackend”) → S4 → S6.  
S5 can follow S3 once AngleBackend is string-only in ConfigView.

---

## 6. API sketch

### 6.1 Schema registration

```cpp
// core/ConfigSchema.hpp
struct OptionSchemaEntry { /* as above */ };

class ConfigSchemaRegistry {
public:
    void add(OptionSchemaEntry e);           // fail-fast on duplicate key conflict
    const OptionSchemaEntry* find(std::string_view key) const;
    std::vector<const OptionSchemaEntry*> all() const;
};
```

### 6.2 Plugin module optional export

```cpp
// Optional; if absent, plugin contributes no schema (AlwaysOn / can_load only).
DS_PLUGIN_MODULE_EXPORT void ds_plugin_module_register_schema(ConfigSchemaRegistry*);
```

Or register via `PluginHost` method passed into existing `ds_plugin_module_init` — prefer **extending init context** over a second export if ABI churn is acceptable in the same migration.

### 6.3 Resolve

```cpp
ConfigView ResolveConfigView(
    const ConfigSchemaRegistry& schema,
    const GameJitCoreConfig& core,      // identity + VM gates
    const CascadeInputs& inputs);       // paths, env, save raw table
```

`PluginHost::resolve(const ConfigView&, const PluginContext&)` stays; bridge `FromGameJitModConfig` deleted after S3.

---

## 7. Failure modes

| Case | Behavior |
|---|---|
| Duplicate schema key, different defaults | Fail-fast at register (log + skip plugin or abort inject — prefer **abort inject** for conflict) |
| Save value fails type coerce | Fail-fast log; leave previous cascade value or default — **prefer default + error log** for client boot stability? **Decision: fail-fast for core keys; business keys use default + error log** so one bad angle string does not kill inject |
| Plugin DLL missing, key only in that schema | Key absent → option AllOf false → feature off (expected) |
| Env angle set, plugin not built (Linux) | String may sit unused; no angle plugin → no consumer |

---

## 8. Testing

| Gate | What |
|---|---|
| Unit | Schema register / duplicate / `EvaluateOptionRule` with ConfigView filled from schema defaults |
| Unit | Cascade priority: env overrides save overrides default for a business key |
| L-E style | EnableVBPool / EnableNetSim / NetworkOpt true/false matrix (native ConfigView) |
| L-G | Core profile PASS with all dynamic plugins |
| Trunk | Injector does not export business feature symbols; plugins still load |

---

## 9. Success criteria

1. Adding a new modinfo-backed plugin option does **not** require editing `GameJitModConfig` fields or `PluginConfigBridge` switch lists.  
2. `DstAngleBackend` (and similar) live only under their plugin directory.  
3. EarlyNative plugins gate on real keys (`EnableNetSim`, `NetworkOpt`, …) without AlwaysOn / hardcoded true.  
4. L0 still completes inject with all business plugins absent/disabled.  
5. modinfo remains the single user config surface.

---

## 10. Open implementation details (resolved at plan time)

| Item | Default unless plan revises |
|---|---|
| Schema via second export vs init context | Prefer **init context / Host method** to avoid dual exports |
| Keep `GameJitModConfig` name for core | Rename to `GameJitCoreConfig` when struct is slim — optional cleanup slice |
| Source tracking on ConfigValue | Keep if write-back needs it; else drop |
| Linux/macOS | Same ConfigView model; gum-using plugins still blocked until re-export |

---

## 11. Approval

User selected: **完整 ConfigView 为唯一真相**, then approved writing this spec.

Next: user reviews this file; on approval → `writing-plans` for C-S0…C-S6 implementation plan.
