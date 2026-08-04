# Plugin System Contributor Guide

Path A remains the primary path: single `Injector` shared library with static native registration + explicit Lua registry.
Phase B skeleton adds optional dynamic `plugin_*.dll` / `plugin_*.so` modules that register the same `IPlugin` contract (see §11).
No mandatory per-plugin DLL split; business features stay static until a later migration plan.

Design source of truth: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md`.
This guide maps **what is in code today** and how to extend it.

---

## 1. L0 core vs plugins

### L0 (always on — not plugins)

| Capability | Config / trigger | Where |
|---|---|---|
| Process inject / Gum interceptor | — | `Inject()`, `InjectorCtx` |
| Signature scan + Lua export remap | — | `ReplaceLuaModule` |
| **VM selection** | `LuaVmType`, `EnabledGenGC` | `GameLua.cpp` |
| Server inject gate | `DisableJITWhenServer` | early return in `Inject()` |
| Force-enable this mod | `AlwaysEnableMod` | force-enable path / `luajit_config` |
| Config cascade | modinfo → json → save → env | `LoadGameModConfig` / `GameJitModConfig` |
| Crash guard | internal | `check_crash` / modmain clear |
| **PluginHost** | — | native: `core/PluginHost.*`; Lua: `Mod/plugins/host.lua` |

L0 boots the host. Without VM replace + AlwaysEnableMod, plugins cannot run.

### Plugins (feature modules)

Features that used to be hard-wired in `Inject()`, `LoadGameModConfig`, or `modmain._M:Main` are plugins. With **all plugins disabled**, inject still works and the selected VM still runs.

| Layer | Phase | Examples (current) |
|---|---|---|
| Native | `EarlyNative` | `network.rpc`, `render.vbpool`, `render.angle` |
| Lua | `AfterModMain` | `jit.*`, `gc.policy`, `network.*`, `save.fork`, … |

Dual-face plugins share **one id**. Example: `network.rpc` has a native EarlyNative face (`GameNetWorkHookRpc4`) and a Lua AfterModMain face (`Mod/plugins/network_rpc.lua`).

---

## 2. Load phases

```text
[Inject]
  → L0: gum, signature, crash guard, VM replace
  → LoadGameModConfig()                 // resolve only; no feature side effects
  → RegisterBuiltinPlugins(host)
  → resolve(ConfigView, gate_ctx)
  → load_phase(EarlyNative)

[openlibs / GameLuaInjectFramework]     // AfterLuaBridge reserved
  → (phase defined; no plugins use it yet in Path A)

[modmain _M:Main]
  → plugins/host.lua + plugins/init.lua
  → resolve(GetModConfigData, gate_ctx)
  → load_phase(AfterModMain)
```

| Phase | When | Typical work |
|---|---|---|
| **EarlyNative** | End of `Inject()`, before game Lua opens | Gum hooks, GL pool, ANGLE rebind, RPC4 |
| **AfterLuaBridge** | After `GameInjector` / inject framework | Reserved for API export registration |
| **AfterModMain** | `modmain` after host is available | Game-facing wraps, `modimport`, JIT/GC policy |
| **OnDemand** | Explicit host call | Optional; sticky unload default |

Within a phase: topological order on hard/soft depends, then **priority ascending** for ties (lower runs first).

**Fail-fast:** missing hard dep, conflict, or cycle → `Failed` + structured `PluginEvent`; that plugin's `load` is not called. Independent plugins continue. L0 failure still aborts inject.

**Unload:** sticky by default (`support_reload = false`). Native gum probes and Lua metatable wraps are not torn down unless a plugin opts in.

---

## 3. How to add a native plugin

Native EarlyNative business plugins are **dynamic modules** under
`src/DontStarveInjector/plugins/plugin_<name>/` (Phase B). They are loaded by
`DynamicPluginLoader` after the empty `RegisterBuiltinPlugins` extension point.

Shipped modules today:

| Module DLL | Plugin id | Hook |
|---|---|---|
| `plugin_network_rpc` | `network.rpc` | `GameNetWorkHookRpc4` |
| `plugin_render_vbpool` | `render.vbpool` | `DS_LUAJIT_set_vbpool_enabled` |
| `plugin_render_angle` | `render.angle` | `InitGameOpenGl` |
| `plugin_dummy` | `debug.dummy` | log only |

### 3.1 Implement `IPlugin` in a module

File pattern: `src/DontStarveInjector/plugins/plugin_my_feature/plugin_my_feature.cpp`

```cpp
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"
// + headers for any Injector-exported hook you call

namespace {
using namespace ds::plugin;

struct MyFeaturePlugin final : IPlugin {
    PluginManifest man{};
    MyFeaturePlugin() {
        man.id = "my.feature";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 50;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {"EnableMyFeature"};
    }
    const PluginManifest &manifest() const override { return man; }
    bool can_load(const PluginContext &ctx) const override { return ctx.is_client; }
    void load(PluginContext &) override { MyFeatureInstall(); /* fail-fast */ }
    void unload(PluginContext &) override {}
};

MyFeaturePlugin g_my_feature;
} // namespace

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION; // "1"
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) return false;
    host->register_plugin(&g_my_feature);
    return true;
}
```

### 3.2 CMake

Use `ds_add_dynamic_plugin` in `src/DontStarveInjector/CMakeLists.txt`:

```cmake
ds_add_dynamic_plugin(plugin_my_feature
    plugins/plugin_my_feature/plugin_my_feature.cpp)
```

Output lands in `$<TARGET_FILE_DIR:Injector>/plugins/plugin_my_feature.dll`.
Deploy that folder next to the game Injector (`bin64/plugins/`).

Hook entrypoints called from modules must be exported from Injector
(`DONTSTARVEINJECTOR_GAME_API` / `DS_PLUGIN_HOST_API`).

### 3.3 Static registry

`RegisterBuiltinPlugins` is intentionally **empty** (extension point only).
Do not re-add business plugins there unless they are true L0-only and cannot
be a module. Inject order:

```text
RegisterBuiltinPlugins(host)   // empty
DynamicPluginLoader::load_all  // plugin_*.dll
resolve → load_phase(EarlyNative)
```

### 3.3 ConfigView / option schema (SSOT)

EarlyNative resolve uses a **schema-driven `ConfigView`**, not a hand-maintained
field list on `GameJitModConfig`. See **§12 ConfigView SSOT** for the full model.

User-facing config remains **`Mod/modinfo.lua` `configuration_options` only** (D5).

### 3.4 Dual-face native + Lua

1. Native face: register as above (`EarlyNative` and/or `AfterLuaBridge`).
2. Lua face: same `id` under `Mod/plugins/`, listed in `init.lua`.
3. Host treats one logical id; native completes before Lua `load` when both exist for that feature lifecycle.

Example: `network.rpc` — see §7 examples.

### 3.5 Do **not** call feature entrypoints from trunks

`Inject()`, `LoadGameModConfig`, and `modmain._M:Main` must not call feature symbols directly. L-F (`plugin_trunk_surface`) fails if they do. Route side effects through `load()`.

---

## 4. How to add a Lua plugin

### 4.1 Create `Mod/plugins/<name>.lua`

Return a plugin table (explicit registry; no filesystem scan):

```lua
return {
    id = "my.feature",
    version = "1.0.0",
    depends = {},              -- hard; missing → Failed / MissingHardDep
    soft_depends = {},         -- order only if present
    conflicts = {},
    phases = "AfterModMain",   -- default if omitted
    options = { all_of = { "EnableMyFeature" } },
    support_reload = false,
    priority = 60,             -- see §5 priority bands
    when = function(ctx)
        -- optional gate; false → Disabled
        return ctx and ctx.has_luajit
    end,
    load = function(ctx)
        modimport("scripts/my_feature")
        -- or use ctx.injector.DS_LUAJIT_* APIs
    end,
    unload = function(ctx)
        -- sticky default: empty
    end,
}
```

### 4.2 Register in `Mod/plugins/init.lua`

```lua
return {
    load_plugin("jit_tailcall"),
    -- …
    load_plugin("my_feature"),   -- file Mod/plugins/my_feature.lua
}
```

`load_plugin` uses `kleiloadlua(MODROOT .. "plugins/" .. name .. ".lua")` in-game, or `require("plugins." .. name)` under unit tests.

### 4.3 Runtime wiring (already in modmain)

`modmain` loads `plugins/host.lua`, registers `init.lua`, resolves via `GetModConfigData`, then `load_phase(AfterModMain)`. Do not re-hard-wire `modimport` of feature scripts in `_M:Main`.

### 4.4 `ctx` fields used by existing plugins

| Field | Meaning |
|---|---|
| `has_luajit` | LuaJIT VM active |
| `is_client` / `is_mastersim` / `is_windows` | role / platform gates |
| `injector` | `GameInjector` / `DS_LUAJIT_*` surface |
| `config` | function or table of option values |
| `encrypted_mod_manager` / `frostxx_mods` | filled by `jit.tailcall` for `jit.runtime` |

---

## 5. Option rules

Enablement is **options rule** then **when/can_load**. Off or gated → `Disabled` (not an error).

### Native (`OptionRule` in `PluginTypes.hpp`)

| Kind | Meaning |
|---|---|
| `AlwaysOn` | No options gate (still subject to `can_load`) |
| `AllOf` | Every key in `keys` is “on” |
| `AnyOf` | Any key in `keys` is “on” |
| `StringNeq` | `pred_key` string ≠ `pred_expected` |
| `StringEq` | `pred_key` string == `pred_expected` |

“On” for bool-ish keys (`is_bool_on`): `true`, non-zero number, string not empty/`off`/`false`/`0`.

### Lua (`options` table — `host.lua`)

| Form | Meaning |
|---|---|
| `nil` / `true` / `{ always = true }` | AlwaysOn |
| `{ all_of = { "A", "B" } }` | All keys on |
| `{ any_of = { "A", "B" } }` | Any key on |
| `{ option = "A" }` | Shorthand AllOf single key |
| `{ neq = { key = "K", value = "off" } }` | String ≠ (aliases: `string_ne`) |
| `{ eq = { key = "K", value = "on" } }` | String == (aliases: `string_eq`) |

`modinfo` `disabled_by` is **already resolved** before Host sees values; Host does not reimplement it.

String enums (profiler/tracy) should use explicit predicates or `any_of` with `is_bool_on` semantics, not raw Lua truthiness alone.

---

## 6. Inventory: depends / conflicts / priority

Current registration (code). Spec inventory may list future rows (e.g. `steam.workshop`); only rows below are live.

### 6.1 Native (dynamic modules under `plugins/`)

| id | Module | Options | Phase | priority | depends | conflicts | `can_load` |
|---|---|---|---|---:|---|---|---|
| `render.vbpool` | `plugin_render_vbpool` | `all_of` `EnableVBPool` | EarlyNative | 20 | — | — | Win client |
| `render.angle` | `plugin_render_angle` | `AlwaysOn` (`AngleBackend` is a parameter) | EarlyNative | 30 | — | — | Win client |
| `network.rpc` | `plugin_network_rpc` | `all_of` `NetworkOpt` | EarlyNative | 40 | — | — | always |
| `network.sim` | `plugin_network_sim` | `all_of` `EnableNetSim` | EarlyNative | 60 | — | — | Win (DLL always maps; load gated) |
| `debug.dummy` | `plugin_dummy` | AlwaysOn | EarlyNative | 1000 | — | — | always |

### 6.2 Lua (`Mod/plugins/init.lua` order + manifests)

| id | Options | priority | depends | soft_depends | conflicts | `when` (summary) |
|---|---|---:|---|---|---|---|
| `jit.tailcall` | `any_of` SlowTailCall, ForceDisableTailCall, AutoDetectEncryptedMod | 10 | — | — | — | `has_luajit` |
| `debug.profiler` | `any_of` EnableProfiler, EnableTracy | 20 | — | — | — | `has_luajit` |
| `gc.policy` | `always` | 30 | — | — | — | — |
| `network.rpc` | `all_of` NetworkOpt | 40 | — | — | — | — |
| `network.entity` | `all_of` NetworkOptEntity | 40 | **`network.rpc`** | — | — | — |
| `fps.render` | `option` TargetRenderFPS | 50 | — | — | — | not non-Windows |
| `save.fork` | `all_of` EnableForkSave | 60 | — | — | — | `has_luajit` + dedicated |
| `sim.lagcomp` | `all_of` EnableLagCompensation | 60 | — | — | — | `has_luajit` + Win + mastersim |
| `network.sim` | `all_of` EnableNetSim | 60 | — | — | — | `has_luajit` + Win + not mastersim |
| `jit.runtime` | `always` | 70 | — | `jit.tailcall`, `debug.profiler` | — | `has_luajit` |

**Hard depends encoded:** only `network.entity` → `network.rpc`.

**Priority bands (AfterModMain, §7.3):**

| priority | plugins |
|---:|---|
| 10 | `jit.tailcall` (compat.frostxx folded in) |
| 20 | `debug.profiler` |
| 30 | `gc.policy` |
| 40 | `network.rpc` (Lua), `network.entity` |
| 50 | `fps.render` |
| 60 | `sim.lagcomp`, `network.sim`, `save.fork` |
| 70 | `jit.runtime` (HideGlobalJIT last among jit-related) |

No production `conflicts` entries today; the host still enforces conflicts if you add them (both Enabled → both `Failed` / `Conflict`).

---

## 7. Examples in-tree

### `save.fork` (Lua + dedicated gate)

- File: `Mod/plugins/save_fork.lua`
- Options: `EnableForkSave`
- `when`: `has_luajit` and not client / dedicated
- `load`: `AddGamePostInit` → `modimport("scripts/fork_save")`
- Priority 60; sticky unload

### `network.rpc` + `network.entity` (dual-face + hard dep)

- Native: `plugins/plugin_network_rpc/` → `GameNetWorkHookRpc4()` on EarlyNative when `NetworkOpt`
- Lua rpc: `Mod/plugins/network_rpc.lua` — channel wraps, priority 40
- Lua entity: `Mod/plugins/network_entity.lua` — `depends = { "network.rpc" }`, option `NetworkOptEntity`
- Entity on + rpc off → `MissingHardDep`, entity `load` not called

### `render.vbpool` / `render.angle` (EarlyNative only, dynamic)

- VBPool: `plugin_render_vbpool` — `EnableVBPool` + Win client → `DS_LUAJIT_set_vbpool_enabled(true)`
- Angle: `plugin_render_angle` — AlwaysOn + Win client → `InitGameOpenGl()` (backend string from ConfigView / `business_options`)

---

## 8. Testing

| Gate | What | How |
|---|---|---|
| **L-A** Host graph | topo, soft/hard deps, conflict, cycle, phase barrier, priority, sticky unload | `ctest -R plugin_host_graph --output-on-failure` |
| **L-B** Option rules | all_of / any_of / shorthand / string eq·neq / when | `ctest -R plugin_option_rules --output-on-failure` |
| **ConfigView build** | schema → business → core merge; Host enable matrix | `ctest -R "config_view_build|plugin_config_bridge|config_schema" --output-on-failure` |
| **L-C / L-E** Lua host | registry, dual-face, enable matrix per plugin | `ctest -R plugin_host_lua --output-on-failure` (`tests/plugin/run_lua_host.py` + `plugin_host_lua_spec.lua`) |
| **L-D** regressions | `fork_save_lua`, pool / VM name tests as applicable | `ctest -R fork_save_lua --output-on-failure` |
| **L-D0** Dynamic loader | empty dir, noise file, bad library isolation | `ctest -R plugin_dynamic_loader --output-on-failure` |
| **L-F** trunk surface | no feature entrypoints in Inject / LoadGameModConfig / modmain | `ctest -R plugin_trunk_surface --output-on-failure` (`tests/plugin/check_trunk_surface.py`) |
| **L-G** dedicated sim pause | injector + plugins load → world ready → stable pause | `ctest -R plugin_dedicated_sim_pause` — skips without `DST_GAME_DIR`; require game for DoD (`tests/plugin_server/`) |

Unit binaries for Host graph/options **do not** link real `RegisterBuiltinPlugins` (it pulls Frida / game hooks). Use manifest-compatible stand-ins in tests.

When adding a plugin:

1. Unit: option rule + resolve status (on → Loaded, off → Disabled, hard dep down → Failed).
2. Dual-face: native and Lua ids aligned; L-E matrix row for each option combo that changes enablement.
3. Keep L-F green — no new hard-wires in trunks.
4. Prefer clang++ unit tests + lua/python gates; full Injector rebuild only when native symbols change.

---

## 9. Checklist: new feature as plugin

1. Add `modinfo` option(s) if user-facing.
2. **Native hooks needed at inject time?** → dynamic module under `plugins/plugin_<name>/` + `ds_add_dynamic_plugin`.
   Register option schema in `ds_plugin_module_init` **before** `register_plugin`. If cascade must parse the key before Host load, also add it to `RegisterBuiltinBusinessOptionSchema` (or the plugin's cascade seed). **Do not** add a new field on `GameJitModConfig`.
3. **Lua / modimport / game API?** → `Mod/plugins/<name>.lua` + entry in `init.lua`.
4. Set `id`, `options`, `depends` / `soft_depends` / `conflicts`, `priority`, `when`/`can_load`.
5. Implement `load` only; leave `unload` empty unless `support_reload = true`.
6. Do not edit `Inject()` / `LoadGameModConfig` / `_M:Main` feature lists beyond host calls already present. Keep `RegisterBuiltinPlugins` empty for business features.
7. Extend L-A/L-B/L-C/L-E as appropriate; run L-F; L-G when game binary available.

---

## 10. Key source paths

| Path | Role |
|---|---|
| `src/DontStarveInjector/core/PluginHost.*` | Native host + option schema registry |
| `src/DontStarveInjector/core/PluginOptionRules.*` | Option evaluation |
| `src/DontStarveInjector/core/PluginTypes.hpp` | Phases, status, manifest, `IPlugin`, `ConfigView` |
| `src/DontStarveInjector/core/ConfigSchema.*` | `OptionSchemaEntry`, coerce, core/business schema seeds |
| `src/DontStarveInjector/core/PluginConfigBridge.*` | `BuildConfigView` merge (schema → business → core) |
| `src/DontStarveInjector/core/PluginModuleAbi.hpp` | Dynamic module C ABI (`ds_plugin_module_init`) |
| `src/DontStarveInjector/core/DynamicPluginLoader.*` | Scan / load / isolate dynamic modules |
| `src/DontStarveInjector/core/RegisterBuiltinPlugins.*` | Empty static extension point |
| `src/DontStarveInjector/plugins/plugin_*/` | Dynamic native modules (rpc/sim/vbpool/angle/dummy) |
| `src/DontStarveInjector/DontStarveInjector.cpp` | Schema seed + EarlyNative host + dynamic loader |
| `Mod/plugins/host.lua` | Lua host |
| `Mod/plugins/init.lua` | Lua registry |
| `Mod/plugins/*.lua` | Lua plugins |
| `Mod/modmain.lua` | AfterModMain host call site |
| `tests/plugin/*` | L-A/B/C/E/F + `test_config_view_build` / `test_config_schema` |
| `tests/plugin_server/*` | L-G |
| `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` | Full architecture |
| `docs/superpowers/specs/2026-08-04-gamejitmodconfig-pluginization-design.md` | ConfigView SSOT design |

## 11. Dynamic modules (Phase B)

1. Create `src/DontStarveInjector/plugins/plugin_<name>/plugin_<name>.cpp`
2. Export `ds_plugin_module_init` / optional `ds_plugin_module_abi_version` (see `PluginModuleAbi.hpp`)
3. Register `IPlugin*` with static storage duration
4. Add via `ds_add_dynamic_plugin(...)` in Injector CMake (output `Injector/plugins/`)
5. Deploy next to game Injector under `bin64/plugins/`
6. Override search with `DS_LUAJIT_PLUGIN_DIR`

EarlyNative business plugins (`network.rpc`, `render.vbpool`, `render.angle`) already ship as dynamic modules. Keep `RegisterBuiltinPlugins` empty unless you need a true L0-only static plugin.

Related design: `docs/superpowers/specs/2026-08-03-dynamic-plugin-skeleton-design.md`.

## 12. ConfigView SSOT (schema-driven options)

`ConfigView` (`unordered_map<string, ConfigValue>`) is the **only runtime truth**
for `PluginHost::resolve` option gates. Business feature options are **not**
typed fields on `GameJitModConfig`.

Design: `docs/superpowers/specs/2026-08-04-gamejitmodconfig-pluginization-design.md`.

### 12.1 Ownership split

| Layer | Owns | Examples |
|---|---|---|
| **L0 core** (typed on `GameJitModConfig`) | Identity + VM / inject gates before plugins | `AlwaysEnableMod`, `DisableJITWhenServer`, `LuaVmType`, `EnabledGenGC`, paths |
| **Schema registry** | Key, type, default, optional `allowed` strings | Registered by L0 seeds + each plugin |
| **Business map** (`business_options`) | Cascade values for plugin keys | `NetworkOpt`, `EnableNetSim`, `EnableVBPool`, `AngleBackend` |
| **ConfigView** | Merge result used by Host | schema defaults → business → core fields |

### 12.2 Registering an option (native plugin)

In `ds_plugin_module_init`, **before** `register_plugin`:

```cpp
OptionSchemaEntry e;
e.key = "EnableMyFeature";
e.type = ConfigValueType::Bool;
e.default_value = ConfigValue::boolean(false);
if (!host->register_option_schema(std::move(e))) {
    std::fprintf(stderr, "[plugin_my] schema conflict EnableMyFeature\n");
    return false;
}
host->register_plugin(&g_my_feature);
```

Gate the plugin with `man.options.kind = OptionRuleKind::AllOf` and
`man.options.keys = {"EnableMyFeature"}` (or `AlwaysOn` when the option is only
a parameter, e.g. `render.angle` + `AngleBackend`).

If save/modoverrides must parse the key **before** Host plugins load, also seed
the same entry via `RegisterBuiltinBusinessOptionSchema` (modinfo defaults).
Plugins re-register the same keys on Host (idempotent when defaults match).

### 12.3 BuildConfigView merge order

```text
schema defaults (ConfigSchemaRegistry)
  → core.business_options  (save / overrides / env)
  → optional extras arg
  → core typed fields (AlwaysEnableMod, DisableJITWhenServer, LuaVmType, EnabledGenGC)
```

Call site after dynamic load:

```cpp
RegisterCoreOptionSchema(host.option_schema());
RegisterBuiltinBusinessOptionSchema(host.option_schema());
RegisterBuiltinPlugins(host);           // empty extension point
DynamicPluginLoader::load_all(host);    // plugins register schema + IPlugin
ConfigView cfg = BuildConfigView(host.option_schema(), *modcfg);
host.resolve(cfg, gate_ctx);
host.load_phase(PluginPhase::EarlyNative);
```

`FromGameJitModConfig(cfg)` is a **compat** wrapper: empty schema + core/business
only (does **not** invent `NetworkOpt`). Prefer `BuildConfigView` with the host
schema.

### 12.4 Cascade parse (save / modoverrides)

`LoadGameJitModConfigFromSaveFile` / `FromModOverridesFile` walk saved options
against a cascade schema (`RegisterCoreOptionSchema` +
`RegisterBuiltinBusinessOptionSchema`):

- Known key → coerce (Bool / String / Number; String may use `allowed`)
- Invalid present value → error log, keep prior/default
- Nil/absent → skip silently
- Unknown key → ignore (modinfo-only / Lua-only options still work in UI)

Core keys write typed `GameJitModConfig` fields; business keys write
`business_options[name]`.

### 12.5 Plugin-owned types

Enums and feature-local types live **with the plugin**. Example:
`DstAngleBackend` is only under `plugins/plugin_render_angle/`. L0 stores the
string key `AngleBackend`; `GameOpenGl.cpp` converts string → enum at use.

Env/cmd angle overrides write **strings** into `business_options["AngleBackend"]`
(`DST_ANGLE_BACKEND` / `ANGLE_DEFAULT_PLATFORM`), not a typed InjectorConfig enum.

### 12.6 Shipped business schema (today)

| Key | Type | Default | Owner plugin | Native gate |
|---|---|---|---|---|
| `NetworkOpt` | Bool | `true` | `network.rpc` | `AllOf` |
| `EnableNetSim` | Bool | `false` | `network.sim` | `AllOf` |
| `EnableVBPool` | Bool | `false` | `render.vbpool` | `AllOf` |
| `AngleBackend` | String | `auto` (`auto,vulkan,d3d11,d3d9`) | `render.angle` | AlwaysOn (parameter) |

`debug.dummy` is AlwaysOn with no option schema (load always when `can_load`).
