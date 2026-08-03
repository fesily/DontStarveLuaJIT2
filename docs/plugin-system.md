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

### 3.1 Implement `IPlugin`

File: `src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp` (Path A: static objects in this TU).

```cpp
struct MyFeaturePlugin final : IPlugin {
    PluginManifest man{};

    MyFeaturePlugin() {
        man.id = "my.feature";           // dotted stable id
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 50;               // lower first within phase when topo-tied
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {"EnableMyFeature"};
        // man.depends = {"other.id"};
        // man.soft_depends = {};
        // man.conflicts = {};
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &ctx) const override {
        // Platform / client-server gate. false → Disabled (not Failed).
        return ctx.is_client;
    }

    void load(PluginContext &ctx) override {
        // Install hooks / side effects. No defensive “if missing then skip”.
        (void) ctx;
        MyFeatureInstall();
    }

    void unload(PluginContext &) override {
        // Sticky default: leave empty.
    }
};

MyFeaturePlugin g_my_feature;
```

### 3.2 Register

```cpp
void RegisterBuiltinPlugins(PluginHost &host) {
    host.register_plugin(&g_network_rpc);
    host.register_plugin(&g_render_vbpool);
    host.register_plugin(&g_render_angle);
    host.register_plugin(&g_my_feature);  // add here
}
```

`RegisterBuiltinPlugins` is called once from `Inject()` after `LoadGameModConfig()`, before `load_phase(EarlyNative)`.

### 3.3 Config bridge (EarlyNative options)

EarlyNative resolve uses `FromGameJitModConfig` (`PluginConfigBridge`). If your option is read from `GameJitModConfig` before Lua exists, add the key mapping there so `ConfigView` contains it.

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

### 6.1 Native (`RegisterBuiltinPlugins`)

| id | Options | Phase | priority | depends | conflicts | `can_load` |
|---|---|---|---:|---|---|---|
| `render.vbpool` | `all_of` `EnableVBPool` | EarlyNative | 20 | — | — | Win client |
| `render.angle` | `AlwaysOn` (`AngleBackend` is a parameter) | EarlyNative | 30 | — | — | Win client |
| `network.rpc` | `all_of` `NetworkOpt` | EarlyNative | 40 | — | — | always |

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

- Native: `NetworkRpcPlugin` in `RegisterBuiltinPlugins.cpp` → `GameNetWorkHookRpc4()` on EarlyNative when `NetworkOpt`
- Lua rpc: `Mod/plugins/network_rpc.lua` — channel wraps, priority 40
- Lua entity: `Mod/plugins/network_entity.lua` — `depends = { "network.rpc" }`, option `NetworkOptEntity`
- Entity on + rpc off → `MissingHardDep`, entity `load` not called

### `render.vbpool` / `render.angle` (EarlyNative only)

- VBPool: `EnableVBPool` + Win client → `DS_LUAJIT_set_vbpool_enabled(true)`
- Angle: AlwaysOn + Win client → `InitGameOpenGl()` (backend string from config singleton)

---

## 8. Testing

| Gate | What | How |
|---|---|---|
| **L-A** Host graph | topo, soft/hard deps, conflict, cycle, phase barrier, priority, sticky unload | `ctest -R plugin_host_graph --output-on-failure` |
| **L-B** Option rules | all_of / any_of / shorthand / string eq·neq / when | `ctest -R plugin_option_rules --output-on-failure` |
| **Config bridge** | `GameJitModConfig` → `ConfigView` keys | `ctest -R plugin_config_bridge --output-on-failure` |
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
2. **Native hooks needed at inject time?** → `IPlugin` in `RegisterBuiltinPlugins.cpp` + ConfigView bridge key if early.
3. **Lua / modimport / game API?** → `Mod/plugins/<name>.lua` + entry in `init.lua`.
4. Set `id`, `options`, `depends` / `soft_depends` / `conflicts`, `priority`, `when`/`can_load`.
5. Implement `load` only; leave `unload` empty unless `support_reload = true`.
6. Do not edit `Inject()` / `LoadGameModConfig` / `_M:Main` feature lists beyond host calls already present.
7. Extend L-A/L-B/L-C/L-E as appropriate; run L-F; L-G when game binary available.

---

## 10. Key source paths

| Path | Role |
|---|---|
| `src/DontStarveInjector/core/PluginHost.*` | Native host |
| `src/DontStarveInjector/core/PluginOptionRules.*` | Option evaluation |
| `src/DontStarveInjector/core/PluginTypes.hpp` | Phases, status, manifest, `IPlugin` |
| `src/DontStarveInjector/core/PluginModuleAbi.hpp` | Dynamic module C ABI (`ds_plugin_module_init`) |
| `src/DontStarveInjector/core/DynamicPluginLoader.*` | Scan / load / isolate dynamic modules |
| `src/DontStarveInjector/core/RegisterBuiltinPlugins.*` | Native static registry |
| `src/DontStarveInjector/core/PluginConfigBridge.*` | Early ConfigView |
| `src/DontStarveInjector/plugins/plugin_dummy/` | Phase B proof MODULE |
| `src/DontStarveInjector/DontStarveInjector.cpp` | EarlyNative host + dynamic loader call site |
| `Mod/plugins/host.lua` | Lua host |
| `Mod/plugins/init.lua` | Lua registry |
| `Mod/plugins/*.lua` | Lua plugins |
| `Mod/modmain.lua` | AfterModMain host call site |
| `tests/plugin/*` | L-A/B/C/E/F |
| `tests/plugin_server/*` | L-G |
| `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` | Full architecture |

## 11. Dynamic modules (Phase B skeleton)

1. Create `src/DontStarveInjector/plugins/plugin_<name>/plugin_<name>.cpp`
2. Export `ds_plugin_module_init` / optional `ds_plugin_module_abi_version` (see `PluginModuleAbi.hpp`)
3. Register `IPlugin*` with static storage duration
4. Add CMake `MODULE` target like `plugin_dummy`, output to `Injector/plugins/`
5. Deploy next to game Injector under `bin64/plugins/`
6. Override search with `DS_LUAJIT_PLUGIN_DIR`

Business features remain in `RegisterBuiltinPlugins` until a later migration plan.

Related design: `docs/superpowers/specs/2026-08-03-dynamic-plugin-skeleton-design.md`.
