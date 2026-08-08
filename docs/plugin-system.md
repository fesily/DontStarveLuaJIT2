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
| Server VM-path gate | `DisableJITWhenServer` | **only** skips signature/ReplaceLuaModule; does **not** abort inject or plugin load |
| Force-enable this mod | `AlwaysEnableMod` | force-enable path / `luajit_config` |
| Config cascade | modinfo → json → save → env | `LoadGameModConfig` / `GameJitModConfig` |
| Crash guard | internal | `check_crash` / modmain clear |
| **PluginHost** | — | native: `core/PluginHost.*`; Lua: `Mod/plugins/host.lua` |
| Core.vm bootstrap (optional load) | `VmPathEnabled` | `core/CoreVmBootstrap.*` — LoadLibrary/`GetProcAddress` only; never static-links the DLL |

L0 boots the host and always runs DynamicPluginLoader for feature modules. **AlwaysEnableMod** remains L0 so this mod can force-load. Without optional `plugin_core_vm` (or when the VM path is disabled), inject still works and most native feature plugins still load; JIT / `GameInjector` / Lua-facing inject APIs are unavailable.

> **Architecture note (D3 supersession for VM *implementation*):**  
> Spec D3 in `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` still treats **AlwaysEnableMod** and the **decision to run a VM path** as L0 concerns. The **implementation** of signature scan + `ReplaceLuaModule` + `GameLua` + `luaopen_GameInjector` is **no longer L0-linked**: it lives in optional `plugins/plugin_core_vm` (id `core.vm`). See `docs/superpowers/specs/2026-08-04-core-vm-plugin-design.md` (V1–V9). Deploy `plugins/plugin_core_vm.dll` next to Injector when you want JIT.

> **Architecture note (`debug.profiler` owns GC policy):**  
> Spec inventory rows that still list a separate Lua `gc.policy` are superseded. Tracy / replace-profiler / FullGC / FrameGC live in dual-face `debug.profiler` (`plugins/plugin_debug_profiler/` package: native MODULE + modinfo/modmain). See `docs/superpowers/specs/2026-08-04-debug-profiler-plugin-design.md`. L0 has **no** fullgc reverse dep on core.vm; `core.vm` only installs a soft `lj_gc_fullgc_external` forwarder. Profiler and core.vm are optional independently.

### Plugins (feature modules)

Features that used to be hard-wired in `Inject()`, `LoadGameModConfig`, or `modmain._M:Main` are plugins. With **all feature plugins disabled**, inject still works. With **core.vm omitted**, the selected stock Lua VM runs (no JIT replace) and native feature plugins still load.

| Layer | Phase | Examples (current) |
|---|---|---|
| Optional core | `EarlyNative` (bootstrap export + Host face) | `core.vm` — Signature + ReplaceLuaModule + GameInjector open |
| Native | `EarlyNative` | `network.rpc`, `render.vbpool`, `render.angle`, `save.fork`, `debug.profiler`, … |
| Lua | `AfterModMain` | `jit.*`, `debug.profiler` (incl. former `gc.policy`), `network.*`, `save.fork`, … |

Dual-face plugins share **one id**. Example: `network.rpc` has a native EarlyNative face (`GameNetWorkHookRpc4`) and a Lua AfterModMain face (`Mod/plugins/plugin_network_rpc/` package via `load_package`).


## 2. Load phases

```text
[Inject]
  → L0: gum, crash guard, Steam interface
  → if VmPathEnabled:                // not DisableJITWhenServer / not FORCE_DISABLE_VM
        CoreVmBootstrap::TryRun…     // optional plugins/plugin_core_vm.dll
          → signature + ReplaceLuaModule   // soft-skip if DLL missing
     else: skip VM path; plugins continue
  → LoadGameModConfig()              // resolve only; no feature side effects
  → RegisterBuiltinPlugins(host)     // empty extension point
  → DynamicPluginLoader::load_all    // plugin_*.dll including core.vm if present
  → resolve(ConfigView, gate_ctx)
  → load_phase(EarlyNative)

[openlibs / GameLuaInjectFramework]  // AfterLuaBridge reserved; GameInjector open is inside core.vm
  → (phase defined; no plugins use it yet in Path A)

[modmain _M:Main]
  → plugins/host.lua + plugins/init.lua
  → resolve(GetModConfigData, gate_ctx)
  → load_phase(AfterModMain)
```

| Phase | When | Typical work |
|---|---|---|
| **EarlyNative** | End of `Inject()`, before game Lua opens | Gum hooks, GL pool, ANGLE rebind, RPC4; `core.vm` Host face is no-op after bootstrap |
| **AfterLuaBridge** | After `GameInjector` / inject framework | Reserved for API export registration |
| **AfterModMain** | `modmain` after host is available | Game-facing wraps, `modimport`, JIT/GC policy |
| **OnDemand** | Explicit host call | Optional; sticky unload default |

Within a phase: topological order on hard/soft depends, then **priority ascending** for ties (lower runs first).

**Fail-fast:** missing hard dep, conflict, or cycle → `Failed` + structured `PluginEvent`; that plugin's `load` is not called. Independent plugins continue. L0 failure still aborts inject. **Missing `plugin_core_vm` is not fail-fast** — log + continue without JIT.

**Unload:** sticky by default (`support_reload = false`). Native gum probes and Lua metatable wraps are not torn down unless a plugin opts in.

---

## 3. How to add a native plugin

Native EarlyNative business plugins are **dynamic modules** under
`src/DontStarveInjector/plugins/plugin_<name>/` (Phase B). They are loaded by
`DynamicPluginLoader` after the empty `RegisterBuiltinPlugins` extension point.

Shipped modules today:

| Module DLL | Plugin id | Hook / role |
|---|---|---|
| `plugin_core_vm` | `core.vm` | **Optional.** Signature + `ReplaceLuaModule` + `luaopen_GameInjector`. **Recommended for JIT.** Feature plugins work without it. |
| `plugin_network_rpc` | `network.rpc` | `GameNetWorkHookRpc4` |
| `plugin_network_sim` | `network.sim` | outbound net simulation |
| `plugin_save_fork` | `save.fork` | clone/fork save path |
| `plugin_sim_lagcomp` | `sim.lagcomp` | lagcomp entity snapshot (needs GameLua context from core.vm when available) |
| `plugin_render_vbpool` | `render.vbpool` | `DS_LUAJIT_set_vbpool_enabled` |
| `plugin_render_angle` | `render.angle` | `InitGameOpenGl` |
| `plugin_debug_profiler` | `debug.profiler` | **Optional.** Tracy / replace-profiler / FullGC / FrameGC. Soft no-op when missing; independent of `core.vm`. |
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
Deploy that folder under the **mod** `plugins/` tree (primary). Game `bin64/plugins/` remains a compat/dev fallback only.

Hook entrypoints called from modules must be exported from Injector
(`DONTSTARVEINJECTOR_GAME_API` / `DS_PLUGIN_HOST_API`).

### 3.3 Static registry

`RegisterBuiltinPlugins` is intentionally **empty** (extension point only).
Do not re-add business plugins — or `core.vm` — there. `plugin_core_vm` is a
dynamic module (optional JIT path via `CoreVmBootstrap` + `DynamicPluginLoader`).
Inject order:

```text
RegisterBuiltinPlugins(host)   // empty
DynamicPluginLoader::load_all  // plugin_*.dll (incl. plugin_core_vm if staged)
resolve → load_phase(EarlyNative)
```

### 3.3 ConfigView / option schema (SSOT)

EarlyNative resolve uses a **schema-driven `ConfigView`**, not a hand-maintained
field list on `GameJitModConfig`. See **§12 ConfigView SSOT** for the full model.

User-facing config remains **`Mod/modinfo.lua` `configuration_options` only** (D5).

### 3.4 Dual-face native + Lua (package layout)

Dual-face features live as a **DST mini-mod package** under one directory, not as a flat
`Mod/plugins/<face>.lua` next to a loose DLL.

1. Create `src/DontStarveInjector/plugins/plugin_<stem>/` for the native MODULE
   (`ds_add_dynamic_plugin`) plus package Lua sources.
2. Add a **DST-complete** `modinfo.lua` (engine hard fields + private `plugin_id` /
   `options` / …) and `modmain.lua` (+ optional `scripts/`). See package aggregation
   design §6 for the engine-compatible field set.
3. Register the Lua face in `Mod/plugins/init.lua` via
   `load_package("plugin_<stem>")` (not `load_flat` for dual-face).
4. Keep identity SSOT in package `modinfo`; native `PluginManifest` must match
   (`python tools/check_plugin_package_identity.py --source-root .`). Prefer regenerating
   native constants later via optional identity codegen; hand-sync is fine until then.
5. **Do not** add a flat dual-face face at `Mod/plugins/<face>.lua` or park business
   scripts only under `Mod/scripts/` — they belong in the package directory.

Deployed / staged shape:

```text
plugins/plugin_save_fork/
  plugin_save_fork.dll
  modinfo.lua
  modmain.lua
  scripts/fork_save.lua
```

Host treats one logical `plugin_id`; native EarlyNative completes before Lua
`AfterModMain` when both faces exist.

Example: `network.rpc` / `save.fork` — see §7.

### 3.5 Do **not** call feature entrypoints from trunks

`Inject()`, `LoadGameModConfig`, and `modmain._M:Main` must not call feature symbols directly. L-F (`plugin_trunk_surface`) fails if they do. Route side effects through `load()`.

---

## 4. How to add a Lua plugin

### 4.1 Create a package or flat Lua face

**Dual-face / package (preferred for features with native MODULE):** create
`Mod/plugins/plugin_<stem>/` with `modinfo.lua` + `modmain.lua` (and optional
`scripts/`). See §3.4.

**Lua-only flat face:** create `Mod/plugins/<name>.lua` and return a plugin table
(explicit registry; no filesystem scan):

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
    load_flat("jit_tailcall"),
    -- …
    load_package("plugin_my_feature"),  -- dual-face package
    load_flat("my_feature"),            -- Lua-only: Mod/plugins/my_feature.lua
}
```

`load_package` loads `plugins/plugin_<stem>/modinfo.lua` (+ modmain rebind).
`load_flat` uses `kleiloadlua(MODROOT .. "plugins/" .. name .. ".lua")` in-game,
or `require("plugins." .. name)` under unit tests.

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
| `core.vm` | `plugin_core_vm` | AlwaysOn | EarlyNative | 10 | — | — | always (optional DLL; missing ⇒ soft skip VM) |
| `render.vbpool` | `plugin_render_vbpool` | `all_of` `EnableVBPool` | EarlyNative | 20 | — | — | Win client |
| `render.angle` | `plugin_render_angle` | `AlwaysOn` (`AngleBackend` is a parameter) | EarlyNative | 30 | — | — | Win client |
| `network.rpc` | `plugin_network_rpc` | `all_of` `NetworkOpt` | EarlyNative | 40 | — | — | always |
| `network.sim` | `plugin_network_sim` | `all_of` `EnableNetSim` | EarlyNative | 60 | — | — | Win (DLL always maps; load gated) |
| `save.fork` | `plugin_save_fork` | `all_of` `EnableForkSave` | EarlyNative | 60 | — | — | always (platform-native) |
| `sim.lagcomp` | `plugin_sim_lagcomp` | `all_of` `EnableLagCompensation` | EarlyNative | 60 | — | — | Win; degrades without core.vm context |
| `debug.profiler` | `plugin_debug_profiler` | AlwaysOn (native face) | EarlyNative | 20 | — | — | always (optional DLL; missing ⇒ soft no-op for Tracy/FullGC/FrameGC) |
| `plugin.manager` | `plugin_manager` | AlwaysOn | EarlyNative | 50 | — | — | always (optional DLL; missing ⇒ no package manager; inject + other plugins continue) |
| `debug.dummy` | `plugin_dummy` | AlwaysOn | EarlyNative | 1000 | — | — | always |

### 6.2 Lua (`Mod/plugins/init.lua` order + manifests)

| id | Options | priority | depends | soft_depends | conflicts | `when` (summary) |
|---|---|---:|---|---|---|---|
| `jit.tailcall` | `any_of` SlowTailCall, ForceDisableTailCall, AutoDetectEncryptedMod | 10 | — | — | — | `has_luajit` |
| `debug.profiler` | `any_of` EnableProfiler, EnableTracy, DisableForceFullGC, EnableFrameGC | 20 | — | — | — | `has_luajit` |
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
| 20 | `debug.profiler` (owns former `gc.policy` FullGC/FrameGC) |
| 40 | `network.rpc` (Lua), `network.entity` |
| 50 | `fps.render` |
| 60 | `sim.lagcomp`, `network.sim`, `save.fork` |
| 70 | `jit.runtime` (HideGlobalJIT last among jit-related) |

No production `conflicts` entries today; the host still enforces conflicts if you add them (both Enabled → both `Failed` / `Conflict`).

---

## 7. Examples in-tree

### `save.fork` (package dual-face + dedicated gate)

- Package: `plugins/plugin_save_fork/` (`modinfo` + `modmain` + `scripts/fork_save.lua` + native MODULE)
- Registry: `load_package("plugin_save_fork")` in `Mod/plugins/init.lua`
- Options: `EnableForkSave` (parent modinfo UI; package private `options` names keys)
- `when`: `has_luajit` and not client / dedicated
- `modmain`: `AddGamePostInit` → `modimport("scripts/fork_save")` under package rebind
- Priority 60; sticky unload

### `network.rpc` + `network.entity` (package dual-face + hard dep)

- Native + Lua package: `plugins/plugin_network_rpc/` → EarlyNative when `NetworkOpt`;
  Lua face via `load_package("plugin_network_rpc")` (priority 40)
- Lua-only peer: `Mod/plugins/network_entity.lua` — `depends = { "network.rpc" }`, option `NetworkOptEntity`
- Entity on + rpc off → `MissingHardDep`, entity `load` not called

### `render.vbpool` / `render.angle` (EarlyNative only, dynamic)

- VBPool: `plugin_render_vbpool` — `EnableVBPool` + Win client → `DS_LUAJIT_set_vbpool_enabled(true)`
- Angle: `plugin_render_angle` — AlwaysOn + Win client → `InitGameOpenGl()` (backend string from ConfigView / `business_options`)

### `debug.profiler` (package dual-face: Tracy + FullGC + FrameGC)

- Package: `plugins/plugin_debug_profiler/` → AlwaysOn EarlyNative so exports stay mapped when staged
- Lua face: package `modmain` via `load_package("plugin_debug_profiler")` — AfterModMain priority 20 (before `jit.runtime` HideGlobalJIT)
- Owns: `DS_LUAJIT_replace_profiler_api`, `DS_LUAJIT_enable_tracy`, `DS_LUAJIT_enable_framegc`, `DS_LUAJIT_disable_fullgc`, `lj_gc_fullgc_external`
- Options: `EnableProfiler`, `EnableTracy`, `DisableForceFullGC`, `EnableFrameGC` (modinfo keys unchanged; GenGC still disables FullGC/FrameGC via `disabled_by`)
- Former separate `gc.policy` Lua plugin is merged here (`gc_policy.lua` is a nil-registration shim only)
- Soft peers: missing `plugin_debug_profiler.dll` → inject continues; GameInjector trampolines no-op; `core.vm` fullgc forwarder calls `oldfn`
- Soft peers: missing `plugin_core_vm` → FrameGC / lua_gc path degrades; profiler DLL still loads
- **L0 has no fullgc reverse dep** (`ds_core_vm_fullgc_*` removed)


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

1. Add parent `Mod/modinfo` option(s) if user-facing (D5 UI SSOT).
2. **Native hooks needed at inject time?** → dynamic module under
   `src/DontStarveInjector/plugins/plugin_<stem>/` + `ds_add_dynamic_plugin`.
   Register option schema in `ds_plugin_module_init` **before** `register_plugin`. If cascade must parse the key before Host load, also add it to `RegisterBuiltinBusinessOptionSchema` (or the plugin's cascade seed). **Do not** add a new field on `GameJitModConfig`.
3. **Dual-face / Lua + game API?** → package layout (not flat face):
   - `modinfo.lua` + `modmain.lua` (+ `scripts/`) next to the native sources
   - `init.lua` entry: `load_package("plugin_<stem>")`
   - Identity gate green vs native `man.id` / `man.version` / option keys
4. **Lua-only (no native MODULE this round)?** → flat `Mod/plugins/<name>.lua` +
   `load_flat("<name>")` still OK (`jit.*`, `network.entity`).
5. Set `plugin_id` / `id`, `options`, `depends` / `soft_depends` / `conflicts`, `priority`, `when`/`can_load`.
6. Implement package `modmain` (or flat `load`) only; leave `unload` empty unless `support_reload = true`.
7. Do not edit `Inject()` / `LoadGameModConfig` / `_M:Main` feature lists beyond host calls already present. Keep `RegisterBuiltinPlugins` empty for business features.
8. Extend L-A/L-B/L-C/L-E as appropriate; run L-F; L-G when game binary available; identity gate for dual-face packages.

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
| `src/DontStarveInjector/core/CoreVmBootstrap.*` | Optional load of `plugin_core_vm` + `ds_core_vm_run_signature_and_replace` |
| `src/DontStarveInjector/plugins/plugin_core_vm/` | Optional `core.vm` (Signature + GameLua + GameInjector open; fullgc forwarder only) |
| `src/DontStarveInjector/plugins/plugin_debug_profiler/` | Optional `debug.profiler` (Tracy / FullGC / FrameGC) |
| `src/DontStarveInjector/plugins/plugin_manager/` | Optional `plugin.manager` (channel/pin download; soft-absent) |
| `src/DontStarveInjector/plugins/plugin_*/` | Dynamic native feature modules (rpc/sim/vbpool/angle/fork/lagcomp/dummy/…) |
| `src/DontStarveInjector/core/PluginPendingUpdates.*` | L0 pre-load `plugins/update_pending/` moves (no manager needed) |
| `Mod/plugins/host.lua` | Lua host |
| `Mod/plugins/init.lua` | Lua registry |
| `Mod/plugins/package_load.lua` | Package load helper (modinfo sandbox + modimport rebind) |
| `Mod/plugins/plugin_*/` | Dual-face runtime packages (modinfo/modmain/scripts; DLL staged) |
| `Mod/plugins/*.lua` | Lua-only flat plugins (`load_flat`) |
| `tools/gen_plugins_manifest.py` | Partial manifests + package zips (DLL + package Lua) |
| `tools/check_plugin_package_identity.py` | Dual-face modinfo vs native identity gate |
| `Mod/modmain.lua` | AfterModMain host call site |
| `tests/plugin/*` | L-A/B/C/E/F + `test_config_view_build` / `test_config_schema` |
| `tests/plugin_server/*` | L-G (+ `--scenario present\|absent\|vm_disabled`) |
| `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` | Full architecture (D3: AlwaysEnableMod + VM path *gate* remain L0) |
| `docs/superpowers/specs/2026-08-04-core-vm-plugin-design.md` | Optional core.vm (VM **implementation** ownership) |
| `docs/superpowers/specs/2026-08-04-debug-profiler-plugin-design.md` | `debug.profiler` owns Tracy + FullGC + FrameGC |
| `docs/superpowers/specs/2026-08-04-gamejitmodconfig-pluginization-design.md` | ConfigView SSOT design |

## 11. Dynamic modules (Phase B)

1. Create `src/DontStarveInjector/plugins/plugin_<name>/plugin_<name>.cpp`
2. Export `ds_plugin_module_init` / optional `ds_plugin_module_abi_version` (see `PluginModuleAbi.hpp`)
3. Register `IPlugin*` with static storage duration
4. Add via `ds_add_dynamic_plugin(...)` in Injector CMake (output `Injector/plugins/`)
5. Deploy under **mod** `plugins/` (primary). Game `bin64/plugins/` is compat/dev fallback only.
6. Override search with `DS_LUAJIT_PLUGIN_DIR`

EarlyNative business plugins (`network.rpc`, `render.vbpool`, `render.angle`, …) already ship as dynamic modules. Keep `RegisterBuiltinPlugins` empty unless you need a true L0-only static plugin.

### 11.1 Deploy list (JIT recommended)

| Artifact | Location | Required? | Notes |
|----------|----------|-----------|-------|
| Winmm / POSIX stub | **game** `bin64` (Linux: `bin64/lib64/libInjector.so`) | **Yes** (shell) | Thin inject shell only; no business logic |
| Injector (real) | **mod** `bin64/` (`Injector.dll` / `libInjector.so` / `.dylib`) | **Yes** | L0 inject + PluginHost + DynamicPluginLoader |
| `plugin_core_vm` | **mod** `plugins/` | **Recommended for JIT** | Optional. Missing ⇒ no Signature/ReplaceLuaModule/`GameInjector`; feature plugins still load |
| `plugin_debug_profiler` | **mod** `plugins/` | **Optional (Tracy/FullGC/FrameGC)** | Independent of core.vm |
| `plugin_manager` | **mod** `plugins/` | **Optional (package manager)** | Missing ⇒ manual install only; UI soft-degrades. See **§13** |
| other `plugin_*` | **mod** `plugins/` | Per feature | `network_*`, `render_*`, `save_fork`, `sim_lagcomp`, `dummy`, … |
| third-party runtime deps | **mod** `deps/` | As needed | Shared DLL/SO search for Injector + plugins |

Override paths: `DS_LUAJIT_INJECTOR` / `DS_LUAJIT_INJECTOR_DIR` (real Injector); `DS_LUAJIT_PLUGIN_DIR` (plugins). Marker: `data/unsafedata/ds_luajit_injector.path`.

`DisableJITWhenServer` (or harness `DS_LUAJIT_FORCE_DISABLE_VM=1`) only skips the VM path; it does **not** skip DynamicPluginLoader. Harness negative path: rename `plugin_core_vm.dll` or set `DS_LUAJIT_FORCE_NO_CORE_VM=1`.

Related designs: `docs/superpowers/specs/2026-08-03-dynamic-plugin-skeleton-design.md`, `docs/superpowers/specs/2026-08-04-core-vm-plugin-design.md`.

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
| `EnableProfiler` | String | `off` (`off,fzvp,Gz`) | `debug.profiler` | AlwaysOn native; Lua `any_of` |
| `EnableTracy` | String | `off` (`off,on`) | `debug.profiler` | AlwaysOn native; Lua `any_of` |
| `DisableForceFullGC` | Bool | `true` | `debug.profiler` | AlwaysOn native; Lua `any_of` |
| `EnableFrameGC` | Bool | `true` | `debug.profiler` | AlwaysOn native; Lua `any_of` |

`debug.dummy` is AlwaysOn with no option schema (load always when `can_load`).

## 13. Plugin install paths and optional `plugin.manager`

Design: `docs/superpowers/specs/2026-08-05-plugin-manager-design.md` (**Accepted** — fully optional / non-core).

**Manual install is first-class.** The optional `plugin.manager` module is pure upside (in-game pin/download). Deleting it must never break Inject, PluginHost, or any business plugin.

### 13.1 Manual install (baseline — no manager required)

| Source | How |
|---|---|
| `{platform}_Mod.zip` | Unpack the monorepo release zip; keep `plugins/` under the **mod** root (not game `bin64/plugins`). Run `install.bat` / `install_linux.sh` for shell + real Injector staging. |
| Per-plugin zip | From the same Release: `plugin_<stem>-<ver>-<platform>.zip` (e.g. `plugin_network_rpc-1.0.0-windows.zip`). Extract module + optional `plugin_*.meta.json` into mod `plugins/`. |
| `plugins/update_pending/` | Drop replacement modules here when the live DLL is locked. L0 `apply_pending_plugin_updates` runs **before** `LoadLibrary` on every inject — no manager needed. |

Also published for humans and tools: `plugins-manifest.json` (catalog of ids, versions, assets, sha256). CI stages `plugins/` via `install(TARGETS … DESTINATION plugins)` so Mod zips include modules even without the manager.

```text
Release assets (manual baseline):
  {platform}_Mod.zip              full mod + shell package + real Injector + plugins/ + deps/
  plugins-manifest.json           catalog
  plugin_<stem>-<ver>-<platform>.zip   single module package
```

After any manual copy, **restart the game / dedicated process** so DynamicPluginLoader can LoadLibrary the new files. There is no FreeLibrary hot-swap.

### 13.2 Optional `plugin.manager` (when present)

| Field | Value |
|---|---|
| Logical id | `plugin.manager` |
| Module stem | `plugin_manager` (`plugin_manager.dll` / `.so` / `.dylib`) |
| Phase | EarlyNative, AlwaysOn if loaded, priority 50 |
| Core dependency | **No** |

When the module is staged:

1. **Config** — independent `data/unsafedata/luajit_plugins.json` (override env `DS_LUAJIT_PLUGINS_CONFIG`). Channel (`repo` / `stable|preview` / tag / `follow_latest`), download (`github_base`, `gh_proxy_base`, `prefer_proxy=auto|always|never`, `auto_apply_on_boot`), per-id pins, soft `prefer_present` (default empty — never blocks boot).
2. **Download** — GitHub Releases; gh-proxy wrap when direct probe fails (`prefer_proxy=auto`).
3. **Apply** — extract allowlisted files into `plugins/` or `plugins/update_pending/` if locked; set `needs_restart`.
4. **UI** — this mod’s `ModConfigurationScreen` action-bar **Plugin Manager / 插件管理** (all platforms). Full list / channel / pin / apply when exports present.
5. **Dedicated** — no UI; optional `auto_apply_on_boot` only if the module loaded.

GameInjector surface (registered only when the module loads): `DS_LUAJIT_plugin_config_path`, `DS_LUAJIT_plugin_manager_status_json`, `DS_LUAJIT_plugin_config_reload`, `DS_LUAJIT_plugin_config_set_json`, `DS_LUAJIT_plugin_pin_set` / `pin_clear`, `DS_LUAJIT_plugin_fetch_manifest`, `DS_LUAJIT_plugin_manifest_json`, `DS_LUAJIT_plugin_plan_apply_json`, `DS_LUAJIT_plugin_apply`, `DS_LUAJIT_plugin_needs_restart`.

Lua always soft-looks up these names. Missing export ⇒ `nil` / popup with manual install guidance — never a hard Injector error.

### 13.3 Soft absence / non-core guarantee

| Rule | Detail |
|---|---|
| Dependency class | Optional enhancement only |
| Missing module | Same as any absent `plugin_*`; loader skips; no Injector error |
| Other plugins | **Must not** list `plugin.manager` in `depends` / `soft_depends` or `DS_LUAJIT_plugin_*` in `requires_services` / `soft_requires_services` |
| Pins / prefer_present | Missing file or soft preference never blocks boot |
| First install of manager | Manual (full Mod.zip or `plugin_manager-*-<platform>.zip`) |
| Self-update | When present, manager may pin/update/remove itself (no special bootstrap lock) |

**Grep guard (CI/review):** no production plugin outside `plugin_manager` may hard-depend on manager APIs.

### 13.4 Restart after apply

Successful replace writes new files (or `update_pending/`) and reports `needs_restart`. Sticky modules are not reloaded in-process. User/UI must restart (client Quit/`DoRestart` confirm; dedicated process restart) before the new modules load. Pending dir is applied on the **next** inject before LoadLibrary.

### 13.5 Absence hardening checklist

```text
[ ] Delete plugin_manager.dll → dedicated/client still injects
[ ] Other plugins load; no MissingService for manager APIs
[ ] UI shows manual guidance
[ ] Restore DLL → manager functions
[ ] Manual copy of a business plugin zip still works without manager
```

Related plan: `docs/superpowers/plans/2026-08-05-plugin-manager.md`.

