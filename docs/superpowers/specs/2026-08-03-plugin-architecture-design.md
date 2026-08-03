# Plugin Architecture Design — DontStarveLuaJIT2 Injector

**Date:** 2026-08-03  
**Status:** Draft for review  
**Scope:** Decouple the injection framework into a core (inject + hook) base and a plugin host that loads feature modules by `modinfo.lua` configuration, with simple dependency orchestration.

---

## 1. Decisions (locked)

| # | Decision | Choice |
|---|---|---|
| D1 | First-phase delivery | **Path A**: in-process static plugin registry, single `Injector` shared library. Dynamic per-plugin DLLs/SOs are a **later phase**, not in this design's implementation scope. |
| D2 | Dependency / conflict failure | **Fail-fast**: missing hard dependency, cycle, or conflict aborts that plugin's load with a hard error log; Host does not silently skip hard deps. Host itself stays up so other independent plugins can still load unless the failure is in L0. |
| D3 | VM selection / AlwaysEnableMod | **L0 core**, not plugins. Without them the plugin system cannot boot or force-load this mod. |
| D4 | Unload policy | **Sticky by default**. Only plugins that set `support_reload = true` (and Lua plugins that implement `unload`) may be unloaded. Most native hooks remain sticky for process lifetime. |
| D5 | Config surface | `Mod/modinfo.lua` `configuration_options` remains the **only** user-facing config. Multiple options may map to one plugin. |
| D6 | Fail-fast style | No defensive “if API missing then no-op”. Missing required APIs/symbols error immediately (project convention). |

---

## 2. Problem statement

Today features are hard-wired, not modular:

| Layer | Entry | Problem |
|---|---|---|
| Inject | `Inject()` in `src/DontStarveInjector/DontStarveInjector.cpp` | Directly calls `ReplaceLuaModule`, `LoadGameModConfig`, `GameNetWorkHookRpc4`, Steam, etc. |
| Early config side effects | `LoadGameModConfig()` in `gameModConfig.cpp` | Hard-enables VBPool + `InitGameOpenGl` |
| Lua orchestration | `modmain._M:Main()` in `Mod/modmain.lua` | Fixed-order stack of dozens of features |
| Build | Single `Injector` SHARED target | All features compiled in; no per-feature boundary |
| Config | `modinfo.configuration_options` | Scattered consumers: some early-native, some late-Lua; no unified lifecycle |

**Coupling hotspots:** `InjectorCtx`, `GameJitModConfig`, `GameLuaContext` singletons; shared `DS_LUAJIT_replace_profiler_api` used by Tracy / FrameGC / FullGC; NetworkOpt requires RPC4 hook installed at inject time.

---

## 3. Goals / non-goals

### Goals

1. Split responsibilities: **L0 core** (inject + hook infrastructure + host) vs **plugins** (features).
2. Load / (optional) unload plugins according to `modinfo` options + platform/role gates.
3. Simple dependency orchestration: hard depends, soft depends, conflicts, cycle detection, phase barriers.
4. One plugin may bind multiple `configuration_options`.
5. Adding a feature = new plugin + manifest; **no** edits to `Inject()` / `_M:Main()` trunks beyond host calls.
6. With all plugins disabled, core still injects and the game remains playable on the selected VM.

### Non-goals (YAGNI)

- Plugin marketplace / remote install / third-party sandbox.
- Full package version negotiation (semver ranges, etc.).
- Forced hot-unload of all native hooks.
- Extra factory/framework libraries “for flexibility”.
- Turning Signature / FunctionRelocation into user plugins.
- Shipping dynamic plugin DLLs in this phase (documented as Phase B only).

---

## 4. Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│ L0 Core (always loaded)                                     │
│  Loader / HookStartup                                       │
│  Gum + Signature                                            │
│  Lua VM replace + GameLuaInjectFramework + GameInjector min │
│  Config cascade                                             │
│  PluginHost (discover, dep graph, load phases, fail-fast)   │
│  core.vm + AlwaysEnableMod + crash guard                    │
└───────────────────────────┬─────────────────────────────────┘
                            │ PluginHost
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
   EarlyNative         AfterLuaBridge    AfterModMain
   (native plugins)    (API export)      (Lua + late native)
```

### 4.1 L0 Core — responsibilities

**Does:**

1. Process inject / startup hook (`winmm` / `chdir` / `HookStartupEntry`).
2. Frida Gum interceptor lifecycle (`InjectorCtx`).
3. Signature scan + Lua export remap + **VM selection** (`LuaVmType`, `EnabledGenGC`, `DisableJITWhenServer` gate).
4. Embedded `GameLuaInjectFramework` (require injectors, event bus, force-enable path).
5. Minimal `GameInjector` bridge: config query, logging, plugin API registration surface.
6. **PluginHost**: discovery, topological sort, load phases, fail-fast on hard errors.
7. Config resolution cascade: modinfo defaults → `luajit_config.json` → save modconfiguration → env/cmd.
8. Crash guard (`luajit_crash.json`).
9. **AlwaysEnableMod** force-load of this mod (required so plugins can run).

**Does not:**

- VBPool, Network RPC/entity/sim, LagComp, ForkSave, ANGLE backend policy as feature logic, Profiler/Tracy business logic, JIT blacklist UI logic, FrameGC/FullGC policy.

### 4.2 Plugin layers

| Layer | When | Examples |
|---|---|---|
| L1 Native plugins | EarlyNative / AfterLuaBridge / sticky | angle, vbpool, network.rpc, network.entity, network.sim, sim.lagcomp, save.fork, profiler.tracy, steam.workshop |
| L2 Lua plugins | AfterModMain | jit.runtime, jit.tailcall, gc.policy, fps.render, save.fork (Lua face), lagcomp/netsim Lua faces |

Native + Lua faces of the **same feature share one plugin id** (e.g. `save.fork` owns both `GameForkSave.cpp` and `scripts/fork_save.lua`).

### 4.3 Delivery path

- **Phase A (this design):** static registration inside `Injector` (`PLUGIN_REGISTER` / static initializers or explicit register table in one translation unit). Same binary, clear logical boundaries.
- **Phase B (later):** optional split into dynamic libraries loaded by Host; same `IPlugin` / manifest contract. Not designed in detail here beyond “interface must not assume static-only linkage.”

---

## 5. Plugin contract

### 5.1 Manifest (shared concepts; C++ and Lua)

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable id, dotted form: `render.vbpool`, `save.fork` |
| `version` | string | Informational for logs |
| `depends` | string[] | Hard dependencies (ids). Missing → **fail-fast** for this plugin |
| `soft_depends` | string[] | Load first if present; absence OK |
| `conflicts` | string[] | Mutual exclusion; both enabled → **fail-fast** |
| `phases` | flags | `EarlyNative`, `AfterLuaBridge`, `AfterModMain`, `OnDemand` |
| `options` | option rule | Which `modinfo` keys enable this plugin (see §6) |
| `support_reload` | bool | Default `false` (sticky). If true, `unload` may be called |
| `when` | gate | Platform / client-server / dedicated / mastersim (evaluated at resolve time) |

### 5.2 C++ interface (Phase A)

```cpp
enum class PluginPhase : uint32_t {
    EarlyNative    = 1 << 0,
    AfterLuaBridge = 1 << 1,
    AfterModMain   = 1 << 2,
    OnDemand       = 1 << 3,
};

struct PluginContext {
    InjectorCtx* injector;
    const GameJitModConfig* config;   // resolved cascade snapshot
    bool is_client;
    // Config option lookup for this process (already merged)
    // Exact API: Host-owned; plugins do not re-parse save files.
};

struct PluginManifest {
    std::string_view id;
    std::string_view version;
    std::span<const std::string_view> depends;
    std::span<const std::string_view> soft_depends;
    std::span<const std::string_view> conflicts;
    PluginPhase phases;
    bool support_reload;
};

struct IPlugin {
    virtual const PluginManifest& manifest() const = 0;
    // Platform/role/config gate after options resolved.
    virtual bool can_load(const PluginContext&) const = 0;
    // Install hooks / register APIs. Throw or return error → Host fail-fast this plugin.
    virtual void load(PluginContext&) = 0;
    // Only called if support_reload; default no-op or assert sticky.
    virtual void unload(PluginContext&) = 0;
};
```

Registration (Phase A):

```cpp
// Explicit table preferred over magic static init order:
void RegisterBuiltinPlugins(PluginHost&);
// Called once from L0 after Config is ready, before EarlyNative phase.
```

### 5.3 Lua plugin shape

```lua
-- Mod/plugins/<id>/plugin.lua  (path convention)
return {
  id = "save.fork",
  version = "1.0.0",
  depends = { "core.luabridge" },  -- logical; core always present
  soft_depends = {},
  conflicts = {},
  options = { all_of = { "EnableForkSave" } },
  support_reload = false,
  when = function(ctx)
    return ctx.has_luajit and TheNet:IsDedicated()
  end,
  load = function(ctx)
    -- existing path preserved:
    modimport("scripts/fork_save")
  end,
  unload = function(ctx) end,
}
```

Lua plugins are discovered from a fixed directory list (or an explicit registry table in `Mod/plugins/init.lua` for Phase A — **explicit registry preferred** to avoid filesystem scanning surprises in the game sandbox).

### 5.4 Dual-face plugins

For features with native + Lua:

| Face | Phase | Role |
|---|---|---|
| Native | EarlyNative and/or AfterLuaBridge | Hooks, `DS_LUAJIT_*` export registration |
| Lua | AfterModMain | Game-facing hooks (`SaveGame`, `FindEntities`, HUD, etc.) |

Host tracks one logical plugin id; faces are ordered: native load completes before Lua `load` for that id when both exist.

---

## 6. Config → plugin enablement

### 6.1 Option rules

Manifest `options` supports:

| Form | Meaning |
|---|---|
| `{ all_of = { "A", "B" } }` | Enabled only if every listed option is “on” |
| `{ any_of = { "A", "B" } }` | Enabled if any listed option is “on” |
| `{ option = "A" }` | Shorthand for `all_of = { "A" }` |

**“On” definition** (must match current modinfo semantics):

- Boolean options: `true` is on, `false` is off.
- Enum/string options used as feature switches (e.g. `EnableProfiler ~= "off"`, `EnableTracy == "on"`): plugin manifests use an explicit predicate where needed, not raw truthiness alone.
- Options with `disabled_by` in modinfo: Host uses the **already resolved** `GetModConfigData` / native cascade value (same as today after disable rules). Do not reimplement `disabled_by` inside Host.

### 6.2 Resolve order

```text
1. Load config cascade (L0)
2. For each registered plugin:
   a. Evaluate options rule → enabled?
   b. Evaluate when(ctx) → allowed?
   c. If not enabled or not allowed → mark Disabled (not an error)
3. Among Enabled plugins:
   a. Detect conflicts → fail-fast (error, plugin not loaded)
   b. Detect missing hard depends → fail-fast
   c. Detect cycles → fail-fast (Host error; do not load the cyclic set)
4. Topological sort (hard + soft edges where soft target is Enabled)
5. Load by phase barrier:
   EarlyNative (all) → AfterLuaBridge (all) → AfterModMain (all)
```

### 6.3 Fail-fast semantics (D2)

| Condition | Behavior |
|---|---|
| Hard dep missing (not registered or Disabled) | Error log with plugin id + missing dep; **do not load** this plugin; continue other independent plugins |
| Conflict between two Enabled plugins | Error both ids; **load neither** |
| Cycle | Error the cycle path; **load none** in the cycle |
| `load()` throws / returns failure | Error; plugin considered failed; dependents that hard-depend on it fail-fast as missing |
| L0 failure (signature, VM replace) | Existing behavior: abort inject |

Note: “fail-fast” means **no silent degradation** of a plugin that cannot correctly run. It does **not** mean one plugin failure kills the entire inject unless L0 itself fails.

---

## 7. Plugin inventory (initial mapping)

### 7.1 L0 (not plugins)

| Capability | modinfo / trigger | Code today |
|---|---|---|
| VM select | `LuaVmType`, `EnabledGenGC` | `GameLua.cpp` ReplaceLuaModule |
| Server inject gate | `DisableJITWhenServer` | `Inject()` early return |
| Force enable mod | `AlwaysEnableMod` | forceEnableLuaMod + luajit_config write |
| Crash guard | internal | `check_crash` / modmain clear |
| PluginHost + config cascade | — | new + `gameModConfig` |

### 7.2 Plugins

| Plugin id | Options | Phase(s) | Current code | Notes |
|---|---|---|---|---|
| `steam.workshop` | (always when Steam build) | EarlyNative | `GameSteam.cpp` | Soft: infrastructure for workshop paths |
| `render.angle` | `AngleBackend` | EarlyNative | `GameOpenGl.cpp` | Win; sticky |
| `render.vbpool` | `EnableVBPool` | EarlyNative | `GameRenderHook.cpp` | Early enable; modmain may only disable late today → move disable into plugin policy |
| `network.rpc` | `NetworkOpt` | EarlyNative + AfterModMain | `GameNetwork.cpp` + modmain NetWorkOpt | Hook install early; Lua use late |
| `network.entity` | `NetworkOptEntity` | AfterModMain | entity register path | **depends:** `network.rpc` |
| `network.sim` | `EnableNetSim` | AfterModMain | `GameNetworkSim.cpp` + `scripts/netsim.lua` | Client, Win |
| `sim.lagcomp` | `EnableLagCompensation` | AfterModMain | `GameSimHook.cpp` + `scripts/lag_compensation.lua` | Mastersim, Win |
| `save.fork` | `EnableForkSave` | AfterModMain | `GameForkSave.cpp` + `scripts/fork_save.lua` | Dedicated; has_luajit |
| `jit.runtime` | `EnabledJIT`, `HideGlobalJIT`, `ModBlackList` | AfterModMain | modmain JIT paths | HideGlobalJIT **after** profiler plugins |
| `jit.tailcall` | `SlowTailCall`, `AnyModDisableTailCall`, `ForceDisableTailCall`, `AutoDetectEncryptedMod` | AfterModMain | SlowTailCall + encrypt manager | Before encrypted mods load |
| `gc.policy` | `DisableForceFullGC`, `EnableFrameGC` | AfterModMain | fullgc/framegc | Soft/hard conflict with GenGC via options already disabled_by |
| `fps.render` | `TargetRenderFPS` | AfterModMain | `DS_LUAJIT_set_target_fps` | Win-meaningful |
| `debug.profiler` | `EnableProfiler`, `EnableTracy` | AfterModMain | profiler/tracy | Must load **before** `jit.runtime` HideGlobalJIT; use depends/soft_depends |
| `compat.frostxx` | (internal / tied to encrypt path) | AfterModMain | decrypt + kleiloadlua | May merge into `jit.tailcall` if too thin |

**Ordering constraints to encode in depends:**

- `network.entity` → depends `network.rpc`
- `debug.profiler` loads before `jit.runtime` (HideGlobalJIT): `jit.runtime` soft_depends or depends `debug.profiler` when profiler options on — prefer: Host phase sub-order list for AfterModMain fixed as: tailcall → profiler → gc → network.* → fps → lagcomp/netsim/fork → jit.runtime (hide last). Document this as **default AfterModMain priority** plus explicit depends for true requirements.

### 7.3 Default AfterModMain priority (stable sort key)

When topology ties, use this priority (low number first):

1. `jit.tailcall` / `compat.frostxx`
2. `debug.profiler`
3. `gc.policy`
4. `network.rpc` (Lua face), `network.entity`
5. `fps.render`
6. `sim.lagcomp`, `network.sim`, `save.fork`
7. `jit.runtime` (including HideGlobalJIT)

---

## 8. Lifecycle

```text
[Loader] HookStartup / chdir
    → Inject(isClient)
        → L0: gum, signature, crash guard, DisableJITWhenServer gate
        → ReplaceLuaModule (VM = L0)
        → Config cascade ready
        → RegisterBuiltinPlugins
        → PluginHost.resolve(config)
        → PluginHost.load_phase(EarlyNative)
        → (return from Inject)

[openlibs]
    → GameLuaInjectFramework.init
    → AlwaysEnableMod (L0)
    → luaopen_GameInjector (core + per-plugin API registration hooks)
    → PluginHost.load_phase(AfterLuaBridge)

[modmain]
    → if no GameInjector → NoInjectorMain (unchanged)
    → else PluginHost.sync_lua_plugins(GetModConfigData)
    → PluginHost.load_phase(AfterModMain)  // topo + priority
    → Main() body shrinks to host run + version check UI leftovers

[optional debug]
    → unload/load only if support_reload
```

### 8.1 GameInjector surface evolution

| Phase | Shape |
|---|---|
| A1 | Keep existing `DS_LUAJIT_*` exports; plugins register into the same sol2 table |
| A2 | Namespace: `GameInjector.core.*`, `GameInjector.plugins[id].*` with **aliases** to old names |
| A3 (later) | Remove aliases after call sites migrated |

No big-bang rename required for first merge.

### 8.2 What happens to `LoadGameModConfig`

Today it enables VBPool + OpenGL. After split:

- Config **resolution** stays L0 (`GameJitModConfig::instance` cascade).
- Side effects move into `render.vbpool` / `render.angle` EarlyNative `load()`.
- `LoadGameModConfig()` becomes “resolve config + run EarlyNative phase” or is inlined into `Inject` as two clear steps.

---

## 9. Build layout (Phase A)

Still one SHARED target `Injector`, but sources grouped:

```text
src/DontStarveInjector/
  core/           # Inject, ctx, signature glue, PluginHost, config
  plugins/
    render_angle/
    render_vbpool/
    network_rpc/
    network_entity/
    network_sim/
    sim_lagcomp/
    save_fork/
    debug_profiler/
    steam_workshop/
  # transitional: existing files move gradually; no mandatory rename in first PR
```

CMake: source lists per plugin object group; still `target_link_libraries(Injector ...)`.  
Optional compile flags later: `-DDL_PLUGIN_VBPOOL=0` style is **not** required in Phase A (config gates at runtime).

Lua:

```text
Mod/
  plugins/
    init.lua              # explicit registry of plugin modules
    jit_runtime.lua
    jit_tailcall.lua
    gc_policy.lua
    fps_render.lua
    save_fork.lua         # thin wrapper → scripts/fork_save.lua or inlined
    ...
  scripts/                # heavy implementations stay until moved
  modmain.lua             # host bootstrap only
```

---

## 10. Migration plan (incremental, always shippable)

| Step | Deliverable | Success check |
|---|---|---|
| M0 | `PluginHost` + manifest types + empty registry; `Inject` / Main still linear | Game boots unchanged |
| M1 | Move `save.fork`, `sim.lagcomp`, `network.sim` into plugins (dual-face) | Toggles via modinfo identical |
| M2 | `network.rpc` + `network.entity` + depends edge | Entity opt off when rpc plugin failed |
| M3 | `render.angle` + `render.vbpool` EarlyNative | Early GL/ANGLE behavior preserved |
| M4 | `jit.*`, `gc.policy`, `debug.profiler`, `fps.render` | HideGlobalJIT still after profiler |
| M5 | Slim `modmain._M:Main` → host; slim `Inject` / `LoadGameModConfig` | No feature logic in trunks |
| M6 | Docs: plugin table + how to add a plugin | Contributor can add feature without touching Inject |
| M7 (later Phase B) | Dynamic library loader behind same interface | Out of scope for initial implementation |

Each step is one or more PRs; no “stop the world” rewrite.

---

## 11. Error handling & logging

- Host logs: `plugin=id phase=... event=resolve|load|fail|skip reason=...`
- Fail-fast messages must include: plugin id, dependency id / conflict peer, phase.
- Match existing spdlog levels; inject path already sets level by build/debugger.
- Lua: `print("[luajit][plugin] ...")` or host-provided `ctx.log` for consistency.

---

## 12. Testing strategy

| Layer | What |
|---|---|
| Host unit (C++ or Lua harness) | Topo sort, cycle detect, conflict, missing hard dep, soft dep ignored, priority tie-break |
| Option rule | `all_of` / `any_of` / profiler string predicates |
| Integration (manual / existing game runs) | Each migrated plugin: option on → behavior on; option off → no hook / no modimport |
| Regression | fork_save tests under `tests/fork_save/` stay green after `save.fork` migration |
| Boot | All plugins disabled (or defaults) still enters game |

No requirement to invent a full native hook integration suite in M0; Host graph tests are mandatory before M1.

---

## 13. Success criteria

1. New feature = new plugin + manifest registration; **no** trunk edits to feature lists in `Inject()` / `_M:Main()`.
2. Disabling a modinfo option prevents that plugin’s hooks/modimport.
3. Missing hard dep / cycle / conflict → visible error, no silent half-enable.
4. `modinfo` remains sole user config; multi-option → single plugin documented in §7.
5. Core-only (plugins all disabled) still injects and runs selected VM.
6. Phase B possible without rewriting manifests (interface does not assume static-only).

---

## 14. Open follow-ups (explicitly deferred)

- Dynamic plugin DLLs/SOs (Phase B).
- Hot reload UX / console commands for `support_reload` plugins.
- Splitting `GameLuaModule.cpp` god-export into per-plugin registration only after A2 aliases.
- Whether `compat.frostxx` stays separate or folds into `jit.tailcall`.
- CMake per-plugin object libraries as optional cleanup after M5.

---

## 15. Source anchors (current system)

| Concern | Location |
|---|---|
| Inject entry | `src/DontStarveInjector/DontStarveInjector.cpp` `Inject` ~225, `HookStartupEntry` ~376 |
| Early feature side effects | `gameModConfig.cpp` `LoadGameModConfig` ~750 |
| Lua orchestration | `Mod/modmain.lua` `_M:Main` ~1083 |
| Config UI | `Mod/modinfo.lua` `configuration_options` ~92–440 |
| GameInjector export | `GameLuaModule.cpp` `luaopen_GameInjector` |
| Build target | `src/DontStarveInjector/CMakeLists.txt` single `Injector` SHARED |

---

## 16. Spec self-review

| Check | Result |
|---|---|
| Placeholders | None intentional; Phase B intentionally deferred with boundary |
| Consistency | D1–D6 match §4–§8; fail-fast = no silent plugin degradation, not “kill whole inject” |
| Scope | Single architecture spec; implementation will be multi-PR via §10 |
| Ambiguity | Option “on” for string enums requires explicit predicates — stated in §6.1 |
| Locked decisions | Path A, fail-fast, L0 vm/force-mod, sticky unload — §1 |
