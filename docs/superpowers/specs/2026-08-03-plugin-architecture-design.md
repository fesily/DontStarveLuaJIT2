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
| D3 | VM selection / AlwaysEnableMod | **L0 core** for the *gate* and AlwaysEnableMod (without force-enable, plugins cannot boot this mod). **Superseded for VM *implementation* ownership:** Signature + `ReplaceLuaModule` + `GameLua` live in optional `plugin_core_vm` (id `core.vm`) — see `docs/superpowers/specs/2026-08-04-core-vm-plugin-design.md`. Missing core.vm soft-skips JIT; feature plugins still load. |
| D4 | Unload policy | **Sticky by default**. Only plugins that set `support_reload = true` (and Lua plugins that implement `unload`) may be unloaded. Most native hooks remain sticky for process lifetime. |
| D5 | Config surface | `Mod/modinfo.lua` `configuration_options` remains the **only** user-facing config. Multiple options may map to one plugin. |
| D6 | Fail-fast style | No defensive “if API missing then no-op”. Missing required APIs/symbols error immediately (project convention). |
| D7 | Success requires tests | Architecture is **not done** without automated gates in §12. Narrative goals without a §13 mapping are non-blocking. |
| D8 | Final game proof | **Automated dedicated-server harness (L-G)**. Must prove injector + plugin modules load successfully and the sim reaches a **stable paused** state. **Implementation is the next step after Host unit gates (M0+)** — specified now, built as its own deliverable (`M-G`), not left as permanent manual-only. |

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
7. **Every success criterion is proven by an automated test.** Final runtime proof is automated dedicated-server L-G (§12.10), not “boots on my machine.”

### Non-goals (YAGNI)

- Plugin marketplace / remote install / third-party sandbox.
- Full package version negotiation (semver ranges, etc.).
- Forced hot-unload of all native hooks.
- Extra factory/framework libraries “for flexibility”.
- Turning Signature / FunctionRelocation into user plugins.
- Shipping dynamic plugin DLLs in this phase (documented as Phase B only).
- Full multiplayer client-bot graphics/network fidelity suite in Phase A (L-G is **dedicated-server** path first; client bots optional later).

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

enum class PluginStatus : uint8_t {
    Registered,
    Disabled,   // options/when off — not an error
    Failed,     // hard dep / conflict / cycle / load error
    Loaded,
};

enum class PluginFailReason : uint8_t {
    None,
    MissingHardDep,
    Conflict,
    Cycle,
    LoadThrew,
    CanLoadFalse, // treated as Disabled, not Failed, if options were on but gate false — see §6
};

struct PluginEvent {
    std::string_view plugin_id;
    PluginPhase phase;       // meaningful for load/unload events
    PluginStatus status;
    PluginFailReason reason;
    std::string_view detail; // missing dep id, conflict peer, cycle path, etc.
};

struct PluginContext {
    InjectorCtx* injector;                 // may be null in unit tests
    const GameJitModConfig* config;        // may be null in unit tests; use ConfigView
    bool is_client;
    // Host-owned option lookup (already merged). Plugins do not re-parse save files.
};

struct PluginManifest {
    std::string_view id;
    std::string_view version;
    std::span<const std::string_view> depends;
    std::span<const std::string_view> soft_depends;
    std::span<const std::string_view> conflicts;
    PluginPhase phases;
    bool support_reload;
    int priority; // lower runs first within a phase when topo-tied; see §7.3
};

struct IPlugin {
    virtual const PluginManifest& manifest() const = 0;
    virtual bool can_load(const PluginContext&) const = 0;
    virtual void load(PluginContext&) = 0;
    virtual void unload(PluginContext&) = 0;
};
```

Registration (Phase A):

```cpp
// Explicit table preferred over magic static init order:
void RegisterBuiltinPlugins(PluginHost&);
// Called once from L0 after Config is ready, before EarlyNative phase.
```

**Testability requirement:** `PluginHost` must expose (at least for tests):

```cpp
void register_plugin(IPlugin*);
// ConfigView = resolved key→variant map (bool/string/number), no file IO.
struct ResolveResult { /* enabled set, failed set, events */ };
ResolveResult resolve(const ConfigView&, const PluginContext& gate_ctx);
struct LoadResult { /* loaded order, events */ };
LoadResult load_phase(PluginPhase);
const std::vector<PluginEvent>& events() const;
PluginStatus status(std::string_view id) const;
// Optional: ordered list of successfully loaded ids for a phase.
std::vector<std::string_view> loaded_order(PluginPhase) const;
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
  priority = 60, -- align with §7.3 band
  when = function(ctx)
    return ctx.has_luajit and TheNet:IsDedicated()
  end,
  load = function(ctx)
    modimport("scripts/fork_save")
  end,
  unload = function(ctx) end,
}
```

Phase A discovery: **explicit registry** in `Mod/plugins/init.lua` (no filesystem scanning in the game sandbox).

### 5.4 Dual-face plugins

| Face | Phase | Role |
|---|---|---|
| Native | EarlyNative and/or AfterLuaBridge | Hooks, `DS_LUAJIT_*` export registration |
| Lua | AfterModMain | Game-facing hooks (`SaveGame`, `FindEntities`, HUD, etc.) |

Host tracks one logical plugin id; native face completes before Lua `load` for that id when both exist.

---

## 6. Config → plugin enablement

### 6.1 Option rules

| Form | Meaning |
|---|---|
| `{ all_of = { "A", "B" } }` | Enabled only if every listed option is “on” |
| `{ any_of = { "A", "B" } }` | Enabled if any listed option is “on” |
| `{ option = "A" }` | Shorthand for `all_of = { "A" }` |
| predicate | For string enums: e.g. `EnableProfiler != "off"`, `EnableTracy == "on"` |

**“On” definition** (must match current modinfo semantics):

- Boolean: `true` on, `false` off.
- String feature switches: use explicit predicates in the manifest (not raw Lua truthiness).
- `disabled_by` in modinfo: Host consumes **already resolved** values (same as `GetModConfigData` / native cascade after disable rules). Host does **not** reimplement `disabled_by`.

### 6.2 Resolve order

```text
1. Load config cascade (L0)
2. For each registered plugin:
   a. Evaluate options rule → option_enabled?
   b. Evaluate when/can_load(ctx) → allowed?
   c. If not option_enabled or not allowed → status=Disabled (not Failed)
3. Among option+gate Enabled plugins:
   a. Conflicts → both Failed (Conflict); load neither
   b. Missing hard depends → dependent Failed (MissingHardDep)
   c. Cycles → all members Failed (Cycle)
4. Topological sort (hard + soft edges where soft target is Enabled)
5. Load by phase barrier:
   EarlyNative (all) → AfterLuaBridge (all) → AfterModMain (all)
   Within phase: topo order, then priority ascending for ties
```

### 6.3 Fail-fast semantics (D2)

| Condition | Behavior |
|---|---|
| Hard dep missing (not registered or Disabled/Failed) | `Failed` + `MissingHardDep`; **do not** call `load()`; other independent plugins continue |
| Conflict between two Enabled plugins | both `Failed` + `Conflict`; **load neither** |
| Cycle | all in cycle `Failed` + `Cycle`; **load none** in cycle |
| `load()` throws | that plugin `Failed` + `LoadThrew`; hard dependents become Failed as missing |
| L0 failure (signature, VM replace) | abort inject (existing) |

“Fail-fast” = **no silent half-enable**. It does **not** mean one feature failure kills entire inject unless L0 fails.

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
| `steam.workshop` | (always when Steam build) | EarlyNative | `GameSteam.cpp` | workshop path infra |
| `render.angle` | `AngleBackend` | EarlyNative | `GameOpenGl.cpp` | Win; sticky; backend is param |
| `render.vbpool` | `EnableVBPool` | EarlyNative | `GameRenderHook.cpp` | early enable before first HWBuffer |
| `network.rpc` | `NetworkOpt` | EarlyNative + AfterModMain | `GameNetwork.cpp` + modmain NetWorkOpt | hook early; Lua late |
| `network.entity` | `NetworkOptEntity` | AfterModMain | entity register | **depends:** `network.rpc` |
| `network.sim` | `EnableNetSim` | AfterModMain | `GameNetworkSim` + `scripts/netsim.lua` | Client, Win |
| `sim.lagcomp` | `EnableLagCompensation` | AfterModMain | `GameSimHook` + `scripts/lag_compensation.lua` | Mastersim, Win |
| `save.fork` | `EnableForkSave` | AfterModMain | `GameForkSave` + `scripts/fork_save.lua` | Dedicated; has_luajit |
| `jit.runtime` | `EnabledJIT`, `HideGlobalJIT`, `ModBlackList` | AfterModMain | modmain JIT | HideGlobalJIT **last** among jit-related |
| `jit.tailcall` | `SlowTailCall`, `AnyModDisableTailCall`, `ForceDisableTailCall`, `AutoDetectEncryptedMod` | AfterModMain | SlowTailCall + encrypt | before encrypted mods |
| `gc.policy` | `DisableForceFullGC`, `EnableFrameGC` | AfterModMain | fullgc/framegc | GenGC disables via modinfo `disabled_by` |
| `fps.render` | `TargetRenderFPS` | AfterModMain | `DS_LUAJIT_set_target_fps` | Win-meaningful |
| `debug.profiler` | `EnableProfiler`, `EnableTracy` | AfterModMain | profiler/tracy | before `jit.runtime` hide |
| `compat.frostxx` | (internal / encrypt path) | AfterModMain | decrypt + kleiloadlua | may fold into `jit.tailcall` |

**Hard depends to encode:**

- `network.entity` → `network.rpc`

**Priority list encodes soft ordering** when there is no hard edge (especially profiler before HideGlobalJIT).

### 7.3 Default AfterModMain priority (stable sort key)

Lower number first (store as `PluginManifest.priority`):

| priority | plugin ids |
|---:|---|
| 10 | `jit.tailcall`, `compat.frostxx` |
| 20 | `debug.profiler` |
| 30 | `gc.policy` |
| 40 | `network.rpc` (Lua face), `network.entity` |
| 50 | `fps.render` |
| 60 | `sim.lagcomp`, `network.sim`, `save.fork` |
| 70 | `jit.runtime` (including HideGlobalJIT) |

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

### 8.2 What happens to `LoadGameModConfig`

- Config **resolution** stays L0.
- Side effects move into `render.vbpool` / `render.angle` EarlyNative `load()`.
- Function becomes “resolve config + `load_phase(EarlyNative)`” or is inlined into `Inject` as two clear steps.

---

## 9. Build layout (Phase A)

Still one SHARED target `Injector`, sources grouped over time:

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
```

Lua:

```text
Mod/
  plugins/
    init.lua              # explicit registry
    jit_runtime.lua
    ...
  scripts/                # heavy implementations until moved
  modmain.lua             # host bootstrap only
```

---

## 10. Migration plan (incremental, always shippable)

Each step has **gate tests**. “Game boots” is never the only gate.

| Step | Deliverable | Automated gate | Manual gate |
|---|---|---|---|
| M0 | `PluginHost` + types + empty registry; trunks still linear | L-A + L-B green | none |
| **M-G** | **Dedicated L-G harness** (may land right after M0 or parallel early Mn) | **L-G green**: server load + stable sim pause | none (this *replaces* manual core boot) |
| M1 | `save.fork`, `sim.lagcomp`, `network.sim` as plugins | L-A/B + L-C + L-E rows for 3 ids + `fork_save_lua` + L-G core profile | none for core path |
| M2 | `network.rpc` + `network.entity` + depends | L-E entity×rpc matrix; L-A hard dep | optional multiplayer beyond L-G |
| M3 | `render.angle` + `render.vbpool` EarlyNative | L-A phase_barrier; `BufferNamePool`; L-E vbpool/angle | client-only render still optional manual |
| M4 | `jit.*`, `gc.policy`, `debug.profiler`, `fps.render` | L-A `profiler_before_hide`; L-B string predicates; L-E rows | — |
| M5 | Slim `Inject` / `modmain` trunks | **L-F** + full unit suite + **L-G** | — |
| M6 | Contributor docs + “add dummy plugin” | doc present; optional dummy plugin unit | — |
| M7 | Dynamic libs (later) | out of scope | — |

---

## 11. Error handling & logging

- Host logs: `plugin=id phase=... event=resolve|load|fail|skip reason=...`
- Fail-fast messages include: plugin id, dependency id / conflict peer, phase.
- Match existing spdlog levels.
- Lua: `print("[luajit][plugin] ...")` or `ctx.log`.
- **Test oracle:** assertions use `PluginEvent` / `PluginStatus` / `load_count`, **not** log-string scraping as the primary proof.

---

## 12. Testable scheme (normative)

Without automated tests, success criteria are not enforceable. This section defines **what is tested, how, where, and what pass means**.

### 12.1 Principles

1. **Observable contracts** — load order, enable/disable, error outcomes, option rules, phase barriers.
2. **Host is pure-logic first** — graph resolve/load runs **without** Frida, game process, or OpenGL.
3. **Match repo test style** — C++ `assert` + `printf("PASS")` (`tests/test_buffer_name_pool.cpp`); Lua specs + Python runner (`tests/fork_save/`); wire via `tests/CMakeLists.txt` `add_test`.
4. **Every migration step has a gate** — §10.
5. **Fail-fast is behavior** — missing hard dep / conflict / cycle ⇒ Failed status + **no** `load()` on the failing set.

### 12.2 Test layers

| Layer | CTest / name | Artifact | Game? | Required from |
|---|---|---|---|---|
| L-A Host graph | `plugin_host_graph` | `tests/plugin/test_plugin_host_graph.cpp` | No | **M0** |
| L-B Option rules | `plugin_option_rules` | same target or `tests/plugin/test_plugin_option_rules.cpp` | No | **M0** |
| L-C Lua host | `plugin_host_lua` | `tests/plugin/plugin_host_lua_spec.lua` + runner | No | **M1** |
| L-D Feature regression | existing names | `fork_save_lua`, `BufferNamePool`, variant tests | No | each related Mn |
| L-E Enable matrix | `plugin_enable_matrix` | C++/Lua fake plugins + config maps | No | **M1+** per id |
| L-F Trunk surface | `plugin_trunk_surface` | `tests/plugin/check_trunk_surface.py` (or cmake -P) | No | **M5** |
| L-G Dedicated server integration | `plugin_dedicated_sim_pause` | `tests/plugin_server/` harness + cluster fixture | Yes (nullrenderer) | **Specified now; implement as M-G (next step after Host units)** |

### 12.3 Host test doubles (required for L-A/L-B/L-E)

```cpp
struct FakePlugin final : IPlugin {
    PluginManifest man{};
    bool allow = true;
    int load_count = 0;
    int unload_count = 0;
    bool throw_on_load = false;
    // manifest() returns man;
    // can_load() returns allow;
    // load() increments load_count or throws;
    // unload() increments unload_count;
};
```

`ConfigView`: in-memory map only (no save-file parsing inside Host unit tests).

Prefer compiling `PluginHost` without Frida. If staged: `PLUGIN_HOST_TESTBUILD` and a small `plugin_host` object set linked into the test executable.

### 12.4 L-A cases (M0 gate — all required)

| Case | Setup | Expected |
|---|---|---|
| `empty_registry` | no plugins | `load_phase` any phase succeeds; loaded_order empty |
| `topo_linear` | A depends B; both enabled | order: B, A; both Loaded |
| `topo_diamond` | A→B, A→C, B→D, C→D | D before B and C; B and C before A |
| `soft_dep_missing` | A soft_depends Z; Z absent | A Loaded; no Failed |
| `soft_dep_present` | A soft_depends Z; both enabled | Z before A |
| `hard_dep_missing` | A depends Z; Z Disabled | A Failed/`MissingHardDep`; `A.load_count==0` |
| `conflict_both_enabled` | A conflicts B; both on | both Failed/`Conflict`; both `load_count==0` |
| `conflict_one_enabled` | only A on | A Loaded |
| `cycle_three` | A→B→C→A | all Failed/`Cycle`; all `load_count==0` |
| `phase_barrier` | X EarlyNative; Y AfterModMain depends X | Y not in EarlyNative loaded_order; after both phases: X then Y |
| `phase_skip_disabled` | options off | `load_count==0`, status Disabled |
| `load_throw_fails_dependents` | B OK; A depends B and throws; C depends A | B Loaded; A Failed/`LoadThrew`; C Failed; C.load_count==0 |
| `priority_tiebreak` | A,B no edges; priority(A)<priority(B) | A before B |
| `profiler_before_hide` | fake `debug.profiler` prio 20 + `jit.runtime` prio 70 | profiler before jit.runtime in AfterModMain order |
| `sticky_no_unload` | support_reload=false after load | `unload` not invoked by host default API |
| `reload_unload` | support_reload=true; host unload API | `unload_count==1` |

**Pass:** process exit 0; each case prints `PASS: <name>`.

### 12.5 L-B cases (M0 gate)

| Case | Rule | Config | Expected |
|---|---|---|---|
| `all_of_true` | all_of {A,B} | A=true,B=true | enabled |
| `all_of_partial` | all_of {A,B} | A=true,B=false | disabled |
| `any_of_one` | any_of {A,B} | A=false,B=true | enabled |
| `any_of_none` | any_of {A,B} | both false | disabled |
| `shorthand_option` | option=A | A=true | enabled |
| `string_ne_off` | EnableProfiler ≠ `"off"` | `"fzvp"` | enabled |
| `string_off` | same | `"off"` | disabled |
| `string_eq_on` | EnableTracy == `"on"` | `"on"` / `"off"` | enabled / disabled |
| `when_false` | options on, can_load false | — | Disabled (not Failed) |
| `when_true` | options on, can_load true | — | enabled path |

### 12.6 L-C cases (M1+)

Lua registry path (`Mod/plugins` host):

- depends order for two plugins
- option off ⇒ load not called
- hard dep missing ⇒ error/Failed, no half load
- dual-face: native marked loaded ⇒ Lua face still runs AfterModMain

Runner: same pattern as `tests/fork_save/run.py` (luajit / lua / lua5.1).

### 12.7 L-E enable matrix (per migrated plugin)

For each id after migration, minimum rows:

| Plugin | Matrix |
|---|---|
| `save.fork` | EnableForkSave true/false |
| `sim.lagcomp` | EnableLagCompensation true/false |
| `network.sim` | EnableNetSim true/false |
| `network.rpc` | NetworkOpt true/false |
| `network.entity` | NetworkOptEntity × NetworkOpt (entity cannot load when rpc off) |
| `render.vbpool` | EnableVBPool true/false |
| `render.angle` | AngleBackend ∈ {auto,vulkan,d3d11,d3d9} as **parameter** (plugin still “enabled” on Win client EarlyNative; assert backend value reaches plugin context) |
| `gc.policy` | DisableForceFullGC / EnableFrameGC combos |
| `debug.profiler` | EnableProfiler off/fzvp; EnableTracy on/off |
| `jit.runtime` | EnabledJIT true/false; HideGlobalJIT true/false (order vs profiler = L-A) |
| `jit.tailcall` | SlowTailCall / AnyMod / ForceDisable / AutoDetect combinations that change enablement |
| `fps.render` | TargetRenderFPS off-ish default vs elevated value (predicate: “calls set_target_fps when resolved value present / Win gate”) |

Assertions per row:

- on + when ⇒ `Loaded` after phase, `load_count==1`
- off ⇒ `Disabled`, `load_count==0`
- hard dep down ⇒ `Failed`, `load_count==0`

### 12.8 L-D existing regressions

| Test | Command | Guards |
|---|---|---|
| `fork_save_lua` | `ctest -R fork_save_lua --output-on-failure` | `save.fork` Lua |
| `BufferNamePool` | `ctest -R BufferNamePool --output-on-failure` | vbpool pool |
| `luajit_variant_registry` / `luajit_gengc_output_name` | ctest | L0 VM names |

Do not weaken assertions to greenlight moves.

### 12.9 L-F trunk surface (M5)

Script fails if:

- `DontStarveInjector.cpp` `Inject()` calls feature entrypoints by name: `GameNetWorkHookRpc4`, `InitGameOpenGl`, `DS_LUAJIT_set_vbpool_enabled` (must go through Host phase).
- `LoadGameModConfig` directly enables VBPool/OpenGL side effects (must be resolve + `load_phase(EarlyNative)` or equivalent).
- `modmain.lua` `_M:Main` directly `modimport`s `scripts/fork_save`, `scripts/lag_compensation`, `scripts/netsim`.

Allowed: L0 (`ReplaceLuaModule`, signature, crash guard, `RegisterBuiltinPlugins`, `PluginHost::*`).

### 12.10 L-G Automated dedicated server (normative; implement next)

**Status:** Contract is **normative**. Implementation is the **next engineering step** after (or overlapping early with) Host unit tests — tracked as migration **M-G**. Until M-G lands, Mn feature PRs may still attach interim evidence, but **architecture DoD requires L-G green**.

L-G is **not** a permanent manual checklist. Manual client/render checks may remain optional; the **required** end-to-end proof is:

> Start dedicated server with Injector → this mod / plugins load successfully → world sim becomes ready → enter **stable sim-paused** state → hold without crash → harness reports PASS.

#### 12.10.1 Why dedicated-first

- Matches server-critical plugins (`save.fork`, lagcomp mastersim path, inject server path).
- Reuses existing assets: `config/server/DoNotStarveTogether/`, `tests/stress_test_mod/run_stress_test.py` (`DSTServer`), `docker/start-docker-server.sh` (`LD_PRELOAD=libInjector.so`), `Mod/install_linux.sh` inject wrapper.
- Headless `dontstarve_dedicated_server_nullrenderer_x64` is CI-feasible; full client GL is not required for module-load proof.

#### 12.10.2 Harness layout (target)

```text
tests/plugin_server/
  run_dedicated_sim_pause.py   # orchestrator (ctest entry)
  probe_mod/                   # tiny server mod OR commands injected via server console
    modinfo.lua
    modmain.lua                # reports plugin/host status; requests sim pause
  cluster/                     # or generate from config/server template
    # offline_server=true, minimal Master shard
  README.md                    # GAME_DIR, token, platform notes
```

CTest (when game dir available):

```cmake
add_test(NAME plugin_dedicated_sim_pause
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        DST_GAME_DIR=${GAME_DIR}   # or env-only; skip if unset
        ${PYTHON_EXECUTABLE_NAME}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugin_server/run_dedicated_sim_pause.py)
# Mark SKIP if DST_GAME_DIR missing; FAIL only when game present and contract breaks.
```

#### 12.10.3 Boot contract (ordered)

| Step | Action | Pass signal (oracle) |
|---|---|---|
| 1. Prep | Copy/install Injector + Mod into game/mod paths; cluster with **offline_server** (or valid token); enable this mod in `modoverrides` | files present; exit non-zero if install incomplete |
| 2. Launch | Start `dontstarve_dedicated_server_nullrenderer_x64` with inject (`LD_PRELOAD` / Windows inject layout) + `-cluster <L-G cluster>` + Master shard | process starts; pid alive |
| 3. Inject alive | Wait for injector log / console evidence | e.g. log contains inject success **or** in-game `GameInjector ~= nil` reported by probe |
| 4. Mod loaded | Probe or log proves DontStarveLuaJit2 modmain ran | marker file or console line `LG_MOD_LOADED` |
| 5. Plugins OK | For **core profile** (defaults / all experimental off as configured): no required plugin in `Failed`; Host AfterModMain completed | marker `LG_PLUGINS_OK` + optional structured dump |
| 6. World ready | Shard reaches running world (mastersim exists / “Done loading world” class signal) | marker `LG_WORLD_READY` within timeout `T_world` |
| 7. Sim pause | Explicitly enter paused sim (pin exact API in harness README on first green run, e.g. `TheNet:SetServerPaused(true)` or project-standard equivalent) | marker `LG_SIM_PAUSED` when paused query is true |
| 8. Stability hold | Remain paused **≥ `T_hold`** (default **30s**) with process alive, no fatal log pattern, no unexpected exit | marker `LG_STABLE` after hold |
| 9. Shutdown | Graceful stop (console quit / SIGTERM policy documented); expect harness-accepted exit | process reaped; no hang beyond `T_shutdown` |

**Defaults (tunable in harness, fixed in CI):**

| Param | Default | Meaning |
|---|---|---|
| `T_world` | 300s | max wait world ready |
| `T_hold` | 30s | stable paused duration |
| `T_shutdown` | 60s | max wait process exit |
| `T_inject` | 60s | max wait inject/mod markers |

#### 12.10.4 Profiles

| Profile | Config | Required for |
|---|---|---|
| `core` | Injector on; mod on; experimental server plugins at safe defaults (or explicitly off matrix row) | M-G gate; S5; S13 |
| `save.fork` | EnableForkSave on (dedicated) | after M1 migrate; optional extended L-G job |
| `matrix-N` | future: one ctest row per heavy server plugin | not all required on day one of M-G |

M-G **minimum ship:** profile `core` green. Extended profiles added when those plugins migrate (still automated, same harness).

#### 12.10.5 Fail conditions (any ⇒ FAIL)

- Process crashes / abort before `LG_STABLE`
- Injector missing (`GameInjector` nil) when inject was required
- Mod did not load / modmain error
- Required plugin status `Failed` on core profile
- World not ready before `T_world`
- Sim never reports paused
- Process dies during `T_hold`
- Fatal patterns in server/injector logs (list maintained in harness; tune without swallowing real faults)
- Hang past `T_shutdown` on teardown

#### 12.10.6 Skip vs fail

| Environment | Result |
|---|---|
| No `DST_GAME_DIR` / no server binary | **SKIP** (ctest skip) — not silent pass |
| Game present, contract broken | **FAIL** |
| Game present, all markers + hold | **PASS** |

CI with game artifacts: run L-G. Dev machines without game: unit layers still gate merges; L-G runs where binary exists.

#### 12.10.7 Probe implementation notes

- Prefer **server console / remote command** or a **tiny companion mod** that only writes markers under `unsafedata/` or cluster dir — keep production mod free of test-only branches when possible.
- Marker files beat brittle log scraping as primary oracle; logs are secondary diagnostics.
- Exact pause API must be verified against current DST. Harness README pins the chosen call after first green run; if API name differs, update harness only — contract step 7 stays “server sim paused and holds.”
- Reuse `DSTServer` patterns from `tests/stress_test_mod/run_stress_test.py` (stdin commands, process life) rather than inventing a second process manager.

#### 12.10.8 Interim (before M-G merges)

Feature migration PRs may still record manual dedicated boot notes. That does **not** satisfy §12.12 item 7 once M-G exists; after M-G, L-G ctest is mandatory for DoD.

### 12.11 Build wiring

```cmake
# tests/CMakeLists.txt (same style as BufferNamePool / fork_save_lua)
add_executable(test_plugin_host_graph
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_host_graph.cpp
    # + PluginHost sources or plugin_host object lib
)
target_include_directories(test_plugin_host_graph PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
add_test(NAME plugin_host_graph COMMAND test_plugin_host_graph)

add_executable(test_plugin_option_rules
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_option_rules.cpp)
# ... same includes / host option evaluator sources
add_test(NAME plugin_option_rules COMMAND test_plugin_option_rules)

add_test(NAME plugin_host_lua
    COMMAND ${CMAKE_COMMAND} -E env REPO_ROOT=${CMAKE_SOURCE_DIR}
        ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/run_lua_host.py)
set_tests_properties(plugin_host_lua PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_test(NAME plugin_trunk_surface
    COMMAND ${PYTHON_EXECUTABLE_NAME}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugin/check_trunk_surface.py
        ${CMAKE_SOURCE_DIR})

# L-G: implement under tests/plugin_server/ (M-G). Skip if DST_GAME_DIR unset.
add_test(NAME plugin_dedicated_sim_pause
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        DST_GAME_DIR=$ENV{DST_GAME_DIR}
        ${PYTHON_EXECUTABLE_NAME}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugin_server/run_dedicated_sim_pause.py)
set_tests_properties(plugin_dedicated_sim_pause PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    TIMEOUT 600)
```

### 12.12 Definition of Done (global)

Architecture work is **done** only when:

1. L-A + L-B green in ctest.
2. L-C green once Lua plugins exist.
3. L-D green after each related move.
4. L-E rows exist for **every** migrated §7.2 plugin.
5. L-F green at M5.
6. Every §13 criterion maps to at least one automated assertion (S6 = interface review checklist on Host headers, still explicit).
7. **L-G `plugin_dedicated_sim_pause` green** on an environment with the game binary (core profile: module load success + stable sim pause). Skip-without-game is allowed in bare CI; **DoD requires at least one recorded green L-G run** (local or game-enabled CI).

---

## 13. Success criteria (test-mapped)

| # | Criterion | Proof | Pass condition |
|---|---|---|---|
| S1 | New feature does not edit feature lists in `Inject()` / `_M:Main` trunks | L-F + register-only path | L-F exit 0 |
| S2 | Disabling modinfo option prevents plugin load | L-E off-rows | all off-rows `load_count==0` |
| S3 | Missing hard dep / cycle / conflict → failure, no half-enable | L-A `hard_dep_missing`, `cycle_three`, `conflict_both_enabled`, `load_throw_fails_dependents` | those PASS |
| S4 | `modinfo` sole user config; multi-option → one plugin | L-B multi-key rules; no second channel | L-B PASS |
| S5 | Core-only still injects / VM runs | L-A `empty_registry` + **L-G core profile** | unit PASS + L-G PASS |
| S6 | Phase B possible without manifest rewrite | Host headers review: no static-only types in `IPlugin`/`PluginManifest` | checklist signed in M0 PR |
| S7 | Phase barriers respected | L-A `phase_barrier` | PASS |
| S8 | Profiler before HideGlobalJIT | L-A `profiler_before_hide` + §7.3 priorities | PASS |
| S9 | `network.entity` requires `network.rpc` | L-E cross row + hard dep | PASS |
| S10 | Feature regressions preserved | L-D ctest | green |
| S11 | Fail-fast is structured | L-A asserts `PluginStatus`/`PluginFailReason` | not log-scrape-only |
| S12 | Sticky unload default | L-A `sticky_no_unload` / `reload_unload` | PASS |
| **S13** | **Dedicated: modules load successfully and sim stays stable paused** | **L-G** steps 3–8 (`LG_MOD_LOADED` … `LG_STABLE`) | harness exit 0; hold ≥ T_hold |

**S1–S13 are the acceptance bar.** Goals in §3 without a row here are non-blocking preferences.

---

## 14. Open follow-ups

### Next step (scheduled, not vague)

- **M-G implement L-G harness** (`tests/plugin_server/run_dedicated_sim_pause.py` + cluster fixture + ctest). Depends on: game binary path, inject install path, pause API pin. Does **not** depend on finishing all plugin migrations.

### Later

- Dynamic plugin DLLs/SOs (Phase B).
- Hot reload UX / console commands for `support_reload` plugins.
- Splitting `GameLuaModule.cpp` god-export after A2 aliases.
- Whether `compat.frostxx` folds into `jit.tailcall`.
- CMake per-plugin object libraries after M5.
- L-G extended profiles (`save.fork`, multi-shard Caves) and optional client-bot smoke.

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
| Test style refs | `tests/test_buffer_name_pool.cpp`, `tests/fork_save/`, `tests/CMakeLists.txt` |
| Dedicated process harness ref | `tests/stress_test_mod/run_stress_test.py` (`DSTServer`) |
| Server cluster fixture ref | `config/server/DoNotStarveTogether/` |
| Linux inject preload ref | `docker/start-docker-server.sh`, `Mod/install_linux.sh` |

---

## 16. Spec self-review

| Check | Result |
|---|---|
| Placeholders | Phase B deferred; L-G **contract complete**, implementation = M-G next step |
| Consistency | D1–D8 match body; fail-fast = no silent plugin degradation |
| Scope | Architecture + test gates; multi-PR via §10 including M-G |
| Ambiguity | String option “on” via predicates; pause API pinned in harness README on first green |
| Locked decisions | Path A, fail-fast, L0 vm/force-mod, sticky unload, tests-required, **automated dedicated L-G** |
| Testability | §12 L-A..L-G + §13 S1–S13 |
| Final game proof manual-only? | **Rejected** (D8, S13, §12.10) |
