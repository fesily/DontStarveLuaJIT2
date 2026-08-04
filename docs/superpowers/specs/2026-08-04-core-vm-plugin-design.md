# Core VM Forced Plugin Design (`plugin_core_vm`)

**Date:** 2026-08-04  
**Status:** Approved approach (user: 整块 core.vm 强制插件 + **Signature 并进 core.vm**)  
**Scope:** Move Lua VM selection, export remap, InjectFramework, GameInjector min open, **and** signature scan/update into a single **mandatory** dynamic module `plugin_core_vm` (id `core.vm`). L0 retains gum lifecycle, inject orchestration, config cascade, and PluginHost.

Related:

- Plugin architecture: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` (D3 previously said VM stays L0 — **this design supersedes D3 for VM/signature ownership**)
- Dynamic impl migration: `docs/superpowers/specs/2026-08-04-dynamic-plugin-impl-migration-design.md`
- ConfigView SSOT: `docs/superpowers/specs/2026-08-04-gamejitmodconfig-pluginization-design.md` (core keys `LuaVmType` / `EnabledGenGC` / `DisableJITWhenServer` still L0-resolved **before** bootstrap)
- Current inject path: `src/DontStarveInjector/DontStarveInjector.cpp` → `SignatureUpdater` → `ReplaceLuaModule`
- Current size: `GameLua.cpp` ~1.8k, `GameLuaModule.cpp` ~2k, `DontStarveSignature.cpp` ~300, `GameLua.def` export table

---

## 1. Problem

Business features are already dynamic plugins. **Lua VM + signature** remain the largest hard-wired L0 block:

| Concern | Today | Pain |
|---|---|---|
| VM selection / export remap | `GameLua.cpp` `ReplaceLuaModule` | Coupled to Injector link of whole GameLua stack |
| Signature scan / JSON update | `DontStarveSignature.cpp` + `SignatureUpdater` | Same TU tree, only used for VM replace |
| GameInjector exports | `GameLuaModule.cpp` god-file | Mixes VM helpers + business trampolines |
| Inject order | Signature → Replace **before** DynamicPluginLoader | Normal EarlyNative plugins load too late for VM |

User direction: **whole core.vm as a forced plugin**, and **include Signature in the same module** so L0 is thinner orchestration only.

---

## 2. Decisions

| # | Choice |
|---|---|
| V1 | **One mandatory module** `plugin_core_vm` / id `core.vm` owns VM **and** Signature |
| V2 | **Bootstrap phase** loads `plugin_core_vm` **before** any game Lua remap; missing/failed init → **fail-fast abort inject** |
| V3 | L0 keeps: gum_init, InjectorCtx, crash guard, config cascade, PluginHost, DynamicPluginLoader shell, AlwaysEnableMod / DisableJITWhenServer early exits |
| V4 | `GameLuaModule.cpp` is **not** moved wholesale; split: min `luaopen_GameInjector` + VM-related binds in core.vm; business APIs stay runtime-resolve trampolines (as today) or later feature plugins |
| V5 | `GameLua.def` moves with core.vm (lua_* re-exports for debugger / game linkage as today) |
| V6 | Config keys `LuaVmType`, `EnabledGenGC` remain **core schema** (resolved before bootstrap); core.vm **consumes** them, does not own cascade |
| V7 | Incremental slices; each slice build + L-G (and client smoke when client path changes) |
| V8 | YAGNI: no optional multi-VM market; no hot-swap VM mid-session; no second Gum |

**Supersedes:** Architecture design D3 (“VM selection is L0 core, not plugins”) for **ownership of implementation**. L0 still **orchestrates** bootstrap; implementation lives in `plugin_core_vm`.

---

## 3. Target architecture

```
Inject(isClient)
  gum already inited (HookStartupEntry)
  LoadGameModConfig / core ConfigView keys
  if DisableJITWhenServer && !client → return
  ── Bootstrap ──────────────────────────────────────
  LoadLibrary(plugin_core_vm)  // fail-fast if missing
  ds_plugin_module_init(host)  // register core.vm + schema if any
  core_vm_prepare(...)         // optional explicit C entry
  SignatureUpdater::create_or_update  // code now in plugin DLL
  ReplaceLuaModule(...)               // code now in plugin DLL
  ── Normal dynamic plugins ─────────────────────────
  DynamicPluginLoader::load_all (network, render, save, …)
  PluginHost::resolve + EarlyNative
  DisableScriptZip / rest
```

### 3.1 What moves into `plugin_core_vm`

| Artifact | Notes |
|---|---|
| `GameLua.cpp` / `GameLua.hpp` / `GameLuaType.hpp` | Contexts, ReplaceLuaModule, RequestVmType, GetGameLuaContext |
| `GameLuaInjectFramework.lua` + generated `.c` | Embedded framework |
| `GameLua.def` | lua_* export forwarding table (MSVC) |
| `LuajitVariantNames.hpp` | JIT variant names |
| `lua_fake.cpp` | If only used by VM path — verify at plan time; move if exclusive |
| `DontStarveSignature.cpp` / `.hpp` | SignatureUpdater, export list, disasm update path |
| Related signature JSON I/O used only by SignatureUpdater | e.g. pieces of `SignatureJson.cpp` if solely signature — audit at plan time |
| Min GameInjector open | `luaopen_GameInjector` shell that registers **VM-owned** functions + re-exports trampoline table for already-moved feature APIs |

### 3.2 What stays L0

| Artifact | Why |
|---|---|
| `DontStarveInjector.cpp` | Orchestration, bootstrap call order, fail-fast |
| `config.hpp` / gum_bridge re-exports / FridaGum.def | Single Gum instance |
| `core/*` PluginHost, DynamicPluginLoader, ConfigSchema | Plugin system |
| `gameModConfig` cascade | Config before bootstrap |
| Crash guard, steam hooks, Progress | Process shell |
| Feature plugins | Already migrated |

### 3.3 GameLuaModule split policy

`GameLuaModule.cpp` today mixes:

- Config load helpers (stay L0 or shared)
- `luaopen_GameInjector` + many `module.set_function`
- Business trampolines (fork, net_sim, vbpool, entity, …) — **already** partly GetProcAddress

**Target:**

1. **core.vm** owns `luaopen_GameInjector` and binds:
   - `DS_LUAJIT_set_vm_type` / `get_vm_type_name`
   - workshop / mod version / update / other VM-adjacent APIs that live in GameLua.cpp
2. **Trampolines** for feature plugins remain in core.vm’s GameInjector open **or** a tiny L0 stub file — prefer **one open site in core.vm** so game only loads one GameInjector module.
3. Config cascade functions currently in GameLuaModule stay in L0 (or a `gameModConfig` TU), **not** forced into core.vm.

Exact function ownership table is an implementation-plan deliverable (grep-driven).

### 3.4 Bootstrap ABI

Prefer **minimal new C ABI** on the module (same style as other plugins):

```cpp
// Required (existing):
bool ds_plugin_module_init(PluginHost* host);
// Optional:
const char* ds_plugin_module_abi_version();

// Required for bootstrap (new, fail-fast if missing):
// Called by L0 after successful init, before/with signature+replace.
// May be thin wrappers exporting existing C++ entry points.
extern "C" bool ds_core_vm_run_signature_and_replace(
    bool is_client,
    uintptr_t lua_module_base,   // or main module path + scan inside
    const char* main_path);
```

Alternatively export existing symbols:

- `SignatureUpdater_create_or_update` (C wrapper)
- `ReplaceLuaModule` (already free function)

**Decision for plan:** one orchestrating C entry `ds_core_vm_bootstrap(const DsCoreVmBootstrapArgs*)` that:

1. Runs signature create_or_update  
2. Calls ReplaceLuaModule  
3. Returns error string / bool  

L0 must not call deep C++ methods across DLL without stable ABI.

### 3.5 Load discovery

`plugin_core_vm` lives next to other plugins (`bin64/plugins/plugin_core_vm.dll`) **or** beside Injector. Bootstrap uses **fixed name** first:

```
<injector_dir>/plugins/plugin_core_vm.dll
<injector_dir>/plugin_core_vm.dll  // optional fallback
```

Not dependent on directory scan order. Normal `DynamicPluginLoader` **skips** already-loaded module (same path) or treats core.vm as sticky registered.

**Idempotency:** `ds_plugin_module_init` may run once; second load_all must not double-register.

### 3.6 Dependencies of core.vm DLL

Likely links:

- Injector (Gum re-exports, InjectorCtx, spdlog, config)
- function_relocation (signature / disasm) — **same rule as other plugins**: no second Gum; `/NODEFAULTLIB:frida-gum.lib`
- lua headers / luajit include for types
- nlohmann_json if SignatureJson needs it
- pe-parse / etc. only if signature path needs them in the plugin (today on function_relocation)

**Must not** pull ANGLE or SLikeNet.

### 3.7 GetGameLuaContext and cross-plugin use

Already exported from Injector for `plugin_sim_lagcomp`. After move, **GetGameLuaContext lives in core.vm** (or thin re-export from Injector forwarding to core.vm).

**Preferred:** export from **plugin_core_vm**; Injector provides optional trampoline only if other TUs still need a stable import at Injector link time. Feature plugins that need context: `GetProcAddress(plugin_core_vm, …)` or import from core.vm.

### 3.8 DisableJITWhenServer

Remains L0 early return **before** bootstrap (no need to load core.vm if server disables JIT entirely). Document: when this gate fires, core.vm is not loaded.

---

## 4. Non-goals

- Moving feature plugins (network/render/save/lagcomp) again  
- Making core.vm optional or hot-reloadable  
- Full rewrite of signature algorithm  
- Merging luajit build system into the plugin  
- Changing modinfo option names  

---

## 5. Migration slices

| Slice | Work | Exit |
|---|---|---|
| **V-S0** | Bootstrap loader API in L0: `LoadCoreVmModule()` find/load/init; skip duplicate in DynamicPluginLoader; unit test “missing DLL → fail” | Inject still uses L0 GameLua; no move yet |
| **V-S1** | Move Signature TUs into `plugin_core_vm`; export C bootstrap half or full; L0 calls into plugin for signature only | Signature not linked into Injector; L-G PASS |
| **V-S2** | Move GameLua + InjectFramework + GameLua.def + ReplaceLuaModule into plugin; L0 calls full `ds_core_vm_bootstrap` | Injector free of GameLua.cpp; L-G + client smoke |
| **V-S3** | Split GameLuaModule: open in core.vm; L0 retains config cascade TUs; fix all GetGameLuaContext callsites | Clean link graph |
| **V-S4** | lua_fake / debugger helper ownership audit; move or keep with evidence | No dead links in Injector |
| **V-S5** | Docs (`plugin-system.md`), trunk surface, deployment note (must ship `plugin_core_vm.dll`) | Done |

Suggested order: S0 → S1 → S2 → S3 → S4 → S5.  
Signature first (S1) proves bootstrap + function_relocation in plugin before the larger GameLua move.

---

## 6. Failure modes

| Case | Behavior |
|---|---|
| `plugin_core_vm` missing | Fail-fast: showError + abort inject |
| `ds_plugin_module_init` false | Fail-fast abort |
| Signature update error | Same as today (showError / return) but error surfaces from plugin |
| DisableJITWhenServer | L0 returns before bootstrap — core.vm not loaded |
| Double init via load_all | No-op / skip already-loaded path |
| Linux/macOS | Same bootstrap; gum re-export still Win-only for other plugins; core.vm itself uses Injector gum |

---

## 7. Testing

| Gate | What |
|---|---|
| Unit | Bootstrap missing module fails; skip-already-loaded |
| Unit | Signature create_or_update still produces expected structure (if existing tests) |
| L-G | Dedicated server profile PASS with core.vm staged |
| Client smoke | Inject + mod load with core.vm |
| Trunk | Injector exports no ReplaceLuaModule / no lua_* def table if fully moved; core.vm exports them |
| Negative | Delete plugin_core_vm.dll → inject aborts with clear log |

---

## 8. Success criteria

1. Injector binary does **not** link `GameLua.cpp` or `DontStarveSignature.cpp`.  
2. Deploy **must** include `plugins/plugin_core_vm.dll` (or so) next to other plugins.  
3. Missing core.vm → **no silent vanilla fallback**.  
4. VM selection still honors `LuaVmType` / `EnabledGenGC` / env `lua_vm_type`.  
5. Feature plugins continue to work via existing runtime resolve / FFI.  
6. L-G + client inject smoke green.

---

## 9. Risks

| Risk | Mitigation |
|---|---|
| GameLua.def / lua_* export consumer expects symbols on Injector | Re-export from core.vm; document; debugger attach path test |
| Circular link Injector ↔ core.vm | core.vm imports Injector only; Injector loads core.vm dynamically (no static link to core.vm) |
| Signature needs large function_relocation surface | Same as network plugins: link function_relocation + NODEFAULTLIB frida |
| GameLuaModule still huge after split | Accept; further export splits are follow-ups |
| Bootstrap vs ConfigView order | Config core keys **before** bootstrap; business plugins after Replace |

---

## 10. Approval

- User selected: **整块 core.vm 强制插件**  
- Then selected: **Signature 也并进 core.vm**

Next: user reviews this file; on approval → `writing-plans` for V-S0…V-S5.
