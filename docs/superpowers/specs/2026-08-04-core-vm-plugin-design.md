# Core VM Plugin Design (`plugin_core_vm`) — Revised

**Date:** 2026-08-04  
**Status:** Revised after design correction (user: **Lua VM 可以不加载**；仅部分功能不可用，**大部分插件仍可用**)  
**Supersedes:** Earlier draft in same file that treated core.vm as **fail-fast mandatory bootstrap**. That draft is **wrong for product semantics**.

Related:

- Plugin architecture: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md`
- Dynamic impl migration: `docs/superpowers/specs/2026-08-04-dynamic-plugin-impl-migration-design.md`
- ConfigView SSOT: `docs/superpowers/specs/2026-08-04-gamejitmodconfig-pluginization-design.md`
- Inject path today: `DontStarveInjector.cpp` (Signature → ReplaceLuaModule → plugins)

---

## 0. Design correction (blind spots)

### What the first draft got wrong

| Blind spot | Wrong assumption | Reality (user + code) |
|---|---|---|
| B1 | No VM ⇒ inject must abort | **VM optional**: skip ReplaceLuaModule / skip core.vm ⇒ game runs; JIT/mod Lua inject features off |
| B2 | Signature+VM are one **forced** bootstrap before any plugin value | **Most feature plugins do not need GameLua** (network, angle, vbpool, save.fork, network.sim). Only lagcomp’s `entity_get_raw_ptr` needs `GetGameLuaContext` |
| B3 | “L0 must own VM forever because inject order” | Order constraint is real **when VM is enabled**, not a reason to fail the whole inject when VM is disabled/missing |
| B4 | Mirror of current early-return `DisableJITWhenServer` as “no plugins” | Today that path returns **before** `DynamicPluginLoader` — that is **L0 coupling debt**, not desired product. Target: **plugins still load** when VM is skipped |
| B5 | Signature must always run | Signature exists to **feed ReplaceLuaModule**. If VM replace is skipped, full signature update can be skipped (or degraded) with the VM path |

### Correct product model

```
Inject always: gum, config, plugin host, feature plugins (as gated)
Optional:     lua51 probe + signature + ReplaceLuaModule (core.vm)
If optional path skipped/fails:
  → log; continue
  → feature plugins that need VM degrade (no GameInjector / no lagcomp raw ptr)
  → native hooks (ANGLE, RPC, netsim, fork, …) still OK
```

---

## 1. Problem

VM + signature is still the largest hard-wired L0 block, but it is **not** the process’s sole purpose. Coupling it as “must load or die” would:

- Break intentional server mode `DisableJITWhenServer` if we ever load plugins after that gate  
- Over-rank core.vm above ANGLE/network/save plugins that users still want without JIT  
- Fight the dual-face model where Lua faces already no-op when `GameInjector` APIs are missing  

Goal: **move VM+signature implementation into `plugin_core_vm`**, load it **when the VM path is enabled**, **without** making it a hard dependency of inject or of most plugins.

---

## 2. Decisions (revised)

| # | Choice |
|---|---|
| V1 | **`plugin_core_vm` (id `core.vm`)** owns VM replace + Signature implementation |
| V2 | **Optional module**: missing/failed core.vm ⇒ **log + skip VM path**, inject continues |
| V3 | **Feature plugins load independently** of core.vm success (fix L0 order vs today’s `DisableJITWhenServer` early return) |
| V4 | When VM path **enabled**, order remains: (optional) load core.vm → signature → ReplaceLuaModule → then or around other plugins; when **disabled**, skip that chain |
| V5 | Signature **travels with VM** (same plugin): only needed for replace; not a separate mandatory service |
| V6 | L0 keeps gum, InjectorCtx, config cascade, PluginHost, DynamicPluginLoader, crash guard |
| V7 | `GameLuaModule` not moved wholesale; GameInjector open lives with core.vm when loaded; business trampolines stay resolve-based |
| V8 | Plugins that need Lua context (**sim.lagcomp**) must **tolerate missing VM** (no symbol / null context → no-op or skip load) |
| V9 | Incremental slices; no fail-fast on missing core.vm |

---

## 3. Target inject flow

```
Inject(isClient)
  init gum ctx / logging / crash check
  LoadGameModConfig / ConfigView core keys
  DynamicPluginLoader::load_all   // feature plugins + optional core.vm if present
  PluginHost::resolve + EarlyNative  // angle, network, fork, … regardless of VM

  if vm_path_enabled(isClient, config):   // e.g. not DisableJITWhenServer
      if core.vm module available:
          run signature + ReplaceLuaModule via core.vm exports
      else:
          spdlog::warn("core.vm missing/unavailable — Lua VM replace skipped")
  else:
      spdlog::info("Lua VM path disabled — plugins may still run")
```

**Note:** Exact interleaving (load_all before vs after signature) is an implementation detail. Invariant:

- **Feature plugins must not be gated on VM success**  
- **VM work only runs when vm_path_enabled && core.vm usable**

### 3.1 `vm_path_enabled`

True when all hold:

- Not `DontStarveInjectorDisable`  
- Not (`!isClient && DisableJITWhenServer`)  
- Optional future: explicit config “enable lua inject” if introduced  

False ⇒ do not require core.vm; do not run SignatureUpdater/ReplaceLuaModule.

### 3.2 What moves into `plugin_core_vm`

Same technical ownership as before, **without mandatory semantics**:

| Artifact | Notes |
|---|---|
| `GameLua.cpp` / `.hpp` / `GameLuaType.hpp` | ReplaceLuaModule, RequestVmType, contexts |
| `GameLuaInjectFramework.*` | Embedded framework |
| `GameLua.def` | lua_* re-exports when VM active (MSVC) |
| `LuajitVariantNames.hpp` | JIT variants |
| `DontStarveSignature.*` + signature-only helpers | Feeds replace |
| Min `luaopen_GameInjector` | VM binds + trampoline table for feature APIs |

### 3.3 What stays L0

Orchestration, gum single-instance, config, host/loader, feature-plugin loading, early process hooks.

### 3.4 Degradation matrix

| Consumer | Without core.vm / without ReplaceLuaModule |
|---|---|
| `plugin_render_angle` | Works (native IAT) |
| `plugin_render_vbpool` | Works (GL hooks; no Lua) |
| `plugin_network_rpc` | Works (Gum hooks) |
| `plugin_network_sim` | Works (Gum hooks; Lua enable optional) |
| `plugin_save_fork` | Works (clone/fork APIs) |
| `plugin_sim_lagcomp` | DLL may load; **entity_get_raw_ptr / GameLua** unusable → Lua face should no-op if API missing |
| Mod Lua `GameInjector.*` | Absent or nil → scripts already often early-return |
| JIT / luajit swap | Off |

### 3.5 ABI (optional module)

```cpp
// Existing module ABI
bool ds_plugin_module_init(PluginHost*);
const char* ds_plugin_module_abi_version(); // optional

// VM path entry (only called if vm_path_enabled && module loaded)
bool ds_core_vm_run_signature_and_replace(/* args: is_client, main_path, ... */);
// false → L0 logs and continues without VM (does not abort inject)
```

L0 **never** static-links core.vm; only `LoadLibrary`/`dlopen` when enabled.

### 3.6 Config

`LuaVmType` / `EnabledGenGC` remain core schema keys (ConfigView SSOT). Used **only if** VM path runs. Missing core.vm does not remove keys from ConfigView.

---

## 4. Non-goals

- Making inject fail when core.vm is absent  
- Blocking feature plugins on VM  
- Full GameLuaModule god-file move in one shot  
- Hot-swap VM mid-session  

---

## 5. Migration slices (revised)

| Slice | Work | Exit |
|---|---|---|
| **V-S0** | Refactor L0 inject: **always** run plugin load after config; apply `DisableJITWhenServer` only to **VM path**, not entire inject | With JIT disabled on server, feature plugins still load (L-G / dedicated) |
| **V-S1** | Add optional `LoadCoreVmModule()`; if missing, skip VM; no fail-fast | Behavior parity when DLL present |
| **V-S2** | Move Signature into plugin; L0 calls export only if module loaded | Injector not linking DontStarveSignature |
| **V-S3** | Move GameLua + framework + def; same optional call | Injector not linking GameLua.cpp |
| **V-S4** | GameInjector open split / trampolines; lagcomp degrades cleanly without context | Client/server smoke |
| **V-S5** | Docs + deploy note: core.vm **recommended for JIT**, not required for all plugins | Done |

---

## 6. Testing

| Gate | Expectation |
|---|---|
| L-G with core.vm present | PASS (JIT path if enabled) |
| L-G / dedicated with VM path disabled | Feature plugins still register; no crash |
| Negative: delete core.vm.dll, VM path enabled | Warn + skip replace; plugins still load |
| lagcomp without VM | No crash; Lua face no-op if symbols missing |
| Trunk | Injector may lack lua_* def exports when moved; document debugger attach via core.vm |

---

## 7. Success criteria

1. core.vm **can** be omitted without killing inject.  
2. Most native plugins work without core.vm.  
3. When core.vm present and VM path enabled, behavior matches today’s ReplaceLuaModule path.  
4. L0 no longer links GameLua/Signature implementation TUs after migration.  
5. `DisableJITWhenServer` does **not** imply “no dynamic plugins.”

---

## 8. Approval trail

- User initially chose “整块 core.vm 强制插件” and “Signature 并进”.  
- User correction: **VM 可以不加载**；强制 fail-fast 是设计盲点.  
- This revision: **optional core.vm + Signature co-located + plugins independent of VM**.

Next: user confirms this revised model → `writing-plans` for V-S0…V-S5 under **optional** semantics.
