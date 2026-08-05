# Config Ownership Boundaries (L0 / core.vm / business)

**Date:** 2026-08-05  
**Status:** Implemented  
**Depends on:** `docs/superpowers/specs/2026-08-04-config-source-schema-unification-design.md` (cascade + `allowed_sources` + `config/`)

## 1. Problem

After source unification, **key ownership** is still wrong:

1. **VM policy keys** (`DisableJITWhenServer`, `LuaVmType`, `EnabledGenGC`) live in L0 `RegisterCoreOptionSchema` and are read by Injector (`current()->disable_jit_when_server()` early-exit), even though they are **game VM** concerns and `core.vm` is **optional**.
2. **Business keys** are registered by plugins **and** re-seeded by L0 `RegisterBuiltinBusinessOptionSchema` — dual authority, magic strings in two places.
3. **Magic string scatter** — same key literals in schema, sources, `ResolvedConfig` accessors, Compat, plugin `options.keys`.

Result: the base layer looks coupled to feature/VM config; missing `core.vm` still forces L0 to know VM policy.

## 2. Three domains

| Domain | Owns | Does **not** own |
|--------|------|------------------|
| **L0 base** | Inject + hook host, cascade **engine**, identity/paths, process `InjectorConfig`, optional force-mod policy | Game VM selection, feature gates |
| **core.vm** | Signature + ReplaceLuaModule, VM type / genGC / “disable JIT on dedicated” | Network/render/save features |
| **Business plugins** | Their own option schema + Host gates + native/Lua faces | Cascade engine, identity, other plugins’ keys |

`InjectorConfig` (debugger, zip, etc.) stays **outside** the game-option cascade forever.

## 3. Key ownership table (normative)

### 3.1 L0 base (game-option cascade)

| Key | Notes |
|-----|--------|
| `modmain_path` | Identity / paths |
| `modname`, `modid` | Identity |
| `save_file` | Client write-back path (optional in view) |
| `AlwaysEnableMod` | **Base policy** (force-enable mod path); not VM selection |

L0 registers **only** these (plus cascade mechanism).  
L0 **must not** treat VM keys as framework kill-switches.

### 3.2 core.vm

| Key | Consumer |
|-----|----------|
| `LuaVmType` | VM module selection |
| `EnabledGenGC` | `jit_gen` variant (`get_lua_vm_type` semantics) |
| `DisableJITWhenServer` | **Inside core.vm / bootstrap**: skip Replace / no-op VM path on dedicated — **not** “abort entire Inject()” as L0 default |

**Registrar:** `plugin_core_vm` (`ds_plugin_module_init` / dedicated schema export).  
**Readers:** core.vm only (and tests). Env/luajit file fields that map to these keys are interpreted for the **VM domain**, not as L0 business inventory.

### 3.3 Business plugins (examples)

| Key | Plugin |
|-----|--------|
| `NetworkOpt` | network.rpc |
| `EnableNetSim` | network.sim |
| `EnableVBPool` | render.vbpool |
| `AngleBackend` | render.angle |
| `EnableForkSave` | save.fork |
| `EnableLagCompensation` | sim.lagcomp |
| EnableProfiler / EnableTracy / … | debug.profiler |

**Registrar:** owning plugin only.  
**L0:** no permanent `RegisterBuiltinBusinessOptionSchema` inventory (see §5).

## 4. Inject / bootstrap target order

```text
gum_init / InjectorCtx
→ L0 schema seed (identity + AlwaysEnableMod only)
→ cascade resolve (L0 keys + whatever schema already known)
→ PluginHost + DynamicPluginLoader
    → plugins register their schemas (core.vm + business)
→ optional: re-fill missing schema defaults into view (no full disk re-read)
→ core.vm bootstrap / load
    → reads VM keys from ResolvedConfig.view (or registers then applies VM partials)
    → if DisableJITWhenServer && server: skip ReplaceLuaModule (soft)
→ PluginHost::resolve(view) + EarlyNative for other plugins
```

**Change from today:** remove L0 early-return of the form “if DisableJITWhenServer then return from Inject”. Base continues; VM path no-ops.

CI harness `DS_LUAJIT_FORCE_DISABLE_VM` (or equivalent) remains an **env process switch**, not a game-option key ownership claim.

## 5. Bootstrap chicken/egg (business + VM keys before DLL)

Save/overrides parse still needs schema for **known** keys before/while modules load.

**Target (preferred):**

1. `DynamicPluginLoader` loads modules and runs `ds_plugin_module_init` (schema register) **before** final Host resolve.
2. For **first** cascade used only for L0 identity: schema = L0-only.
3. After all `module_init`, either:
   - **re-apply** Save/Env partials once with full schema (second apply, not full redesign), or
   - single cascade **after** all modules registered (move “heavy” resolve later; L0 identity pre-pass stays light).

**Interim (if needed for one slice):** keep a generated or shared key header for parse-only defaults, **owned by the same module that registers** — not a hand-maintained L0 business list. Delete `RegisterBuiltinBusinessOptionSchema` body once (3) works.

## 6. Magic strings

| Rule | |
|------|--|
| Each domain defines `OptionKeys` (constexpr string_view) **once** | e.g. `config/BaseOptionKeys.hpp`, `plugins/plugin_core_vm/VmOptionKeys.hpp`, `plugins/plugin_network_rpc/RpcOptionKeys.hpp` |
| Schema register + `man.options.keys` + sources + accessors use those constants only | No raw `"EnabledGenGC"` outside the owning domain’s header |
| Cross-domain read of another domain’s key | Prefer Host/service API or documented public key header; YAGNI until needed |

## 7. ResolvedConfig / accessors

| Accessor today | After |
|----------------|--------|
| `disable_jit_when_server()` on L0 hot path | Move to core.vm helper or keep on `ResolvedConfig` but **only called from VM path** |
| `get_lua_vm_type()` / `enabled_gen_gc()` | core.vm |
| `always_enable_mod()`, identity accessors | L0 |
| `angle_backend()` | render.angle (or generic `string_opt` only in L0) |

L0 may keep a thin `current()` pointer; **semantic accessors for VM keys should not be required by Injector.cpp**.

## 8. Non-goals

- Changing modinfo.lua user-visible option names.
- Merging `InjectorConfig` into game cascade.
- Making core.vm mandatory.
- Remote schema / version negotiation.

## 9. Success criteria

1. `RegisterCoreOptionSchema` (or renamed base seed) contains **no** `LuaVmType` / `EnabledGenGC` / `DisableJITWhenServer`.
2. Those three keys are registered by **plugin_core_vm** (or fail-soft if module absent — keys missing → defaults / no VM replace).
3. Injector main path does **not** early-out solely on `DisableJITWhenServer`; dedicated + flag ⇒ core.vm skips replace.
4. `RegisterBuiltinBusinessOptionSchema` removed or reduced to zero business keys.
5. No new magic string literals for option keys outside domain `OptionKeys` headers (grep gate in review).

## 10. Migration slices (see plan)

| Slice | Focus |
|-------|--------|
| OB-S0 | Spec + OptionKeys headers (constants only, wire gradually) |
| OB-S1 | Inject: remove L0 DisableJITWhenServer kill-switch; core.vm handles soft skip |
| OB-S2 | Move VM keys registration to plugin_core_vm; thin L0 base schema |
| OB-S3 | Env/Luajit sources: VM fields only applied when VM schema present / via VM helper |
| OB-S4 | Remove business bootstrap seed; cascade after module_init schema register |
| OB-S5 | Accessors cleanup + grep gate + docs |

Each slice: unit tests + L-G present when touching inject/VM path.
