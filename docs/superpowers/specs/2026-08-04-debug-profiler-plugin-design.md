# debug.profiler Plugin Design (Tracy + FullGC + FrameGC)

**Date:** 2026-08-04  
**Status:** Approved  
**Scope:** Extract profiler / FullGC / FrameGC business logic from L0 (+ fullgc state currently stranded in `plugin_core_vm`/gameio) into a single dual-face plugin `debug.profiler`.

## 1. Goals

1. One plugin owns **Tracy zone hooks**, **game profiler push/pop replacement**, **FullGC deferral policy**, and **Frame GC** (modinfo-aligned).
2. Remove L0 → `plugin_core_vm` reverse `GetProcAddress` for `ds_core_vm_fullgc_deferred_ptr` / `ds_core_vm_lua_gc_func_ptr`.
3. Keep L0 free of business features; keep `core.vm` optional for JIT without requiring the profiler.
4. Preserve current GC / Tracy semantics (move code, do not redesign algorithms).

## 2. Non-goals

- Second plugin for Tracy alone.
- Changing FullGC / FrameGC algorithm or modinfo option names in v1.
- Mandatory merge of LuaJIT sampling `profiler.cpp` / `DS_LUAJIT_enable_profiler` into v1 (optional same-id export later).
- Cross-compiler plugin ABI; same-build-tree Module ABI v1 still applies.

## 3. Decisions (user-approved)

| Decision | Choice |
|----------|--------|
| Plugin cohesion | **One** dual-face plugin `debug.profiler` for Tracy + FullGC + FrameGC |
| fullgc ownership | **State + policy in profiler**; `core.vm` only installs `lj_gc_fullgc_external` |
| Install timing | Prefer **forwarding stub** in core.vm `init_luajit_io` (resolve profiler export on each call / cached) so load order is soft |

## 4. Identity

| Field | Value |
|-------|--------|
| Plugin id | `debug.profiler` |
| Native DLL | `plugin_debug_profiler.dll` / `.so` |
| Schema keys | `EnableProfiler`, `EnableTracy`, FullGC incremental / Frame GC options (existing modinfo keys; register on plugin schema) |
| Phase | AfterModMain (priority ~20, before `jit.runtime` hide) |
| Sticky | Native sticky; Lua face may follow config hot-reload patterns used by other Lua plugins |
| Dependencies | Soft: `core.vm` optional for FrameGC / luaType / `lua_gc`; no hard fail if missing |

## 5. Architecture

```
L0 Injector
  inject / gum / PluginHost / Config cascade
  no GameProfilerHook business body
  no fullgc state
        |
        | DynamicPluginLoader: plugin_debug_profiler
        v
debug.profiler
  DS_LUAJIT_replace_profiler_api
  DS_LUAJIT_enable_tracy
  DS_LUAJIT_enable_framegc
  DS_LUAJIT_disable_fullgc
  fullgc_deferred state
  hook_profiler_push / pop (Update → TryDoGC)
  export C: lj_gc_fullgc_external  (for core.vm install)
        ^
        | GetProcAddress / forwarding stub
        |
core.vm (optional)
  init_luajit_io sets lua51 export lj_gc_fullgc_external
    -> profiler export if mapped, else pass-through oldfn
  no fullgc_deferred ownership
  no ds_core_vm_fullgc_* exports
```

## 6. Ownership matrix (before → after)

| Item | Before | After |
|------|--------|--------|
| `GameProfilerHook.hpp` body | L0 header included by `gameModConfig` | `plugins/plugin_debug_profiler/` |
| `DS_LUAJIT_replace_profiler_api` | L0 `gameModConfig.cpp` | profiler plugin |
| `DS_LUAJIT_enable_tracy` | L0 | profiler plugin |
| `DS_LUAJIT_enable_framegc` | L0 | profiler plugin |
| `fullgc_deferred` / `fullgc_deferred_enabled` | `plugin_core_vm` gameio | profiler plugin |
| `DS_LUAJIT_disable_fullgc` | gameio | profiler plugin |
| `lj_gc_fullgc_external` | gameio | **profiler export**; core.vm only wires pointer |
| `lua_gc_func` fill | gameio `init_luajit_io` | remains core.vm (or profiler re-reads from lua51 module); **no L0 resolve** |
| `ds_core_vm_fullgc_deferred_ptr` / `ds_core_vm_lua_gc_func_ptr` | core.vm | **deleted** |
| L0 GameProfilerHook dynamic resolve | L0 | **deleted** |
| Lua `debug_profiler.lua` / `gc_policy.lua` | separate Lua plugins | same id `debug.profiler` (one or two chunks under one registration) |
| `profiler.cpp` sampling | L0 optional | out of v1 unless trivial; may stay L0 or later same plugin |

## 7. Exports and trampolines

### 7.1 Native exports from `plugin_debug_profiler`

```text
ds_plugin_module_init
ds_plugin_module_abi_version   (optional "1")
DS_LUAJIT_replace_profiler_api
DS_LUAJIT_enable_tracy
DS_LUAJIT_enable_framegc
DS_LUAJIT_disable_fullgc
lj_gc_fullgc_external          // C ABI for core.vm
```

`DONTSTARVEINJECTOR_GAME_API` / explicit C export for `lj_gc_fullgc_external` so `GetProcAddress` works.

### 7.2 GameInjector trampolines (`GameLuaModule` in core.vm)

Resolve from `plugin_debug_profiler` via `GetModuleHandle` + `GetProcAddress` (same pattern as fork/rpc/vbpool). Missing module → no-op / false / 0.

### 7.3 core.vm install contract

In `init_luajit_io` (or equivalent):

1. Prefer set `lj_gc_fullgc_external` to a **local forwarding stub** that:
   - looks up `plugin_debug_profiler` export once (cache) or per call;
   - if found, call it with `(L, oldfn)`;
   - if not, call `oldfn(L)` immediately.
2. Do **not** fail inject or ReplaceLuaModule if profiler is absent.
3. Remove gameio-owned `fullgc_deferred` and the two `ds_core_vm_*_ptr` getters.

### 7.4 FrameGC / luaType

`DS_LUAJIT_enable_framegc` / `TryDoGC` continue to use `ds::core_vm::TryGetGameLuaContext()` when available. If `core.vm` is not mapped, FrameGC enables as soft no-op (return false / skip steps) — same practical degradation as missing JIT.

## 8. Config / Lua

- Plugin option schema registers the existing modinfo keys (no rename in v1).
- Enable predicate: any of profiler/tracy/fullgc/framegc options that currently activate `gc_policy` / `debug_profiler` (match today’s `any_of` / disabled_by gen-gc rules).
- Lua face: keep behavior of:
  - `Mod/plugins/debug_profiler.lua` — replace_profiler + tracy
  - `Mod/plugins/gc_policy.lua` — disable_fullgc / enable_framegc / ensure replace_profiler first  
  Prefer single host registration id `debug.profiler` (implementation may keep two files).

## 9. Build

- `ds_add_dynamic_plugin(plugin_debug_profiler …)`
- Link: Injector (Gum re-export), `function_relocation`, spdlog; Tracy if already used by profiler path; `/NODEFAULTLIB:frida-gum.lib` on MSVC.
- Remove profiler implementation TUs from Injector `SOURCES` / stop including `GameProfilerHook.hpp` from L0 business TUs.
- Tracy-only compile flags that lived on Injector for profiler move with the plugin target as needed.

## 10. Failure / degradation

| Scenario | Expected |
|----------|----------|
| No `plugin_debug_profiler` | inject OK; core.vm JIT OK; fullgc never deferred; framegc/tracy APIs no-op |
| Profiler present, no core.vm | replace_profiler/tracy may still run if signatures match game; FrameGC/luaType paths soft no-op |
| Profiler + core.vm | full behavior parity with pre-move |
| Both FullGC and FrameGC options | preserve current `gc_policy.lua` sequencing (replace_profiler first) |

Fail-fast only for true hard errors inside hooks (same as today); missing optional peer is never inject-abort.

## 11. Migration slices (implementation plan input)

| Slice | Work | Gate |
|-------|------|------|
| P0 | Scaffold `plugin_debug_profiler` + empty `ds_plugin_module_init` + schema keys | unit plugin host |
| P1 | Move `GameProfilerHook` + `replace_profiler_api` / tracy / framegc into plugin; L0 stubs removed | build + L-G |
| P2 | Move fullgc state + `DS_LUAJIT_disable_fullgc` + `lj_gc_fullgc_external` export; core.vm forwarding stub; delete `ds_core_vm_fullgc_*` | L-G present; no L0 GetProcAddress fullgc |
| P3 | GameLuaModule trampolines → `plugin_debug_profiler` | L-G with options |
| P4 | Lua dual-face registration under `debug.profiler` | mod load order |
| P5 | Docs (`plugin-system.md`) + degradation matrix notes | ctest + L-G |

Each slice runnable and revertible.

## 12. Testing

1. **Unit:** plugin load graph includes `debug.profiler` when schema enables.
2. **L-G present (core.vm):** inject + world; with profiler DLL staged.
3. **L-G without profiler DLL:** inject + core.vm still PASS; no crash on GC.
4. **Config matrix (manual or harness):** FullGC on; FrameGC on; Tracy on; all off.
5. **Grep gate:** L0 has no `ds_core_vm_fullgc` / no `fullgc_deferred` resolve to core.vm.

## 13. Success criteria

- [ ] `plugin_debug_profiler` is the sole owner of profiler + fullgc policy state
- [ ] L0 has zero reverse deps to core.vm for fullgc
- [ ] core.vm optional path unchanged for non-profiler users
- [ ] Behavior parity for Tracy / FullGC / FrameGC when plugin enabled
- [ ] Documented in `docs/plugin-system.md`

## 14. Related

- Plugin architecture: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` (`debug.profiler`, `gc.policy` rows — this design **merges** GC policy into `debug.profiler` for precise cohesion)
- core.vm optional: `docs/superpowers/specs/2026-08-04-core-vm-plugin-design.md`
- Module ABI v1 / dynamic loader: existing dynamic plugin skeleton specs

## 15. Open follow-ups (not blocking v1)

- Fold `profiler.cpp` / `DS_LUAJIT_enable_profiler` into the same DLL
- Whether Lua remains two files or one
- Client vs dedicated signature differences already encoded in `replace_profiler_api` — keep as-is
