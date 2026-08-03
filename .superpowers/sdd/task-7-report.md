# Task 7 Report — M4 jit/gc/profiler/fps/tailcall Lua plugins

**Status:** DONE  
**Date:** 2026-08-03  
**Commit:** `48fd06a` — `feat(plugin): migrate jit/gc/profiler/fps/tailcall Lua plugins (M4 Task 7)`

## Summary

Migrated hard-wired AfterModMain features from `modmain.lua` onto Path A Lua PluginHost:

| Plugin | File | Priority | Options / gates |
|---|---|---:|---|
| `jit.tailcall` | `Mod/plugins/jit_tailcall.lua` | 10 | any_of `SlowTailCall` / `ForceDisableTailCall` / `AutoDetectEncryptedMod`; `has_luajit`. Folded encrypt detect + frostxx ctx. |
| `debug.profiler` | `Mod/plugins/debug_profiler.lua` | 20 | any_of `EnableProfiler` / `EnableTracy` (string is_bool_on: `"off"` off, `"fzvp"`/`"on"` on); `has_luajit` |
| `gc.policy` | `Mod/plugins/gc_policy.lua` | 30 | AlwaysOn; resets fullgc/framegc then applies `DisableForceFullGC` / `EnableFrameGC` unless `EnabledGenGC` |
| `fps.render` | `Mod/plugins/fps_render.lua` | 50 | `TargetRenderFPS` (nonzero); `is_windows` gate |
| `jit.runtime` | `Mod/plugins/jit_runtime.lua` | 70 | AlwaysOn + `has_luajit`; ForceJitOpt, EnabledJIT, ModBlackList/frostxx kleiloadlua, **HideGlobalJIT last** |

`compat.frostxx` merged into `jit.tailcall` (thin; compile-time `EnableFrostxxMods=false` preserves former default).

## Changes

### Created
| File | Role |
|---|---|
| `Mod/plugins/jit_tailcall.lua` | SlowTailCall + ForceDisableTailCall + AutoDetectEncryptedMod |
| `Mod/plugins/debug_profiler.lua` | EnableProfiler + EnableTracy |
| `Mod/plugins/gc_policy.lua` | fullgc / framegc policy |
| `Mod/plugins/fps_render.lua` | TargetRenderFPS |
| `Mod/plugins/jit_runtime.lua` | JIT opt/on + HideGlobalJIT + blacklist hook |
| `.superpowers/sdd/task-7-report.md` | This report |

### Modified
| File | Change |
|---|---|
| `Mod/plugins/init.lua` | Register M4 plugins; order reflects priority bands |
| `Mod/modmain.lua` | Strip hard-wired feature blocks; Main keeps version UI / NoInjector / crash clean / AlwaysEnableMod write / host bootstrap; gate_ctx gains `jit` + `mod_env` |
| `tests/plugin/plugin_host_lua_spec.lua` | L-E matrices for all five plugins; real-registry profiler-before-jit order; GC stubs for network matrices |

## Behavior (production)

```text
modmain Main (GameInjector present):
  GetModVersion / AlwaysLoad / version gate
  HookGetModConfigData
  PluginHost register(plugins/init) → resolve(GetModConfigData, gate_ctx) → load_phase(AfterModMain)
    10 jit.tailcall     (encrypt detect, slow tail, force disable)
    20 debug.profiler   (jit.zone / jit.p / tracy — before hide)
    30 gc.policy
    40 network.rpc / network.entity
    50 fps.render
    60 sim.lagcomp / network.sim / save.fork
    70 jit.runtime      (ForceJitOpt, EnabledJIT, blacklist, HideGlobalJIT)
  SwitchVm / GetModMainPath / HookGameVersionUI / luajit_config:WriteConfig
  modimport inject_server_only_mod

GameInjector nil → NoInjectorMain (unchanged)
```

## Verification

```text
python tests/plugin/run_lua_host.py
→ PASS: … profiler_before_hide, m4_plugin_priorities_and_order,
         debug_profiler_enable_matrix, gc_policy_enable_matrix,
         fps_render_enable_matrix, jit_tailcall_enable_matrix,
         jit_runtime_enable_matrix, network_* (GC stubs)
→ plugin_host_lua_spec: all tests passed
```

## L-E matrix rows covered

| Plugin | Config | Expected |
|---|---|---|
| `debug.profiler` | EnableProfiler=off, EnableTracy=off | Disabled |
| `debug.profiler` | EnableProfiler=fzvp | Loaded, ProfilerJit installed |
| `debug.profiler` | EnableTracy=on | Loaded, tracy=1 |
| `gc.policy` | DisableForceFullGC+EnableFrameGC, GenGC off | Loaded; fullgc/framegc true |
| `gc.policy` | same + EnabledGenGC | Loaded; flags reset false |
| `fps.render` | TargetRenderFPS=144, Win | Loaded; set_target_fps |
| `fps.render` | TargetRenderFPS=0 | Disabled |
| `fps.render` | TargetRenderFPS=120, non-Win | Disabled (when) |
| `jit.tailcall` | SlowTailCall+AnyMod | Loaded; registry `__any__` |
| `jit.tailcall` | all options false | Disabled |
| `jit.tailcall` | has_luajit=false | Disabled |
| `jit.runtime` | has_luajit | Loaded |
| `jit.runtime` | no luajit | Disabled |
| `jit.runtime` | HideGlobalJIT=true | global `jit` cleared |
| order | real registry | tailcall < profiler < jit.runtime |

## Acceptance checklist

- [x] Step 1: RED/GREEN profiler before jit.runtime (existing fake + real registry order test)
- [x] Step 2: Migrate functions into plugins; strip modmain hard-wire; keep NoInjector/version/AlwaysEnableMod
- [x] Step 3: Lua host tests + option matrices green
- [x] Step 4: Commit + this report

## Notes / concerns

1. **Host bootstrap order:** PluginHost still runs before `GetModMainPath` / `WriteConfig` (same as Task 2+). M4 features do not depend on modmain_path.
2. **gc.policy AlwaysOn:** always loads when registered (matches former unconditional fullgc/framegc reset). Network Lua tests needed GC API stubs on injectors.
3. **EnableFrostxxMods** remains compile-time false inside `jit.tailcall` (former modmain default).
4. No C++ / Injector rebuild for this task (Lua-only M4).
