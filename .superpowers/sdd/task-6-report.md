# Task 6 Report — M3 `render.angle` + `render.vbpool` EarlyNative

**Status:** DONE  
**Date:** 2026-08-03  
**Commit:** `664f7d2` — `feat(plugin): migrate render.vbpool + render.angle EarlyNative (M3 Task 6)`

## Summary

Migrated EarlyNative render features onto PluginHost:

- **`render.vbpool`**: EarlyNative, option `EnableVBPool`, priority 20, Win client `can_load`. `load()` → `DS_LUAJIT_set_vbpool_enabled(true)`.
- **`render.angle`**: EarlyNative, `AlwaysOn` options (backend is a **parameter**), priority 30, Win client `can_load`. `load()` → `InitGameOpenGl()` (no-ops when `AngleBackend == auto`).
- **`LoadGameModConfig`**: config resolve stays L0 via `GameJitModConfig::instance()`; hard VBPool / OpenGL side effects removed. Win still runs `repalce_set_thread_name()` (L0 hygiene).
- **`modmain.lua`**: removed late `EnableVBPool == false` → `DS_LUAJIT_set_vbpool_enabled(false)`. Disable is host/config only (plugin simply does not load when option off).

## Changes

### Modified

| File | Change |
|---|---|
| `src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp` | Register `RenderVbpoolPlugin` + `RenderAnglePlugin` beside `network.rpc` |
| `src/DontStarveInjector/core/RegisterBuiltinPlugins.hpp` | Comment lists render plugins |
| `src/DontStarveInjector/gameModConfig.cpp` | Strip VBPool/OpenGL side effects; keep thread-name L0 call; drop unused `GameOpenGl.hpp` |
| `src/DontStarveInjector/DontStarveInjector.cpp` | Comment: EarlyNative owns network + render side effects |
| `Mod/modmain.lua` | Remove late VBPool disable block |
| `tests/plugin/test_plugin_host_graph.cpp` | L-E matrices: EnableVBPool true/false/gate; AngleBackend auto/vulkan/d3d11/d3d9 parameter |
| `tests/plugin/test_plugin_config_bridge.cpp` | Bridge enable matrix for vbpool + angle backend reaches plugin |

## Behavior (production)

```text
Inject:
  LoadGameModConfig
    // resolve cascade only (+ Win thread name)
  → RegisterBuiltinPlugins (network.rpc, render.vbpool, render.angle)
  → FromGameJitModConfig (EnableVBPool, AngleBackend, NetworkOpt default, …)
  → resolve → load_phase(EarlyNative)
       EnableVBPool + client → DS_LUAJIT_set_vbpool_enabled(true)
       client → InitGameOpenGl()  // auto backend returns early inside
       NetworkOpt → GameNetWorkHookRpc4()
  → DisableScriptZip
```

| Plugin | Gate | EarlyNative result |
|---|---|---|
| `render.vbpool` | EnableVBPool=true, is_client, Win | Loaded → pool hooks |
| `render.vbpool` | EnableVBPool=false | Disabled, no API call |
| `render.vbpool` | option true, dedicated | can_load false → Disabled |
| `render.angle` | is_client, Win (AlwaysOn) | Loaded → InitGameOpenGl |
| `render.angle` | dedicated | Disabled |
| `render.angle` | AngleBackend=auto/vulkan/… | Backend from GameJitModConfig; auto no-ops init |

## Verification

| Suite | Result |
|---|---|
| `test_plugin_host_graph` (incl. render L-E) | PASS (clang++ unit binary) |
| `test_plugin_config_bridge` (vbpool/angle rows) | PASS |
| `test_plugin_option_rules` | PASS |
| `test_buffer_name_pool` | Pre-existing fail: test assumes per-bucket cap 32; header `MAX_POOL_SIZE_PER_BUCKET=128`. **Not introduced by Task 6** (header-only, untouched). |

## Acceptance checklist

- [x] Step 1: Config bridge EnableVBPool true/false already green; BufferNamePool unit is pre-existing mismatch (not Task 6)
- [x] Step 2: Plugins implemented; LoadGameModConfig side effects stripped; modmain late disable removed
- [x] Step 3: Host graph + bridge unit tests compile and pass
- [x] Step 4: Commit + this report

## Notes / concerns

1. **Disable path**: former modmain could force-disable after EarlyNative enable. With host ownership, disable = option false → plugin never loads. If save config flips mid-session without restart, behavior already required restart (`require_restart = true` on EnableVBPool).
2. **RegisterBuiltinPlugins** still pulls `GameNetwork` + `GameOpenGl` + `DS_LUAJIT_set_vbpool_enabled` — unit binaries continue to use stand-ins (do not link RegisterBuiltinPlugins).
3. Full Injector SHARED not rebuilt this task (prefer clang++ unit tests per plan).
4. `BufferNamePool` ctest may still red until test limits match `MAX_POOL_SIZE_PER_BUCKET` (out of scope).
