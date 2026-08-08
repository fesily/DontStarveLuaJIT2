# Task 7 Report: Migrate remaining dual-face packages (P3)

**Status:** DONE  
**Branch:** `feature/plugin-package-aggregation`

## Commits

| SHA | Message |
|-----|---------|
| `0215871` | `feat(plugins): migrate remaining dual-face packages to mini-mod layout` |

Full SHA: `02158716d7131db8c9530538c6e43bf658c7f736`  
Base: `542a97b` (Task 6 fork_save_spec path fix)

## Packages migrated

| stem | plugin_id | scripts | notes |
|------|-----------|---------|-------|
| `plugin_network_rpc` | `network.rpc` | none (inline modmain) | former load body → modmain; uses `GameInjector` |
| `plugin_network_sim` | `network.sim` | `scripts/netsim.lua` | moved from `Mod/scripts/netsim.lua` |
| `plugin_sim_lagcomp` | `sim.lagcomp` | `scripts/lag_compensation.lua` | moved from `Mod/scripts/lag_compensation.lua` |
| `plugin_debug_profiler` | `debug.profiler` | none | AlwaysOn native; modinfo `any_of` Lua keys |
| `plugin_fps_render` | `fps.render` | none | AlwaysOn native; modinfo `option = TargetRenderFPS` |

Each package mirrored under:

- `src/DontStarveInjector/plugins/<stem>/`
- `Mod/plugins/<stem>/`

## Files

| Action | Path |
|--------|------|
| Create | `src/.../plugin_{network_rpc,network_sim,sim_lagcomp,debug_profiler,fps_render}/{modinfo,modmain}.lua` (+ scripts where needed) |
| Create | `Mod/plugins/plugin_{...}/` runtime mirrors |
| Modify | `Mod/plugins/init.lua` — final `load_package` order per brief |
| Modify | `Mod/plugins/package_load.lua` — inject `GameInjector` + config-backed `GetModConfigData` into package modmain env from host `ctx` |
| Modify | native `plugin_*.cpp` comments (Lua face paths) |
| Modify | `tests/plugin/plugin_host_lua_spec.lua` — clear `plugins.package_load` between cases |
| Delete | flat faces: `network_rpc.lua`, `network_sim.lua`, `sim_lagcomp.lua`, `debug_profiler.lua`, `fps_render.lua` |
| Delete | `Mod/scripts/netsim.lua`, `Mod/scripts/lag_compensation.lua` (moved into packages) |

## init order (delivered)

```lua
return {
    load_flat("jit_tailcall"),
    load_package("plugin_debug_profiler"),
    load_package("plugin_network_rpc"),
    load_flat("network_entity"),
    load_package("plugin_fps_render"),
    load_package("plugin_save_fork"),
    load_package("plugin_sim_lagcomp"),
    load_package("plugin_network_sim"),
    load_flat("jit_runtime"),
}
```

## Tests

```bash
python tools/check_plugin_package_identity.py --source-root .
# identity gate OK: checked=6 skipped=0  (IDENTITY_RC:0)

python tests/plugin/run_package_load.py
# ALL PASS package_load_spec  (PKG_RC:0)

LUA_BIN=<parent builds>/luajit/Release/luajit.exe python tests/plugin/run_lua_host.py
# plugin_host_lua_spec: all tests passed  (HOST_RC:0)

python tests/plugin/test_plugin_package_identity.py -q
# 6/6 OK
```

No full suite / formatters (per task scope). L-G not run.

## Concerns

1. **Dual tree mirror:** `src/.../plugin_*` and `Mod/plugins/plugin_*` must stay in sync until install is the sole runtime path (same as save.fork).
2. **package_load env:** modmain now receives `GameInjector` and config-derived `GetModConfigData` from host gate_ctx so inline faces (rpc/profiler/fps) keep production behavior under pure Host tests without `_G.GameInjector`.
3. **AlwaysOn natives:** identity gate only enforces AllOf/AnyOf key sets; profiler/fps keep Lua-facing option keys in modinfo while native remains AlwaysOn (documented in modinfo comments).
4. **Host runner:** worktree has no local `builds/`; need `LUA_BIN` or parent-build walk (package_load runner already walks parents; host runner does not — pre-existing).
