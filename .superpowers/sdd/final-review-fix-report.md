# Final review fix report: plugin-package-aggregation

**Date:** 2026-08-08  
**Branch:** `feature/plugin-package-aggregation`  
**Agent:** FinalFix  

## Important: package_load modinfo sandbox free globals

### Problem

`Mod/plugins/package_load.lua` `make_modinfo_env` returned a bare table. Package `modinfo` `when()` closures (e.g. `plugin_save_fork`) resolve free globals `TheNet` / `_G` / `TheWorld` against that env. With incomplete `gate_ctx` (no `is_client`), `when` falls through to `TheNet:IsDedicated()` → nil index / throw during host resolve.

### Fix

1. After building marker fields on the modinfo env, set  
   `setmetatable(env, { __index = extras.parent_env or _G })`.  
   - Free globals fall through to parent/`_G`.  
   - No `__newindex` → assignments stay on env (Host markers not polluted).  
   - Markers remain raw fields (`rawget` still sees them).
2. Unit test `test_when_sees_thenet_from_g` in `tests/plugin/package_load_spec.lua`:  
   mock `_G.TheNet:IsDedicated() → false`, load package, call `when({ has_luajit = true })` without `is_client` → success / `false`, not error; marker still raw-true.
3. Docs: `docs/plugin-system.md` leftover flat paths  
   (`network_rpc.lua`, `load_plugin`) → package layout (`plugin_network_rpc/`, `load_package` / `load_flat`).

### Files

- `Mod/plugins/package_load.lua`
- `tests/plugin/package_load_spec.lua`
- `docs/plugin-system.md`

### Tests

```
package_load_spec          ALL PASS (incl. when_sees_thenet_from_g)
plugin_host_lua_spec       all tests passed
test_plugin_package_identity  OK (6 tests)
```

### Commit

`fix(plugins): rebind modinfo env so when() sees game globals`
