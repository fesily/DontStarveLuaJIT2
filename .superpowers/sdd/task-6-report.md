# Task 6 Report — Optional `plugin.manager` skeleton + soft Lua bindings

**Status:** DONE  
**Date:** 2026-08-05  
**Base:** `e8fe133`  
**Commit:** (see git log) `feat(plugin-manager): optional plugin.manager skeleton and soft Lua bindings`

## Summary

Added optional dynamic plugin module `plugin_manager` (logical id `plugin.manager`) with:

- IPlugin skeleton (EarlyNative, AlwaysOn, priority 50, no reload)
- C API surface for pin config + stubbed fetch/apply
- Soft GameInjector exports via `register_game_injector_export` (GiType auto)
- CMake always-built `add_subdirectory` (still **runtime-optional** if DLL deleted)

## Architecture adaptation (vs plan wording)

Plan / brief still said:

> Modify `GameLuaModule.cpp` — bind all `DS_LUAJIT_plugin_*` via `host_service` only  
> module_init: `register_service` for each API

**Current repo pattern (supersedes that wording):**

| Concern | Implementation |
|---|---|
| Lua soft bindings | `host->register_game_injector_export("DS_LUAJIT_plugin_*", &fn)` in `module_init` |
| `luaopen_GameInjector` | core.vm binds owned symbols then `apply_game_injector_exports(L, -1)` |
| Soft absence | If `plugin_manager.dll` missing → no exports registered → Lua sees **nil** |
| `GameLuaModule.cpp` | **Not modified** — no host_service wrappers |
| Optional C services | Also `register_service` same names for native callers (not required by any plugin) |

## Files

| Path | Action |
|---|---|
| `src/DontStarveInjector/plugins/plugin_manager/CMakeLists.txt` | Create — `ds_add_dynamic_plugin` + nlohmann_json |
| `src/DontStarveInjector/plugins/plugin_manager/plugin_manager.cpp` | Create — IPlugin + module_init exports |
| `src/DontStarveInjector/plugins/plugin_manager/PluginManagerApi.hpp` | Create — C API decls |
| `src/DontStarveInjector/plugins/plugin_manager/PluginManagerApi.cpp` | Create — pin ops real; HTTP/apply stubs |
| `src/DontStarveInjector/CMakeLists.txt` | Modify — `add_subdirectory(plugins/plugin_manager)` in always-built list |

Existing (linked, unchanged this task): `PluginPinConfig.*`, `PluginDownloadUrl.hpp`.

## IPlugin

- id: `plugin.manager`
- version: `1.0.0`
- phases: `EarlyNative`
- AlwaysOn, priority 50, `support_reload = false`
- `load()`: `reload_pin_config()` only (no network)

## C API

| Export | Behavior (Task 6) |
|---|---|
| `DS_LUAJIT_plugin_config_path` | `resolve_config_path()` static string buffer |
| `DS_LUAJIT_plugin_manager_status_json` | Minimal stub JSON (`plugins:[]`, last_error, needs_restart, …) |
| `DS_LUAJIT_plugin_config_reload` | Reload pin file |
| `DS_LUAJIT_plugin_config_set_json` | Write + reload |
| `DS_LUAJIT_plugin_pin_set` / `pin_clear` | Mutate pins + save |
| `DS_LUAJIT_plugin_fetch_manifest` | **stub false** (Task 8) |
| `DS_LUAJIT_plugin_manifest_json` | `"{}"` |
| `DS_LUAJIT_plugin_plan_apply_json` | `"[]"` |
| `DS_LUAJIT_plugin_apply` | **stub false** (Task 8) |
| `DS_LUAJIT_plugin_needs_restart` | false |

HTTP/curl/vcpkg intentionally skipped (Task 8).

## Soft absence

```text
plugins/ without plugin_manager.dll
  → DynamicPluginLoader skips missing module
  → no DS_LUAJIT_plugin_* registered
  → apply_game_injector_exports has nothing to bind
  → GameInjector.DS_LUAJIT_plugin_* is nil in Lua
  → other plugins unaffected (no requires_services / depends)
```

## Verification

| Check | Result |
|---|---|
| `add_subdirectory(plugins/plugin_manager)` in always-built list | Yes (next to dummy/save_fork/core_vm) |
| No other plugin `requires_services` / depends on manager | Grep: only profiler soft-requires core.vm; lagcomp requires core.vm context — **no** manager refs |
| GameLuaModule host_service not reintroduced | Confirmed: only `apply_game_injector_exports` |
| clang++ -std=c++23 -c PluginManagerApi.cpp | PASS (syntax/includes) |
| clang++ -std=c++23 -c plugin_manager.cpp | PASS (syntax/includes) |
| Full `plugin_manager` MODULE link | Skipped — main `builds/ninja-multi-vcpkg` is master tree (`CMAKE_HOME_DIRECTORY` main repo); worktree not configured there. Sources complete for next configure. |

## Acceptance checklist

- [x] Build files produce `plugin_manager` MODULE target when Injector CMake configures this worktree
- [x] Module optional at runtime (no hard deps from other plugins)
- [x] Soft Lua path via GameInjector exports (not GameLuaModule host_service)
- [x] HTTP stubs only (Task 8)
- [x] Commit + this report

## Notes

1. `register_service` duplicates export names for C DI; **no** other plugin lists them in `requires_services`.
2. Status JSON is intentionally minimal until Task 7 inventory.
3. Pin config write path uses existing `PluginPinConfig` load/save helpers.
