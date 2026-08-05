# Task 7 Report — Local inventory + status_json + plan (no network)

**Status:** DONE  
**Date:** 2026-08-05  
**Base:** `a85dcb8`  
**Commit:** `feat(plugin-manager): local inventory, status JSON, apply plan`

## Summary

Extended optional `plugin.manager` with pure local inventory scan, real `status_json`, and offline `plan_apply_json`. No HTTP. Manager remains runtime-optional.

## Files

| Path | Action |
|------|--------|
| `src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.hpp` | Create — scan / status / plan pure APIs |
| `src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.cpp` | Create — meta+module scan, status rows, plan actions |
| `src/DontStarveInjector/plugins/plugin_manager/PluginManagerApi.cpp` | Modify — wire inventory into status/plan; recompute on read |
| `src/DontStarveInjector/plugins/plugin_manager/PluginManagerApi.hpp` | Modify — comment (Task 7 scope) |
| `src/DontStarveInjector/plugins/plugin_manager/CMakeLists.txt` | Modify — add `PluginLocalInventory.cpp` |
| `tests/plugin/test_plugin_local_inventory.cpp` | Create — TDD inventory/status/plan |
| `tests/CMakeLists.txt` | Modify — `test_plugin_local_inventory` target |

## API

```cpp
namespace ds::plugin {
struct LocalPluginEntry { id, version?, sha256?, module, path, has_meta, has_module };
std::vector<LocalPluginEntry> scan_local_inventory(path plugins_dir);
std::filesystem::path resolve_plugins_dir(); // DS_LUAJIT_PLUGIN_DIR or injector/plugins

struct PluginStatusEntry {
  id, local_version?, desired_version?, channel_version?, pin_source?,
  state /* ok|missing|update_available|unknown */, module, sha256?
};
std::vector<PluginStatusEntry> build_plugin_status(cfg, inventory, channel_cache={});

struct PlanAction { id, from?, to, reason /* version_mismatch|missing|prefer_present */ };
std::vector<PlanAction> build_plan_actions(cfg, inventory, channel_cache={});
}
```

### Plugins dir discovery
1. `DS_LUAJIT_PLUGIN_DIR` env  
2. else `<injector_module_dir>/plugins` (same heuristic as DynamicPluginLoader)  
3. Inventory scan always takes an explicit path (testable).

### Meta sidecar
`plugin_*.meta.json`: `{id, version, sha256, module}` (from `gen_plugins_manifest.py --write-meta`).  
Module file without meta → logical id via stem map, `version` unknown.

### status_json fields
- Top: `config_path`, `plugins_dir`, `schema_version`, `channel_name`, `repo`, `release_tag`, `follow_latest`, `prefer_proxy`, `auto_apply_on_boot`, `needs_restart`, `last_error`
- `plugins[]`: `id`, `local_version`, `desired_version`, `channel_version`, `pin_source`, `state`, `module`, `sha256`
- Offline: `channel_version` null unless Task 8 cache filled; desired from override pins only via `desired_version()`

### plan_apply_json
JSON array of `{id, from, to, reason}` for:
- override/channel desired ≠ local (`version_mismatch`)
- desired but not on disk (`missing`)
- `prefer_present` soft missing (`prefer_present`) — never hard-fails

## TDD Evidence

- **RED:** test included `PluginLocalInventory.hpp` before sources existed → missing header.
- **GREEN:** `g++ -std=c++23` + nlohmann include path; run:
  ```
  PASS: scan_meta_and_module
  PASS: module_without_meta_version_unknown
  PASS: missing_dir_empty
  PASS: status_override_update_available
  PASS: status_local_only_ok
  PASS: plan_mismatch_and_prefer_present
  PASS: plan_missing_override
  PASS: status_with_channel_cache
  ALL PASS plugin_local_inventory
  ```
- Regression: `test_plugin_pin_config` ALL PASS  
- `clang++ -std=c++23 -fsyntax-only PluginManagerApi.cpp` + `PluginLocalInventory.cpp` PASS

## Behavior matrix

| Case | Result |
|------|--------|
| meta + dll | id/version/sha256 from meta |
| dll only | id from stem map; version null; state `unknown` |
| local only, no pins | state `ok` |
| override pin ≠ local | state `update_available`; plan `version_mismatch` |
| override, no local | state `missing`; plan `missing` |
| prefer_present absent | plan soft `prefer_present` |
| channel cache present | desired follows channel (non-override pin) |

## Self-review

- No network; `g_channel_cache` reserved empty for Task 8
- Manager still optional; pure library + optional module
- `prefer_present` soft only
- pin_set/pin_clear commit `g_cfg` then refresh status (no stale pins)
- status/plan recompute on API read
