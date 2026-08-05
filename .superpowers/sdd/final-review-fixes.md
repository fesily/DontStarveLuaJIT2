# Final whole-branch review fixes

**Date:** 2026-08-05  
**Branch:** `feature/plugin-manager`  
**Commit message:** `fix(plugin-manager): safe pending replace, zip caps, require files list, curl on unix`

## Findings fixed (Important)

| # | Finding | Fix |
|---|---------|-----|
| 1 | `PluginPendingUpdates::apply_one` deleted dest before durable replacement | Prefer rename-over-existing; else copy pending → sibling temp in plugins_dir, rename temp over dest; on failure leave pending and keep working module. Never pre-delete dest. |
| 2 | Zip extract unbounded uncompressed size | Cap per-entry **64 MiB**, total extracted **128 MiB** (`kMaxZipEntryUncompressedBytes` / `kMaxZipTotalUncompressedBytes`). Hard fail with clear `exceeds` error. |
| 3 | Empty `files[]` only hashed primary module | Production `apply_one_plugin` now **requires non-empty `files[]`** (`apply: files[] is required…`). Default extract allowlist remains for fixtures/extract helpers only. |
| 4 | Non-Windows curl optional | `vcpkg.json`: add `curl` (`ssl`, `!windows`). `plugin_manager` CMake: `find_package(CURL REQUIRED)` on non-Windows + link + `DS_PLUGIN_MANAGER_HAS_CURL`. Windows stays WinHTTP. |

## Files

- `src/DontStarveInjector/core/PluginPendingUpdates.cpp`
- `src/DontStarveInjector/plugins/plugin_manager/PluginZipExtract.{hpp,cpp}`
- `src/DontStarveInjector/plugins/plugin_manager/PluginApply.cpp`
- `src/DontStarveInjector/plugins/plugin_manager/CMakeLists.txt`
- `vcpkg.json`
- `tests/plugin/test_plugin_pending_updates.cpp`
- `tests/plugin/test_plugin_hash_zip.cpp`
- `tests/plugin/test_plugin_apply_offline.cpp`

## Tests (offline unit, PASS)

```
plugin_pending_updates  ALL PASS
  empty_or_missing_pending
  apply_overwrites_and_clears_pending
  apply_fresh_install_from_pending
  ignores_staging_temps

plugin_hash_zip         ALL PASS
  … existing …
  zip_reject_oversized_entry

plugin_apply_offline    ALL PASS
  … existing …
  apply_requires_nonempty_files
```

Built/run via `.superpowers/sdd/build_t8_{pending,hash,apply}.bat` against main tree vcpkg_installed.
