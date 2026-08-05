# Task 8 Report: HTTP fetch, download, verify, apply

**Status:** DONE  
**Branch:** feature/plugin-manager  
**Base:** fd99b86  
**Commit:** 38e44fec104f52dd965e3481ec3fe8cbb47babc0

## Summary

Wired real download/apply into optional `plugin.manager`:

- `PluginHttp` — `http_get` (WinHTTP on Windows; libcurl if `DS_PLUGIN_MANAGER_HAS_CURL`, else `"http unsupported"`)
- Auto probe: prefer_proxy `auto` tries direct short timeout then gh-proxy wrap
- Injectable `set_http_get_override` for offline tests
- `PluginHash` — pure SHA-256 (module verify)
- `PluginZipExtract` — libzip extract with `..` / absolute / nested reject + files[] allowlist (default: top-level `plugin_*` modules + meta)
- `PluginApply` — resolve tag → fetch `plugins-manifest.json` → channel cache → download asset → sha256 verify → install to `plugins/` or `update_pending/` on lock
- `PluginManagerApi` — real `fetch_manifest` / `apply` (fail-soft network errors)

## Files

| Path | Action |
|------|--------|
| `plugins/plugin_manager/PluginHttp.hpp/.cpp` | Create — WinHTTP GET + proxy probe + override |
| `plugins/plugin_manager/PluginHash.hpp/.cpp` | Create — sha256_hex / file / equal |
| `plugins/plugin_manager/PluginZipExtract.hpp/.cpp` | Create — safe extract |
| `plugins/plugin_manager/PluginApply.hpp/.cpp` | Create — manifest fetch + apply plan |
| `plugins/plugin_manager/PluginManagerApi.cpp` | Wire fetch/apply + channel cache |
| `plugins/plugin_manager/PluginManagerApi.hpp` | Comment update |
| `plugins/plugin_manager/CMakeLists.txt` | Sources + libzip + winhttp / optional curl |
| `tests/plugin/test_plugin_hash_zip.cpp` | Offline sha256 + zip fixtures |
| `tests/plugin/test_plugin_apply_offline.cpp` | Mock HTTP apply pipeline |
| `tests/CMakeLists.txt` | New test targets |

## TDD Evidence

### RED → GREEN (offline)

1. **hash/zip** — `test_plugin_hash_zip` (MSVC `/MD` + vcpkg libzip):
   ```
   PASS: sha256_known_vectors
   PASS: sha256_file
   PASS: zip_unsafe_detection
   PASS: zip_extract_allowlist_default
   PASS: zip_extract_explicit_allowlist
   PASS: zip_reject_dotdot
   PASS: zip_reject_nested
   PASS: zip_memory_extract
   ALL PASS plugin_hash_zip
   ```

2. **apply offline** — mock HTTP map, no network:
   ```
   PASS: channel_cache_and_lookup (platform=windows module=plugin_dummy.dll)
   PASS: fetch_manifest_mock
   PASS: apply_plan_with_mock_http
   PASS: install_pending_fallback
   ALL PASS plugin_apply_offline
   ```
   Includes intentional sha256 mismatch failure path (keeps old install semantics).

3. **Syntax-check** — `cl /c` of PluginHttp, PluginApply, PluginManagerApi, PluginZipExtract, PluginHash: PASS (C4819 codepage warnings only).

### Full plugin_manager MODULE link

Skipped — worktree not configured in main `builds/ninja-multi-vcpkg` (same as Task 6/7). CMake sources + link lines ready for next configure.

## Behavior notes

| Case | Behavior |
|------|----------|
| `prefer_proxy=always` | only proxied URL |
| `prefer_proxy=never` | only direct |
| `prefer_proxy=auto` | direct 3s then proxy full timeout |
| Network fail | `last_error` set; return false; no partial corrupt modules (staging + sha gate) |
| Zip `..` / abs / nested | hard reject extract |
| DLL write lock | `plugins/update_pending/` + `needs_restart` |
| No manifest | apply fails with clear error |

## Security

- Path traversal reject on extract (`..`, absolute, drive letters, nested paths)
- Only extract `files[]` when present; else only top-level plugin modules/meta
- SHA-256 of **module** bytes vs manifest platform.sha256 before install

## Checklist

- [x] PluginHttp WinHTTP + fail-soft non-Win without curl
- [x] fetch_manifest + channel cache + optional file cache beside pin config
- [x] apply download / verify / extract / pending
- [x] Offline sha256 + zip tests PASS
- [x] Offline mock-HTTP apply tests PASS
- [x] CMake libzip + winhttp
- [x] Commit `feat(plugin-manager): GitHub download, gh-proxy, verify, and apply`
