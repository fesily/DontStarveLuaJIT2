# Plugin Manager Design

**Date:** 2026-08-05  
**Status:** Draft for review  
**Scope:** Injector base plugin version manager (upgrade/downgrade), unified pin config, GitHub download with CN gh-proxy, CI plugin packages, client UI entry.

## 1. Context and problem

### Current state

| Layer | Today | Gap |
|---|---|---|
| Plugin semantic version | Free-form `PluginManifest::version` / Lua `version` (mostly `1.0.0`; `core.vm` `0.2.0`) | Host never compares or pins versions |
| Module ABI | Major string `"1"` (`DS_PLUGIN_ABI_VERSION`) | Hard gate only; orthogonal to semver |
| Config | Cascade `ResolvedConfig` + `modinfo` `configuration_options` | No version-pin file |
| CI | `.github/workflows/release.yaml` publishes `{platform}_Mod.zip` | `ds_add_dynamic_plugin` has **no** `install()` → CI zips often omit `plugins/plugin_*`; no per-plugin assets; no `plugins-manifest.json` |
| Download | Local `install.bat` / dead auto-updater (`updater.cpp` `#if 0`) | No GitHub Releases client; no gh-proxy |
| UI | `ModConfigurationScreen` action bar (uninstall pattern in `AlwaysLoad`) | No Plugin Manager screen |

### Main contradiction

Plugins already declare versions, but CI does not publish plugin packages to GitHub Releases. A manager without installable assets cannot upgrade or downgrade.

### Locked decisions (brainstorming)

| Decision | Choice |
|---|---|
| Version unit | **Hybrid:** monorepo release channel + optional per-plugin override pins |
| Apply surface | Client writes config; **client and dedicated server** can download locally |
| Pin storage | Independent **`luajit_plugins.json`** (not modinfo / modoverrides) |
| Download owner | **Native** Injector API (`DS_LUAJIT_plugin_*`) |
| Release assets | Monorepo release + `plugins-manifest.json` + optional per-plugin zips |
| Implementation home | Dynamic plugin **`core.plugin_manager`** (not L0 business bloat) |
| v1 scope | End-to-end: CI + config + download + usable management UI |

## 2. Goals and non-goals

### Goals (v1)

1. **Version management:** channel follows a monorepo release; optional per-plugin pin for upgrade/downgrade override.
2. **Unified config:** one `luajit_plugins.json` semantics for client and dedicated server.
3. **Download:** default GitHub Releases; when direct GitHub fails (typical CN), wrap URL with gh-proxy.
4. **CI:** install plugins into package tree; attach manifest (+ per-plugin zips) on the same release as `{platform}_Mod.zip`.
5. **UI:** entry on this mod’s configuration screen; list / channel / pin / apply / restart hint.
6. **Native apply path:** dedicated server can reconcile pins without game UI.

### Non-goals (YAGNI)

- Runtime hot-swap of sticky native modules (`FreeLibrary` / multi-version side-by-side).
- Full plugin store, third-party registries, or code-signing PKI.
- Automatic migration across ABI major ≠ `"1"`.
- Pins inside `modinfo` / `modconfiguration_*` / `modoverrides.lua`.
- Uninstalling bootstrap plugins (`core.plugin_manager`, `core.vm`).
- Pretending Gum-only Windows plugins are available on Linux/macOS (manifest marks platform availability).
- UI automation frameworks (Playwright, FlaUI, etc.) — project policy rejects them.

### Success criteria

- A git tag release includes `{platform}_Mod.zip` with `bin64/.../plugins/plugin_*.{dll,so,dylib}` and a `plugins-manifest.json` (and preferably per-plugin zips).
- Change pin → download → restart → on-disk plugin version matches pin (manager validation layer).
- CN-unfriendly networks use gh-proxy after failed direct probe; others use direct GitHub.
- Dedicated server reading the same JSON can fetch missing/wrong-version plugins without UI.

## 3. Architecture

### Approach: `core.plugin_manager` dynamic plugin (B)

```text
┌─────────────────────────────────────────────────────────────┐
│ Client UI (Lua)                                             │
│  ModConfigurationScreen action → PluginManagerScreen        │
│  calls DS_LUAJIT_plugin_* only                              │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│ core.plugin_manager (native EarlyNative, AlwaysOn)          │
│  luajit_plugins.json  │  manifest cache  │  HTTP download   │
│  pin resolve          │  sha256 verify   │  pending moves   │
└───────────────────────────┬─────────────────────────────────┘
                            │ writes
┌───────────────────────────▼─────────────────────────────────┐
│ <InjectorDir>/plugins/   (+ update_pending/)                │
│ DynamicPluginLoader scans plugin_* ; PluginHost resolve/load│
│ (Host still gates ABI only; does not select by semver)      │
└─────────────────────────────────────────────────────────────┘

CI (same monorepo tag):
  build → install plugins/ → gen plugins-manifest.json
  → publish Mod.zip + manifest + plugin_*-<ver>-<platform>.zip
```

### Bootstrap / chicken-and-egg

| Rule | Detail |
|---|---|
| Bootstrap set | Default `["core.plugin_manager", "core.vm"]` |
| Always present | Shipped inside monorepo `{platform}_Mod.zip` |
| Not removable | Pin UI cannot remove bootstrap ids; version may follow channel or override |
| Missing manager | UI shows unavailable + full-mod update guidance; Injector continues without manager APIs |

### Boundary with existing systems

| System | Responsibility |
|---|---|
| `modinfo` / cascade / `OptionRule` | Feature enable/disable (e.g. `NetworkOpt`) |
| `luajit_config.json` | `modmain_path`, `AlwaysEnableMod`, `DisableJITWhenServer` |
| **`luajit_plugins.json`** | Channel + version pins + download policy |
| `PluginHost` / `DynamicPluginLoader` | Register, ABI gate, option resolve, phase load |
| `core.plugin_manager` | Disk package version ≈ pin; download; status for UI |

Pin and enable are orthogonal: pin `network.rpc@1.0.0` with `NetworkOpt=false` keeps the DLL on disk; Host may still skip `load`.

### Inject ordering (conceptual)

```text
Inject:
  RegisterCoreOptionSchema
  DynamicPluginLoader::load_all   // includes core.plugin_manager when present
  plugin_manager: apply update_pending/ file moves (earliest safe point)
  plugin_manager: optional auto_apply_on_boot
  refresh_cascade_after_plugins
  BuildConfigView → resolve → load_phase(EarlyNative)
```

Sticky modules already mapped in-process are **not** reloaded after apply; `needs_restart` is required.

## 4. Config model: `luajit_plugins.json`

### Path

- Default: `<game>/data/unsafedata/luajit_plugins.json`  
  (same directory convention as `luajit_config.json` via game dir / `unsafedata`)
- Optional override env: `DS_LUAJIT_PLUGINS_CONFIG` (absolute path) for shared dedicated-server layouts
- **Not** part of Klei mod configuration cascade

### Schema (v1)

```json
{
  "schema_version": 1,
  "channel": {
    "repo": "fesil/DontStarveLuaJIT2",
    "name": "stable",
    "release_tag": "v2.9.1",
    "follow_latest": false
  },
  "download": {
    "github_base": "https://github.com",
    "gh_proxy_base": "https://gh-proxy.com",
    "prefer_proxy": "auto",
    "auto_apply_on_boot": false
  },
  "pins": {
    "network.rpc": { "version": "1.0.0", "source": "override" },
    "core.vm": { "version": "0.2.0", "source": "channel" }
  },
  "bootstrap": ["core.plugin_manager", "core.vm"]
}
```

| Field | Meaning |
|---|---|
| `schema_version` | Config format; unknown → log + in-memory defaults (do not crash Injector) |
| `channel.repo` | `owner/name` for Releases URLs |
| `channel.name` | Logical channel: `stable` \| `preview` |
| `channel.release_tag` | Pinned monorepo tag when not following latest |
| `channel.follow_latest` | `true`: resolve latest non-prerelease for `stable`, allow prerelease for `preview` |
| `download.prefer_proxy` | `auto` \| `always` \| `never` |
| `download.auto_apply_on_boot` | Dedicated-server friendly reconcile on load (default `false`) |
| `pins[id].version` | Desired package version string |
| `pins[id].source` | `channel` \| `override` |
| `bootstrap` | Ids that must remain installable |

### Desired-version resolution

For each known plugin id (local install and/or manifest):

1. If `pins[id].source == "override"` → use `pins[id].version`.
2. Else use the version from the channel’s **plugins-manifest** for this platform.
3. If manifest has no id → keep local files; UI shows “not in channel”.
4. Bootstrap ids always required present; default version follows channel; override allowed; remove forbidden.

### Defaults when file missing

In-memory (optional first UI open may write file):

- `channel.name = "stable"`, `follow_latest = true`
- `prefer_proxy = "auto"`, `auto_apply_on_boot = false`
- `pins = {}`
- `bootstrap = ["core.plugin_manager", "core.vm"]`
- `channel.repo` = project’s canonical GitHub repo

### Cross-tag pin limitation (v1)

Override pin asset resolution order:

1. Current channel tag’s manifest.
2. If the version is not listed → error: switch channel/tag first.

v1 does **not** search the entire Releases history for an arbitrary old version without changing tag/channel.

## 5. CI, assets, and manifest

### Build fix (blocking)

`ds_add_dynamic_plugin` must `install(TARGETS ...)` into the install prefix `plugins/` directory so `cmake --target install` stages:

`Mod/bin64/<platform>/plugins/plugin_*.{dll,so,dylib}`

Existing `release.yaml` zipping `./Mod` then includes plugins without a separate packaging invention.

### Release assets (same monorepo tag)

| Asset | Role |
|---|---|
| `{windows,linux,macos}_Mod.zip` | Full mod + Injector + **plugins/** |
| `plugins-manifest.json` | Single cross-platform manifest (preferred over per-OS copies) |
| `plugin_<file_id>-<version>-<platform>.zip` | Per-plugin package (v1 recommended) |

`file_id` uses filesystem-safe names (`network_rpc`); logical id in manifest remains dotted (`network.rpc`).

### Manifest shape

```json
{
  "schema_version": 1,
  "repo": "fesil/DontStarveLuaJIT2",
  "release_tag": "v2.9.1",
  "mod_version": "2.9.1",
  "abi_version": "1",
  "generated_at": "2026-08-05T00:00:00Z",
  "plugins": [
    {
      "id": "network.rpc",
      "version": "1.0.0",
      "bootstrap": false,
      "lua_faces": ["plugins/network_rpc.lua"],
      "platforms": {
        "windows": {
          "available": true,
          "asset": "plugin_network_rpc-1.0.0-windows.zip",
          "sha256": "...",
          "module": "plugin_network_rpc.dll",
          "files": ["plugin_network_rpc.dll"]
        },
        "linux": { "available": false, "reason": "gum_win_only" }
      }
    }
  ],
  "bundle": {
    "windows": { "asset": "windows_Mod.zip", "sha256": "..." },
    "linux": { "asset": "linux_Mod.zip", "sha256": "..." },
    "macos": { "asset": "macos_Mod.zip", "sha256": "..." }
  }
}
```

### Version sources

| Field | Source of truth |
|---|---|
| `mod_version` / git tag | CMake `project(... VERSION ...)` + release tag |
| Per-plugin `version` | Extracted from source (`man.version` / Lua `version`) by generator script — no third manual list |
| `abi_version` | `DS_PLUGIN_ABI_VERSION` |

CI should fail or warn if extracted version ≠ staged meta (when meta is generated).

### Workflow increments (`.github/workflows/release.yaml`)

1. CMake install includes `plugins/`.
2. After install, run `tools/gen_plugins_manifest.py` (name indicative) over staged plugins + source versions → `plugins-manifest.json`.
3. Optionally zip each plugin as `plugin_<file_id>-<ver>-<platform>.zip` with `sha256`.
4. `publish-release` / `publish-preview` attach manifest + per-plugin zips alongside `*_Mod.zip`.
5. Preview tags remain `preview-${{ github.run_id }}`; manifest `release_tag` records the actual tag.

### Download URL rules

- Direct:  
  `https://github.com/<repo>/releases/download/<tag>/<asset>`
- gh-proxy wrap:  
  `{gh_proxy_base}/https://github.com/<repo>/releases/download/<tag>/<asset>`

`prefer_proxy`:

- `always` / `never`: fixed
- `auto`: short-timeout probe of direct GitHub asset URL; on failure/timeout retry via proxy; cache choice in-process for the session

No geo-IP database; connectivity is the signal.

### On-disk layout

- Primary: `<InjectorDir>/plugins/` (matches `DynamicPluginLoader::default_search_dirs`)
- Verify `sha256` before replace
- Write `*.download` / extract to temp → atomic replace when possible
- If Windows lock on mapped DLL: write `plugins/update_pending/` + `pending_ops.json`; on next process start, manager moves pending into `plugins/` **before** relying on updated modules for later work
- Sidecar **`plugin_*.meta.json`** (id, version, sha256) written by CI/packaging and by apply — preferred local version source without loading the DLL

### Bundle vs per-plugin

| Use case | Path |
|---|---|
| Fresh install / major base update | `{platform}_Mod.zip` |
| Plugin upgrade/downgrade | Per-plugin zip first |
| Fallback | Extract from monorepo zip (optional, may be disabled; large) |

## 6. Native API (`core.plugin_manager`)

### Plugin identity

| Field | Value |
|---|---|
| id | `core.plugin_manager` |
| phase | `EarlyNative` |
| options | `AlwaysOn` (bootstrap; not a modinfo business toggle) |
| support_reload | `false` |
| version | Own semver shipped with monorepo |

### Exported C API

```cpp
// Status / paths
const char* DS_LUAJIT_plugin_config_path();
const char* DS_LUAJIT_plugin_manager_status_json();

// Config
bool DS_LUAJIT_plugin_config_reload();
bool DS_LUAJIT_plugin_config_set_json(const char* json);
bool DS_LUAJIT_plugin_pin_set(const char* id, const char* version, bool is_override);
bool DS_LUAJIT_plugin_pin_clear(const char* id);

// Remote
bool DS_LUAJIT_plugin_fetch_manifest(const char* release_tag_or_null); // null = channel policy
const char* DS_LUAJIT_plugin_manifest_json();

// Apply
bool DS_LUAJIT_plugin_plan_apply_json(char* out, size_t n); // dry-run plan
bool DS_LUAJIT_plugin_apply(const char* id_or_null);       // null = full plan; sync v1
bool DS_LUAJIT_plugin_needs_restart();
```

v1 apply is **synchronous/blocking**. Failures return `false`; details in `status_json` / spdlog.

### `status_json` (UI primary model)

```json
{
  "config_path": ".../luajit_plugins.json",
  "channel": { "name": "stable", "release_tag": "v2.9.1", "follow_latest": true },
  "proxy": { "mode": "auto", "active": true, "base": "https://gh-proxy.com" },
  "needs_restart": false,
  "plugins": [
    {
      "id": "network.rpc",
      "local_version": "1.0.0",
      "desired_version": "1.0.0",
      "channel_version": "1.0.0",
      "pin_source": "channel",
      "loaded": true,
      "abi_ok": true,
      "platform_available": true,
      "state": "ok"
    }
  ],
  "last_error": null
}
```

`state` enum: `ok` | `missing` | `update_available` | `downgrade_available` | `pending_restart` | `unavailable` | `error`

`local_version` priority:

1. Sidecar `plugin_*.meta.json`
2. Else registered `PluginHost` manifest version if loaded
3. Else `unknown`

### Download pipeline

```text
resolve_channel_tag
  → GET plugins-manifest.json
  → plan: desired vs local per id
  → for each action:
       URL (github or gh-proxy)
       download → sha256
       extract to plugins/ or update_pending/
       write meta.json
  → needs_restart if any replace or pending
```

### Failure model

| Case | Behavior |
|---|---|
| Bad JSON / unknown schema_version | Log + defaults; no Injector crash |
| Network failure | `false` + `last_error`; UI retry |
| Checksum mismatch | Do not replace; keep old file |
| Single plugin fail | Do not roll back other successes; report partial |
| Bootstrap fail | Hard error in status; do not silent-continue as healthy |
| Version mismatch on disk vs pin | Warn in status; **do not** block game boot (fail-soft on semver) |
| ABI mismatch | Existing loader skip; independent of manager |

### Dependencies (implementation choice in plan)

- HTTP: prefer already-vendored/linked stack; otherwise WinHTTP on Windows + libcurl (or equivalent) elsewhere — avoid unnecessary new heavy deps
- JSON: existing nlohmann
- Zip: light library or platform tools; CI zip format fixed

## 7. Client UI

### Entry

In `Mod/modmain.lua` `AlwaysLoad` → `ModConfigurationScreen._ctor` when `_modname == modname`:

- Add action **「Plugin Manager」 / 「插件管理」** next to uninstall (same `dialog.actions:AddItem` pattern ~L497–523).
- Show on **all platforms** (unlike Windows-only uninstall).
- Without Injector / without manager exports: screen opens with “manager unavailable” + install/update guidance; no crash.

Secondary entry on `ModsScreen` is **out of v1** (avoid dual entry).

### Screen module

- `Mod/scripts/plugin_manager_screen.lua`
- `TheFrontEnd:PushScreen(...)`
- DST redux styling (`Screen`, `TEMPLATES`, scrolling list, `PopupDialogScreen`)
- Strings via existing `translate({ zh = ..., en = ... })`

### Information architecture

```text
Channel [stable|preview]  Tag  [Follow latest]
Proxy mode + active base   [Refresh]
────────────────────────────────────────
id | local | desired | state | actions (Pin / Get)
────────────────────────────────────────
[Apply All] [Reset pins to channel] [Close]
needs_restart → confirm restart dialog (no forced quit without confirm)
```

### Flows

1. Open → `config_reload` + `status_json`; best-effort `fetch_manifest`.
2. Change channel / follow_latest → write config → fetch → refresh desired.
3. Pin → `pin_set` / `pin_clear` within v1 cross-tag rules.
4. Apply / Get → `plugin_apply`; disable controls while running; refresh after.
5. `needs_restart` → `PopupDialogScreen`; user confirms quit/restart (same spirit as `require_restart` config patch).

### Dedicated server

- No UI.
- Ops: deploy `luajit_plugins.json`; optional `auto_apply_on_boot`; logs for plan/apply/errors.
- v1 does not require console Lua commands (optional later).

## 8. Testing

| Layer | What | How |
|---|---|---|
| CI package | `plugins/` present in install/zip | Shell path assertions in workflow or test job |
| Manifest tool | Versions, platform flags, sha256 | Fixture-based script tests |
| Config parse | schema, override vs channel, bootstrap | C++ tests under `tests/plugin/` style |
| Proxy URL | always/never/auto wrapping | Pure unit tests, no live network |
| Apply | bad sha256 keeps old file; pending path under lock simulation | Temp dir fixtures; mock HTTP where needed |
| Game integration | Optional: boot tokens when network + assets available | `SKIP` without game/network; never silent green without evidence |
| UI | Manual smoke checklist only | No UI automation frameworks |

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Cannot overwrite loaded Windows DLL | `update_pending/` + early boot move; UI restart |
| Manager missing | Bootstrap in monorepo zip; UI full-package guidance |
| GitHub rate limit / CN block | Asset direct links + gh-proxy; disk-cached manifest |
| Version triple drift (source / meta / manifest) | Single extractor script; CI consistency check |
| L0 bloat | All business logic in `core.plugin_manager` |
| Pin to missing asset | Plan validation before download |
| Preview vs stable confusion | UI labels prerelease; default stable + follow_latest |
| Large monorepo fallback | Prefer per-plugin zip; fallback optional |

## 10. Milestones

```text
M1  CI foundation
    - install() for dynamic plugins
    - release zip contains plugins/
    - gen_plugins_manifest + release attach
    - per-plugin zip + sha256

M2  Config + native skeleton
    - luajit_plugins.json read/write
    - core.plugin_manager register + status/pin APIs
    - meta.json sidecar
    - pending boot moves

M3  Download pipeline
    - manifest fetch, proxy auto, sha256, apply
    - auto_apply_on_boot

M4  Client UI
    - ModConfigurationScreen entry
    - PluginManagerScreen list/channel/pin/apply/restart

M5  Hardening
    - unit tests, CI gates, docs/plugin-system.md section
    - manual smoke checklist
```

**Order:** M1 unblocks real assets for M3; M2 can start after M1 install fix; M4 depends on M2/M3 APIs.

## 11. Open implementation details (plan, not design blockers)

1. Final HTTP client selection (WinHTTP vs existing curl).
2. Final unzip implementation.
3. Exact default repo string and tag naming (`v` prefix vs bare CMake version).
4. Whether first UI open always materializes `luajit_plugins.json` on disk.

## 12. Documentation touchpoints

| Doc | When |
|---|---|
| This spec | Design approval |
| `docs/superpowers/plans/2026-08-05-plugin-manager.md` | After spec approval (writing-plans) |
| `docs/plugin-system.md` | During implementation (operator + contributor section) |

## 13. Key code anchors (existing)

| Area | Path |
|---|---|
| Dynamic plugin CMake helper | `src/DontStarveInjector/CMakeLists.txt` (`ds_add_dynamic_plugin`) |
| Loader search dirs | `src/DontStarveInjector/core/DynamicPluginLoader.cpp` |
| ABI | `src/DontStarveInjector/core/PluginModuleAbi.hpp` |
| Manifest types | `src/DontStarveInjector/core/PluginTypes.hpp` |
| Release workflow | `.github/workflows/release.yaml` |
| `luajit_config` path pattern | `src/DontStarveInjector/config/sources/LuajitConfigFile.cpp` |
| UI action pattern | `Mod/modmain.lua` `AlwaysLoad` ~uninstall `actions:AddItem` |
| Local update API (reference only) | `DS_LUAJIT_update` in `GameRuntimeApis.cpp` |

## 14. Summary

Ship a **channel + override pin** plugin package manager as **`core.plugin_manager`**, driven by **`luajit_plugins.json`**, backed by **CI-published manifest and plugin assets**, with **GitHub + gh-proxy** download, **restart-safe** apply, and a **client Plugin Manager UI** entry on the existing mod configuration screen. PluginHost remains ABI/option-centric; the manager owns disk package versions end-to-end for client and dedicated server.
