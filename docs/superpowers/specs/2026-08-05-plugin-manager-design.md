# Plugin Manager Design

**Date:** 2026-08-05  
**Status:** Accepted (amended: fully optional, non-core)  
**Scope:** Optional Injector plugin package manager (upgrade/downgrade), unified pin config, GitHub download with CN gh-proxy, CI plugin packages, client UI entry.

## Amendment (2026-08-05)

**`plugin.manager` is not a core dependency.**

- May be absent: Injector, PluginHost, and all business plugins must work unchanged.
- Presence is pure upside (in-game/UI download + pin apply).
- Absence ⇒ **manual install** remains first-class (copy from `{platform}_Mod.zip` or per-plugin zip).
- No other plugin may `depends` / `requires_services` on manager APIs.
- Lua bindings always soft-fail via `host_service` when the module is missing.

## 1. Context and problem

### Current state

| Layer | Today | Gap |
|---|---|---|
| Plugin semantic version | Free-form `PluginManifest::version` / Lua `version` | Host never compares or pins versions |
| Module ABI | Major string `"1"` | Hard gate only; orthogonal to semver |
| Config | Cascade `ResolvedConfig` + modinfo options | No version-pin file |
| CI | `{platform}_Mod.zip` monorepo only | Often no `plugins/` in zip (`install()` missing); no manifest / per-plugin assets |
| Download | Local `install.bat` only | No GitHub client / gh-proxy |
| UI | Config screen action bar | No Plugin Manager screen |

### Main contradiction

Plugins declare versions, but CI does not publish plugin packages. A manager without assets cannot upgrade/downgrade.

### Locked decisions

| Decision | Choice |
|---|---|
| Version unit | Hybrid: monorepo release channel + optional per-plugin override pins |
| Apply surface | Client writes config; client **and** dedicated server can download when manager present |
| Pin storage | Independent `luajit_plugins.json` (not modinfo) |
| Download owner | Native services `DS_LUAJIT_plugin_*` (only if module loaded) |
| Release assets | Monorepo zip + `plugins-manifest.json` + per-plugin zips |
| Implementation home | **Optional** dynamic plugin `plugin.manager` (not L0, not required) |
| Core dependency | **No** — missing manager is a supported production path |
| v1 scope | End-to-end when present; manual path when absent |

## 2. Goals and non-goals

### Goals (v1)

1. Channel + optional per-plugin pin upgrade/downgrade **when manager is installed**.
2. Unified `luajit_plugins.json` for client and dedicated server (ignored if manager absent).
3. GitHub Releases download; gh-proxy when direct probe fails.
4. CI stages `plugins/`, publishes manifest + per-plugin zips (usable for **manual** install too).
5. Client UI entry; soft message if manager missing.
6. Dedicated server can `auto_apply_on_boot` **only if** manager module is present.

### Non-goals

- Manager as core / L0 / hard dependency of Injector or any business plugin
- Runtime FreeLibrary hot-swap / multi-version side-by-side
- Plugin store / third-party registries / code-signing PKI
- ABI major auto-migration
- Pins inside modinfo / modoverrides
- UI automation frameworks
- Blocking boot because manager or any pin is missing

### Success criteria

- **With manager deleted:** game + Injector + other plugins behave as today (manual plugin files only).
- **With manager present:** pin → download → restart → disk version matches pin.
- CI ships installable plugin assets (manual **or** manager).
- CN path uses gh-proxy after failed direct probe.

## 3. Architecture

### Optional `plugin.manager` dynamic plugin

```text
Client UI (always)
  → host_service(DS_LUAJIT_plugin_*)  → nil/false if module absent
  → if present: pin/download/apply UI

plugin.manager (OPTIONAL MODULE)
  → luajit_plugins.json, manifest cache, HTTP, zip extract
  → writes plugins/ or plugins/update_pending/

L0 DynamicPluginLoader (always)
  → apply_pending_plugin_updates(dir) BEFORE LoadLibrary  // no manager needed
  → scan plugin_*; missing manager is not an error

PluginHost / business plugins
  → no depends on plugin.manager
```

### Optional presence rules

| Rule | Detail |
|---|---|
| Dependency class | Optional enhancement only |
| Missing module | Skip like any absent `plugin_*`; no Injector error |
| Lua | Soft-fail service lookup; UI explains manual install |
| Manual path | Copy plugins from release assets; no JSON required |
| Shipping | Monorepo zip **may** include manager for convenience; may be deleted |
| Self-update | Manager may pin/update/remove **itself** when present (no special bootstrap lock) |
| First install of manager | Manual (full zip or `plugin_manager-*-<platform>.zip`) |

### System boundaries

| System | Responsibility |
|---|---|
| modinfo / cascade | Feature toggles |
| `luajit_config.json` | Identity / AlwaysEnableMod / DisableJITWhenServer |
| `luajit_plugins.json` | Channel + pins — **read only by manager when present** |
| PluginHost / loader | ABI + options; independent of manager |
| `plugin.manager` | Package versions on disk when present |
| L0 pending moves | Filesystem-only pre-load; safe no-op if empty |

### Inject ordering

```text
Inject:
  RegisterCoreOptionSchema
  DynamicPluginLoader::load_all:
    for each plugins dir: apply_pending_plugin_updates(dir)  // L0
    scan + LoadLibrary + init   // plugin_manager optional
  refresh_cascade_after_plugins
  resolve → load_phase(EarlyNative)
    // if plugin.manager loaded && auto_apply_on_boot → network apply
```

Sticky modules are not reloaded in-process; successful replace ⇒ `needs_restart`.

## 4. Config model: `luajit_plugins.json`

### Path

- Default: `<game>/data/unsafedata/luajit_plugins.json`
- Override env: `DS_LUAJIT_PLUGINS_CONFIG`
- Not part of Klei cascade
- File may be absent forever if manager unused

### Schema (v1)

```json
{
  "schema_version": 1,
  "channel": {
    "repo": "fesily/DontStarveLuaJIT2",
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
  "prefer_present": []
}
```

| Field | Meaning |
|---|---|
| `schema_version` | Unknown → log + defaults; never crash Injector |
| `channel.*` | Repo / stable\|preview / tag / follow_latest |
| `download.prefer_proxy` | `auto` \| `always` \| `never` |
| `download.auto_apply_on_boot` | Default `false`; only runs if manager loaded |
| `pins[id]` | Override or channel tracking |
| `prefer_present` | Soft preference list when applying channel (default **empty**). **Not** a core gate; missing ids never block boot |

> Renamed from earlier draft `bootstrap` to avoid implying core bootstrap. Empty by default. Do **not** put `plugin.manager` here as required.

### Desired-version resolution

1. `pins[id].source == "override"` → that version  
2. Else channel manifest version for platform  
3. Manifest missing id → keep local; UI “not in channel”  
4. `prefer_present` only affects plan “should fetch if missing” soft preference — never hard-fail Injector  

### Defaults when file missing

- `channel.name=stable`, `follow_latest=true`
- `prefer_proxy=auto`, `auto_apply_on_boot=false`
- `pins={}`, `prefer_present=[]`
- `repo=fesily/DontStarveLuaJIT2`

### Cross-tag pin (v1)

Override asset must appear on **current** channel tag manifest; otherwise error “switch channel/tag first”. No full-history search.

## 5. CI, assets, and manifest

### Build fix

`ds_add_dynamic_plugin` must `install(TARGETS … DESTINATION plugins)` so CI zips include modules for **manual** install even without the manager.

### Release assets

| Asset | Role |
|---|---|
| `{platform}_Mod.zip` | Full mod + Injector + plugins/ (manual baseline) |
| `plugins-manifest.json` | Catalog for manager **and** humans |
| `plugin_<stem>-<ver>-<platform>.zip` | Per-plugin package (manual or manager) |

Logical id: `plugin.manager`  
Module stem: `plugin_manager`  
Asset example: `plugin_manager-1.0.0-windows.zip`

### Manifest shape

Same as prior design: global manifest with per-platform `available` / `asset` / `sha256` / `module` / `files`, plus `bundle` entries for Mod zips. Field `bootstrap` on plugin entries is **removed** or always `false` (prefer `prefer_present` only in client config, not CI force).

### CI workflow increments

1. install includes plugins/  
2. `tools/gen_plugins_manifest.py` + meta + per-plugin zips  
3. merge platform partials → `plugins-manifest.json`  
4. publish with Mod zips  

### URL / landing

- Direct GitHub release asset URL; gh-proxy wrap under auto/always  
- Land in `<InjectorDir>/plugins/`; locked files → `update_pending/`  
- Sidecar `plugin_*.meta.json` for local version without LoadLibrary  

## 6. Native API (`plugin.manager`, optional)

### Identity

| Field | Value |
|---|---|
| id | `plugin.manager` |
| module | `plugin_manager` |
| phase | EarlyNative |
| options | AlwaysOn **if loaded** |
| support_reload | false |
| core dependency | **No** |

### Services (registered only when module loads)

```cpp
const char* DS_LUAJIT_plugin_config_path();
const char* DS_LUAJIT_plugin_manager_status_json();
bool DS_LUAJIT_plugin_config_reload();
bool DS_LUAJIT_plugin_config_set_json(const char* json);
bool DS_LUAJIT_plugin_pin_set(const char* id, const char* version, bool is_override);
bool DS_LUAJIT_plugin_pin_clear(const char* id);
bool DS_LUAJIT_plugin_fetch_manifest(const char* release_tag_or_null);
const char* DS_LUAJIT_plugin_manifest_json();
bool DS_LUAJIT_plugin_plan_apply_json(char* out, size_t n);
bool DS_LUAJIT_plugin_apply(const char* id_or_null);
bool DS_LUAJIT_plugin_needs_restart();
```

GameInjector bindings: **always** via `host_service`; missing ⇒ nil/false/empty string policy consistent with other optional plugin services.

### status_json / pipeline / failure

Unchanged from prior design except:

| Case | Behavior |
|---|---|
| Manager module absent | No services; UI manual-install message; boot OK |
| prefer_present missing | Soft plan entry only |
| Semver mismatch | Status warn; **never** block boot |
| Network / checksum | Fail apply only; keep old files |

## 7. Client UI

- Entry on this mod’s `ModConfigurationScreen` (all platforms).
- Manager missing: open dialog — “插件管理器未安装，请从 Release 手动复制 plugins 或安装 plugin_manager 包”.
- Manager present: full list / channel / pin / apply / restart confirm.
- No second ModsScreen entry in v1.
- Dedicated: no UI; optional JSON + auto_apply only if module present.

## 8. Testing

| Layer | What |
|---|---|
| CI | plugins/ non-empty after install |
| Manifest tool | fixture test |
| Pin config / proxy URL / pending | C++ unit tests |
| **Absence** | Document + optional test: Inject path does not require manager target; Lua bindings soft-fail |
| UI | Manual smoke: with and without `plugin_manager` DLL |

## 9. Risks

| Risk | Mitigation |
|---|---|
| Loaded DLL lock | update_pending + pre-load L0 move |
| Manager missing | **Supported** — manual install |
| L0 bloat | Only pending moves in L0; HTTP/pin in optional plugin |
| Accidental hard dep | CI/review: grep other plugins for `plugin.manager` / `DS_LUAJIT_plugin_` requires |

## 10. Milestones

```text
M1 CI foundation (install + manifest + zips) — valuable alone for manual install
M2 Optional plugin.manager skeleton + pin config + pending
M3 Download / proxy / apply
M4 Client UI (soft-absent)
M5 Hardening + docs + absence checklist
```

## 11. Open implementation details

1. HTTP: WinHTTP (Win) + curl (else)  
2. libzip extract  
3. Tag naming (`v` prefix)  
4. Whether UI first open writes default JSON  

## 12. Docs

- This spec  
- Plan: `docs/superpowers/plans/2026-08-05-plugin-manager.md`  
- `docs/plugin-system.md` operator section (manual **and** manager paths)

## 13. Summary

Optional **`plugin.manager`** owns channel/override package updates via **`luajit_plugins.json`** and CI assets. **Absence is supported**; manual install from release packages remains the baseline. Injector/PluginHost/business plugins never depend on the manager.
