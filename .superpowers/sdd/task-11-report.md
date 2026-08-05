# Task 11 Report: Docs + absence hardening

**Status:** DONE  
**Branch:** feature/plugin-manager  
**Commit:** `docs: optional plugin manager and manual install path` on `feature/plugin-manager`

## Summary

Documented manual install as the first-class path and `plugin.manager` as optional upside in `docs/plugin-system.md` §13. Ran grep guards proving no other plugin hard-depends on manager. Spec already **Accepted** (optional/non-core). Absence checklist recorded in docs + this report.

## Files

| Path | Action |
|------|--------|
| `docs/plugin-system.md` | Modify — inventory row, key paths, deploy list, new **§13** (manual first, optional manager, soft absence, restart, checklist) |
| `.superpowers/sdd/task-11-report.md` | Create — this report |
| `.superpowers/sdd/progress-plugin-manager.md` | Modify — Task 11 complete |

Spec (no change needed): `docs/superpowers/specs/2026-08-05-plugin-manager-design.md` already  
`**Status:** Accepted (amended: fully optional, non-core)`.

## Docs coverage (§13)

| Subsection | Content |
|---|---|
| 13.1 Manual install | `{platform}_Mod.zip` `plugins/`, per-plugin zips, `update_pending/` (L0, no manager) |
| 13.2 Optional manager | `luajit_plugins.json`, channel/pin, gh-proxy, UI entry, GameInjector APIs |
| 13.3 Soft absence | Non-core guarantee; no `depends` / `requires_services` on manager |
| 13.4 Restart | Apply ⇒ `needs_restart`; no FreeLibrary hot-swap |
| 13.5 Checklist | Absence hardening items |

Also: native inventory row for `plugin.manager`; deploy list marks `plugin_manager.dll` optional; key paths include `plugin_manager/` + `PluginPendingUpdates.*`.

## Grep guard evidence

### Guard: no other plugin sources reference manager APIs

```text
rg -n "plugin\.manager|DS_LUAJIT_plugin_" src/DontStarveInjector --glob '!**/plugin_manager/**'
→ (no matches outside plugin_manager under DontStarveInjector)

rg -n "plugin\.manager|DS_LUAJIT_plugin_|plugin_manager" Mod/plugins
→ (no matches)
```

### Guard: all production depends / requires_services

| Location | Declaration | Target |
|---|---|---|
| `plugin_sim_lagcomp.cpp` | `depends` / `requires_services` | `core.vm` / `ds_core_vm_get_game_lua_context` |
| `plugin_debug_profiler.cpp` | `soft_depends` / `soft_requires_services` | `core.vm` / core.vm services |
| `Mod/plugins/network_entity.lua` | `depends` | `network.rpc` |
| `Mod/plugins/jit_runtime.lua` | `soft_depends` | `jit.tailcall`, `debug.profiler` |
| All other Lua plugins | empty depends | — |
| `plugin_manager` itself | none on others for hard deps | AlwaysOn optional |

**Result:** No `depends` / `soft_depends` / `requires_services` / `soft_requires_services` entry names `plugin.manager` or `DS_LUAJIT_plugin_*`.

### Soft UI references (expected, not hard deps)

- `Mod/scripts/plugin_manager_screen.lua` — soft `manager_available()` + popup if exports nil
- `Mod/modmain.lua` — AlwaysLoad button → `open_plugin_manager()`

These call GameInjector exports only after nil-check / `pcall`; missing module ⇒ manual install popup, not `MissingService`.

### Self-contained manager module (allowed)

All `DS_LUAJIT_plugin_*` definitions and `register_service` / `register_game_injector_export` live under `src/DontStarveInjector/plugins/plugin_manager/` only.

## Absence hardening checklist

```text
[ ] Delete plugin_manager.dll → dedicated/client still injects
[ ] Other plugins load; no MissingService for manager APIs
[ ] UI shows manual guidance
[ ] Restore DLL → manager functions
[ ] Manual copy of a business plugin zip still works without manager
```

Static evidence for items 2 and 5:

- Item 2: no other plugin lists manager in `requires_services` (grep above) ⇒ Host cannot mark `MissingService` for manager APIs.
- Item 5: L0 `install(TARGETS … DESTINATION plugins)` + per-plugin zips + `update_pending/` apply without manager (Tasks 1–3); documented as manual baseline.

In-game items 1/3/4 remain manual smoke (same as Task 10 UI checklist).

## Verification

| Check | Result |
|-------|--------|
| Docs §13 present; manual first | OK |
| Spec Status Accepted | OK (pre-existing) |
| Grep: no hard dep on manager | OK (evidence above) |
| Checklist in docs + report | OK |
| Commit message | `docs: optional plugin manager and manual install path` |

## Notes

- Manager remains fully optional / non-core.
- Anti-patterns avoided: no new depends, no boot-fail on missing pins, no HTTP in L0 docs as required.
