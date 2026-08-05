# Task 10 Report: Client UI (soft-absent)

**Status:** DONE  
**Branch:** feature/plugin-manager  
**Commit:** `7a6a541f7f339fba91eb48cbb2e273f889b055b0`

## Summary

Client Plugin Manager entry on this mod’s `ModConfigurationScreen` for **all platforms**. Soft-degrades when `GameInjector` plugin-manager exports are missing: popup with manual install guidance. When present: usable v1 screen for refresh / list / pin / apply / restart confirm.

## Files

| Path | Action |
|------|--------|
| `Mod/scripts/plugin_manager_screen.lua` | Create — screen + helpers (`manager_available`, manual popup, open entry) |
| `Mod/modmain.lua` | Modify — AlwaysLoad action-bar button for this mod only; all platforms |

## Behavior

### Entry (`modmain` AlwaysLoad)

```text
if _modname == modname then
  add Plugin Manager button  -- all platforms
  if os_is_windows then
    uninstall button (existing)
  end
end
```

### Soft absence

```lua
manager_available():
  inj = GameInjector
  inj and inj.DS_LUAJIT_plugin_manager_status_json
  and pcall(status_json) returns non-nil
```

| Case | UI |
|------|-----|
| No GameInjector / no export / status nil / call error | `PopupDialogScreen` with zh/en manual install (Mod.zip / `plugin_manager-*-{platform}.zip` / `plugins/`) |
| status_json present | `PushScreen(PluginManagerScreen)` |

### PluginManagerScreen (v1)

- Title: Plugin Manager / 插件管理
- Channel / tag / proxy (from status JSON) + last_error / plugin count
- Scrolling list: `id`, local, desired, state, pin source
- **Refresh** → `config_reload` + `fetch_manifest(nil)` + rebuild from `status_json`
- **Apply All** → `plugin_apply(nil)`; surface `last_error`; if `needs_restart` confirm Quit/`DoRestart`
- **Pin** → `InputDialogScreen` version entry → `pin_set(id, ver, true)`
- **Clear Pin** → `pin_clear(id)`
- **Back** pops screen
- JSON via `json` / `require("json")` + defensive `pcall`
- `translate({zh,en})` for user-facing strings; DST redux `TEMPLATES` / `PopupDialogScreen` / `InputDialogScreen`

## Verification

| Check | Result |
|-------|--------|
| `luajit` `loadfile` `plugin_manager_screen.lua` | OK |
| `luajit` `loadfile` `modmain.lua` | OK |
| Unit smoke: `manager_available` nil/export/nil-status/json/throw | OK |
| In-game with DLL | Manual (checklist below) |
| In-game without DLL | Manual (checklist below) |

## Manual smoke checklist

### Without `plugin_manager` module

1. Remove / rename `plugins/plugin_manager*.dll` (or `.so`) under injector dir.
2. Launch client; open this mod’s configuration screen.
3. Confirm **Plugin Manager / 插件管理** button is present (all platforms).
4. Click button → popup with manual install instructions (not a crash).
5. Cancel; other mod options still work; uninstall (Windows) still present.

### With `plugin_manager` module

1. Restore module; restart client.
2. Open this mod’s configuration → **Plugin Manager**.
3. Full screen opens; channel/proxy line visible; list populates (or empty).
4. **Refresh** reloads config / tries manifest fetch; list updates; errors surface in status line / dialog.
5. Select a row → **Pin** → enter version → OK; row shows override pin after refresh.
6. **Clear Pin** restores non-override desired.
7. **Apply All** (may no-op / network fail offline); last_error shown on failure.
8. If apply sets needs_restart → restart/quit confirm dialog appears.
9. **Back** closes to config screen.

## Notes

- Manager remains optional; UI never hard-requires the native module.
- Dedicated servers: no UI path (existing design).
- Button only for this mod (`_modname == modname`), not other mods’ config screens.
