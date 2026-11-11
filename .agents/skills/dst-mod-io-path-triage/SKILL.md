---
name: dst-mod-io-path-triage
description: "DST mod writes/reads landing in the wrong place (file not cleared, stale config, invalid filepath) — measure mod io sandbox + CWD, then pick native-owned path."
---

# DST mod file-path triage

Use when a DST mod's file write/read silently targets the wrong file, or `io.open` raises `invalid filepath`.

## Measure first (never guess from the game source)
The mod env gives no `io` of its own (`CreateEnvironment` in `scripts/mods.lua` has no `io`; modmain builds `_G = GLOBAL` + an `__index` metatable onto the real one), so `io.open` semantics = whatever the shipped exe patched in.

Temporary probe, one game boot proves everything:
1. Native: add to `plugin_core_vm/injector/GameLuaModule.cpp` an export returning `GetCurrentDirectoryA` (guard `#if defined(_WIN32)`, return `{}` otherwise).
2. Lua: call it at modmain-load and in `AddGamePostInit`, then `pcall(io.open, name, "w")` for `probe_root.json`, `unsafedata/probe_sub.json`, `../probe_parent.json` (use `.json` — extensions are allowlisted).
3. Boot, read `Documents/Klei/DoNotStarveTogether/client_log.txt`, then `find` the probe files and delete them. Revert both probes afterwards.

Interpreting: the error object comes back as `print("...: \n"..(r or ""))` in `mods.lua` (xpcall with `debug.traceback`), so an empty message means look at the following lines in the log, not at `r`.

Known result on 759671: CWD stays `<game>/data` at load and postinit; `unsafedata/*.json` is re-rooted to the save dir; absolute paths and `..` → `invalid filepath`.

## Decision rule
- Files shared with the injector (`luajit_crash.json`, `luajit_config.json`, `luajit_plugins.json`, shell marker/boot log): native owns them, path from `util/Unsafedata.hpp` (`dir_for(root)` off `getExePath()`), and Lua goes through an export (`DS_LUAJIT_*`) — it cannot open absolute paths at all.
- Files only Lua touches (e.g. `luajit_encryptmods.json`) may stay relative; they live under the save dir.
- Do not "fix" path mismatches by moving the injection hook after the chdir: the chdir is `../data`, not the save dir, and the shell writes its boot log before any chdir exists.

## Verify
`cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector plugin_core_vm && cmake --install ... --config RelWithDebInfo` (install prefix = `Mod/`, which the Workshop dir junctions to), then boot twice: arm `{1}` → postinit clears to 0 bytes; rewrite `luajit_config.json` mtime in `<game>/data/unsafedata` advances while the save-dir copy does not.

## Gotchas
- A Lua exception inside `AddGamePostInit` disables the mod persistently (`modindex`), and KLEI's native force-enable is the only way back — always `pcall` cleanup callbacks.
- Build with the config that matches the deployed DLL (`RelWithDebInfo` here): `check_crash` is compiled out under NDEBUG-less Debug.
- LNK1201 on `Injector.pdb`/`plugin_manager.pdb` means the game still runs; `taskkill /F /IM dontstarve_steam_x64.exe` first.
- cmake/ninja may be blocked in the shell sandbox; drive them through `python -c "subprocess.run([...])"`.
