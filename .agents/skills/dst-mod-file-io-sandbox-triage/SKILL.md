---
name: dst-mod-file-io-sandbox-triage
description: "DST mod file I/O breaks after a game update (log printed but file unchanged, 'invalid filepath', writes landing in the save dir) or when native and mod must share a state file; includes the in-game probe/verify loop"
---

# DST mod file I/O triage (759671+ io sandbox)

## Symptoms that point here
- Mod logs "cleared/wrote X" but the file is unchanged (mtime untouched) - the write hit a different file.
- `[C] in function 'open'` + `invalid filepath` inside a mod callback -> the game aborted the mod callback (`error calling gamepostinit`), and DST marks the mod bad/disabled for that session.
- A state file exists twice: `<game>/data/unsafedata/` (native) and `<...>/client_save/unsafedata/` (mod).

## Establish the facts before designing a fix
1. Compare mtimes/sizes of both candidate files with `ls -la --time-style=full-iso` + `xxd`; the one with a fresh mtime is where the write actually went.
2. Correlate with logs: `%USERPROFILE%/Documents/Klei/DoNotStarveTogether/client_log.txt`. Backup naming gotcha: `backup/client_log/client_log_<HH-MM-SS>.txt` is named for the ROTATION time, so its content belongs to the session that ENDED then - check `Version:`/`Steam AppBuildID:` inside to know which build actually wrote what.
3. Confirm behaviour with a throwaway probe (revert it afterwards): a native `GameInjector.DS_LUAJIT_probe_cwd()` lambda returning `GetCurrentDirectoryA`, plus Lua `pcall(io.open,...)` attempts on `probe_root.json`, `unsafedata/probe_sub.json`, `../probe_parent.json`, printing `(ok, fp, err)`; then `find` the files.

Measured on 759671: relative `unsafedata/x.json` lands in `<Documents>\Klei\DoNotStarveTogether\<steamid>\client_save\unsafedata\`; absolute and `../` fail with `invalid filepath`; process CWD stays `<game>\data` at modmain load and at AddGamePostInit. So CWD alignment of native and Lua is impossible - the mod root is the sandbox's, not the CWD's.

## Design rules that survive game updates
- One owner per file. Files native consumes (`luajit_config.json`, crash sentinel) must be written by native through an exported API; Lua only passes values.
- Files only Lua consumes may stay relative (`unsafedata/...`) - they land per-user-save, which is self-consistent.
- Shell-side artifacts (`ds_luajit_injector.path`, `ds_luajit_boot.log`) must stay at `<game>/data/unsafedata` (written by Winmm before the game/SteamID exist, and documented by install scripts).
- Wrap cleanup calls in `pcall` in `AddGamePostInit`: an exception there disables the whole mod for that session.

## Verify in the real game (fast loop)
1. `cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector plugin_core_vm` then `cmake --install builds/ninja-multi-vcpkg --config RelWithDebInfo` (install prefix = repo `Mod/`; the workshop path is a junction to it).
   - `cmake` is missing from bash PATH and blocked as a direct path; launch it via `python -c "subprocess.run([r'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe', ...])"`.
   - A running game locks the build-tree PDB -> `LNK1201`; `taskkill /F /IM dontstarve_steam_x64.exe` first.
2. Launch: `start "" "steam://rungameid/322330"` (Steam must be running; SteamClientLaunch gates the crash guard).
3. Wait for a NEW file in `backup/client_log/` (rotation = this session started), then poll `client_log.txt` for `ModIndex: Load sequence finished`, sleep ~5s, then read the evidence: `[lc_probe] TOKEN LG_CLIENT_INJECT_OK|_MISSING`, `bin64/DontStarveInjector_client.log` (`skip inject, find crash content`), and target file mtimes.
4. Always kill the client afterwards; it also blocks the next link.
