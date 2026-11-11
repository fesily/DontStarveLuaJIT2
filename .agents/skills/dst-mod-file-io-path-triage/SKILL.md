---
name: dst-mod-file-io-path-triage
description: DST mod writes/reads the wrong file after a game update (log says cleared/written but file unchanged); probe io sandbox root vs native CWD; not generic mod debugging
---

# DST mod file-IO path triage (injector C++ <-> mod Lua)

## Symptom
A mod prints that it wrote/cleared a file, but the file the C++ side reads is unchanged. Or injection is skipped with `skip inject, find crash content` / an assert about a missing config.

## Fast checks (no build needed)
1. Find BOTH candidate files before theorizing:
   - `<game>/data/unsafedata/<name>` (native/shell path)
   - `<Documents>/Klei/DoNotStarveTogether/<steamid>/client_save/unsafedata/<name>` (mod path)
   `find` both trees; compare size + mtime against the boot time in `client_log.txt`.
2. Read `bin64/DontStarveInjector_{client,server}.log` (spdlog, level err) — it states whether injection ran (`skip inject, find crash content`) and exposes config rejects.
3. Remember `backup/client_log/client_log_<HH-MM-SS>.txt` = **previous** session (named at rotation). Correlate game version via its `Version:` / `Steam AppBuildID:` lines when suspecting a Klei change.
4. An `io.open` failure that raises instead of returning nil+msg (empty `error calling gamepostinit` message) means the game ships a custom io: DST 759671 rejects absolute paths and `../` with `invalid filepath`.

## Definitive probe (one boot, ~40 s)
Temporarily add:
- native: a `GameInjector.DS_LUAJIT_probe_cwd` export returning `GetCurrentDirectoryA`;
- Lua: in `modmain` at load and in a `AddGamePostInit`, print the native CWD and `pcall(io.open, name, 'w')` for `probe_root.json`, `unsafedata/probe_sub.json`, `../probe_parent.json` (`.json` because the sandbox allowlists extensions).
Boot, then `find` the probe files. Measured DST 759671 client: CWD = `<game>/data` at both points, `unsafedata/...` → **save dir**, root and `../` → `invalid filepath`. Revert the probe afterwards.

## Design rule that follows
- Files shared with the mod (sentinel, configs the mod writes) must live under `<save dir>/unsafedata`; native resolves it as `GetClientSaveDir(steamid)/unsafedata` (`util/Unsafedata.{hpp,cpp}` in DontStarveLuaJIT2) and creates it at Inject time.
- Shell-owned files (injector marker `ds_luajit_injector.path`, `ds_luajit_boot.log`) stay in `<game>/data/unsafedata`: written before the game's main, unaffected by the sandbox.
- Do NOT try to "align CWD by moving the hook after the chdir": the CWD is already the same on both sides, the sandbox re-roots Lua paths.

## Build/verify on this workstation
- bash cannot exec `C:\Program Files\...` binaries → build through `python -c "import subprocess; subprocess.run([r'...\cmake.exe','--build','builds/ninja-multi-vcpkg','--config','RelWithDebInfo','--target','Injector','plugin_core_vm'])"`, then `--install` (stages into `Mod/`).
- RelWithDebInfo is the dev/game config (NDEBUG ⇒ crash guard active).
- `LNK1201` on a `.pdb` ⇒ kill `dontstarve_steam_x64.exe` first.
- Launch/quit a client headlessly: `start "" "steam://rungameid/322330"`, wait for a NEW file in `backup/client_log/`, then poll `client_log.txt` for `ModIndex: Load sequence finished`; verify via `[lc_probe] TOKEN LG_CLIENT_INJECT_*` lines, then `taskkill /F /IM dontstarve_steam_x64.exe`.
