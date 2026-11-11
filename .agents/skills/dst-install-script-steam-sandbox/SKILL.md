---
name: dst-install-script-steam-sandbox
description: Verify DontStarveLuaJIT2 install.ps1 / install.bat staging target and shell deploy in a fake steamapps sandbox (workshop vs mods branch) without touching the real game
---

# DST install-script sandbox verification

Purpose: prove `install.ps1` (and the packaged `install.bat`) stage to the right folder and deploy `Winmm.dll` into the right `bin64`, without touching the real Steam library.

## Layout facts

- Game root: `<library>\steamapps\common\Don't Starve Together`; `steamapps` is **two** parents up.
- Workshop content: `<library>\steamapps\workshop\content\322330\<item>` (item = `3444078585`).
- `install.bat` picks its destination from `%mod_root%`:
  - path contains `workshop\content\322330` → `..\..\..\..\common\Don't Starve Together\bin64` (same library)
  - else → `..\..\bin64`
- `install.ps1` target: workshop item dir if `<steamapps>\workshop\content\322330` exists, else `<game>\mods\<DSJ_MOD_FOLDER or DontStarveLuaJit2>`; existing target without `modinfo.lua` is refused.

## Procedure

1. Preconditions: `tasklist /FI "IMAGENAME eq dontstarve_steam_x64.exe"` and `...dontstarve_dedicated_server_nullrenderer_x64.exe` must both be empty — `install.bat` calls `taskkill /F`.
2. Build the sandbox with a `.ps1` file (shell one-liners with `$env:`/`;`/`Join-Path` quoting break the bash shim → write a script, run `powershell -NoProfile -File`):
   - `$sbx = "$env:TEMP\dsj-ws-test"`; `$lib = $sbx\steamapps`
   - `common\Don't Starve Together\bin64`, `common\Don't Starve Together\mods\DontStarveLuaJit2`
   - workshop case: `workshop\content\322330\3444078585\modinfo.lua` + `SENTINEL.txt` (sentinel must disappear after staging)
3. Run with overrides only (never let Steam discovery hit the real install):
   ```powershell
   $env:DSJ_GAME_DIR = "$sbx\steamapps\common\Don't''t Starve Together"   # note '' inside single quotes
   $env:DSJ_CHANNEL  = 'release'
   powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
   ```
   (`DSJ_REPO` default downloads the real release: ~17 s, no auth.)
4. Assert:
   - log line `target (workshop):` vs `target (local mod):`
   - `install.bat` prints `install shell -> ..\..\..\..\common\Don't Starve Together\bin64` (workshop) or `..\..\bin64` (mods)
   - `CHECK shell` present; `CHECK marker: … MISSING` is **expected** (marker is written by the shell at game boot)
   - sentinel wiped, `modmain.lua`/`Injector.dll` in the chosen target, the other target untouched.
5. Cases to cover: (a) `322330` exists, (b) `322330` absent → mods fallback, (c) item dir present without `modinfo.lua` → error, foreign file preserved.
6. Clean up: delete `builds/_sandbox` and `$env:TEMP\dsj-ws-test`; `git status --porcelain` to confirm no stray files.
