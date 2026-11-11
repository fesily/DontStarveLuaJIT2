---
name: dst-large-save-server-load-soak
description: "Run a DST existing-save server-only load soak (50+ rounds) with the repo performance module; covers Debug/Release VM selection, evidence bypass, shutdown timeout, and interruption cleanup."
---

# DST Large-Save Server-Load Soak

Use for repeated server-only loads of a large existing DST save (crash soak, startup timing) in `DontStarveLuaJIT2`. For generic performance interpretation, follow the `dst-performance` skill; this only adds the large-save pitfalls.

## Prerequisites

- Repo root is the checkout containing `tests/performance/`.
- Save example: `C:/Users/fesil/Documents/Klei/DoNotStarveTogether/191485686/StressTest` (Master/save ~247 MB, 74,986 entities, 4,401 cycles).
- Missing Workshop mods must be allowed explicitly. Current StressTest list:
  `2287303119 3424065137 3535964924 3561785531 3671964429` (pass one `--allow-missing-mod` each; `3444078585` is disabled by the harness).
- Confirm the VM file and its build configuration before running.

## Evidence rules

- Release VM needs a hash-bound `<name>.performance.json`; otherwise `validate_release` rejects it.
- A Debug/ninja-multi-vcpkg VM (e.g. `builds/ninja-multi-vcpkg/luajit/Debug/lua51DS.dll`, installed as `Mod/deps/lua51DS.dll`) runs only with `DS_ALLOW_ASAN=1`; results are marked `diagnostic=true`.
- `DS_ALLOW_ASAN` bypasses only VM evidence, NOT `validate_runtime`: the injector must still have `performance-runtime.json`. If the perf runtime dirs were deleted, rebuild before running.
- Rebuild Release VM/runtime when needed. `cmake`/`ninja` are not on the default shell PATH; use VS 18's bundled tools and vcvars. Example wrapper:

```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
set "PATH=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
cd /d C:\Users\fesil\DontStarveLuaJIT2
python -u tests/performance/build_release.py --runtime --build-dir builds\game-performance-vm-release --runtime-build-dir builds\game-performance-runtime-release
```

## Run

`server_load.py` supports `--shutdown-timeout` (default 120 s). Do not remove it: `LogProcess.stop` otherwise caps the graceful close at `min(15, T_SHUTDOWN)`, and this save needs ~26 s, so every round is falsely failed with `exit_code=1` and `server failed during shutdown`.

```powershell
$env:DS_ALLOW_ASAN = "1"   # only for a Debug/diagnostic VM
python -u tests/performance/server_load.py `
  --cluster-source C:\Users\fesil\Documents\Klei\DoNotStarveTogether\191485686\StressTest `
  --injector builds/game-performance-runtime-release/src/DontStarveInjector/Release/Injector.dll `
  --vm C:\Users\fesil\DontStarveLuaJIT2\Mod\deps\lua51DS.dll `
  --lua builds/ninja-multi-vcpkg/luajit/Debug/luajit.exe `
  --jit on --instances 1 --rounds 50 --timeout 900 --shutdown-timeout 180 `
  --allow-missing-mod 2287303119 --allow-missing-mod 3424065137 `
  --allow-missing-mod 3535964924 --allow-missing-mod 3561785531 `
  --allow-missing-mod 3671964429 `
  --output builds/server-load-<label>.json *> builds/server-load-<label>.console.log
```

Output and its `.logs` directory must not already exist. One round is ~180 s for the Debug VM (ready ~61-65 s after the first round). Run a 2-round smoke before committing to 50.

## Stop at a boundary

To stop before the next round, watch the console for the count of `^\[load\] srv0 ` lines and kill the python runner immediately after the next line appears. The following round begins with a multi-second save copy, so no game process is normally orphaned; verify anyway.

On SIGKILL the context managers never unwind. Manually:

- kill `dontstarve_dedicated_server_nullrenderer_x64.exe` processes whose command line contains `ds_load_`;
- remove the newest `%TEMP%/ds_load_0_*` tree only (older `ds_load_*` trees can be preserved prior evidence);
- remove `<game>/mods/ds_startup_probe`;
- restore `data/unsafedata/luajit_config.json` `modmain_path` to `C:\Users\fesil\DontStarveLuaJIT2\Mod\modmain.lua` (the original bytes exist only in runner memory, so they are lost);
- the original `bin64/Winmm.dll` bytes are also memory-only; the file remains the harness shell. The next harness run replaces and re-restores it, so state converges, but report the hash left behind.
