# Commands and Evidence

Run from the repository root. These PowerShell examples use the module's
ordinary Release output paths. Resolve actual files before launching; older
ETW experiments used other build-directory names. Output directories must be
new. Read current `--help` and the relevant README section if options differ.

## Release Builds

```powershell
python tests/performance/build_release.py `
  --build-dir builds/game-performance-vm-release `
  --runtime --runtime-build-dir builds/game-performance-runtime-release

$perfVm = (Resolve-Path builds/game-performance-vm-release/luajit/lua51DS.dll).Path
$perfLua = (Resolve-Path builds/game-performance-vm-release/luajit/luajit.exe).Path
$perfInjector = (Resolve-Path builds/game-performance-runtime-release/src/DontStarveInjector/Release/Injector.dll).Path
$perfBatch = Get-Date -Format 'yyyyMMdd-HHmmss'
```

To build another revision, use `--source PATH/TO/luajit` and a separate
`--build-dir`. VM output contains `.performance.json` and on Windows
`.symbols.json` sidecars. Runtime evidence is `performance-runtime.json`.
Reuse matching artifacts when appropriate; do not rebuild automatically for
an analysis-only request. Rebuilding changes artifact identity even if the
source revision is unchanged.

## Fresh World Comparisons

```powershell
python tests/performance/run.py --profile worldgen `
  --injector "$perfInjector" `
  --vm game=game --vm "jit_off=$perfVm" --vm "jit_on=$perfVm" `
  --vm-jit jit_off=off --vm-jit jit_on=on `
  --repeat 3 --warmup 1 --output "builds/worldgen-$perfBatch"
```

`run.py` automatically adds `game=game` if no embedded VM group was supplied.
Order reverses each round. To measure generated-world server/client startup
instead, use `--profile startup`. Compiler mode options here affect map
generation only; do not infer full client startup JIT mode from them.
Profiles under `tests/performance/profiles/` determine size, seed and limits.
Use `--seed` for a seed override. Change map size only when it serves the
requested workload, and record it as a changed configuration.

For worldgen hotspots, use a separate output and add `--sample-native`.
Add `--sample-lua` for VM-state/stack and require timing, or
`--jit-diagnostics` for trace callbacks/aborts when that attribution is needed.
These options alter timing. Analyze with:

```powershell
python tests/performance/analyze.py "builds/worldgen-etw-$perfBatch"
```

WPR CPU collection and native LuaJIT symbol publishing are separate switches.
The worldgen runner does not guarantee that `jit.profile.etw(true)` was called;
check the current probe and capture before promising native JScript trace
names. The `--jit-diagnostics` stdout range path remains a distinct mechanism.
For publishing semantics and standalone validation, read the README's
"JIT symbols in WPA / PerfView" section and
`verify_jit_symbols.py --help`.

## Existing Save Startup

Select and verify the user's source cluster, then set `$perfSave`:

```powershell
$perfSave = 'C:/Users/fesil/Documents/Klei/DoNotStarveTogether/191485686/StressTest'
python tests/performance/stress_startup.py `
  --cluster-source "$perfSave" --injector "$perfInjector" --lua "$perfLua" `
  --vm game=game --vm "jit_off=$perfVm" --vm "jit_on=$perfVm" `
  --mode jit_off=off --mode jit_on=on `
  --repeat 3 --warmup 1 --output "builds/startup-$perfBatch"
```

This loads only the existing Master snapshot, with Wilson as the client bot.
It excludes Caves/Shipwrecked/Volcano and disables the LuaJIT Lua mod in the
temporary configuration. Missing Workshop content fails unless each ID is
explicitly allowed with `--allow-missing-mod ID`. Report that configuration
change; do not import an old machine-specific allowance list automatically.

The timing path disables ETW publishing before main.lua where supported and
verifies JIT/ETW state at milestones. For native diagnostics, run a separate
batch with `--etw --repeat 1 --warmup 0` and a new output. It starts WPR before
the server and stops after client readiness; it enables the LuaJIT publisher.

```powershell
python tests/performance/startup_etw.py `
  "builds/startup-etw-$perfBatch/round-0-jit_on-native-samples.json"
```

`--validate-csv` cross-checks the native kernel consumer against xperf
PC/TID/Count samples. `--csv-samples` instead selects the alternate xperf
consumer; these modes are mutually exclusive.

Native records join SampledProfile/StackWalk by QPC/TID and thread lifetime.
JIT attribution includes PID, context, generation, address and lifetime.
Require zero lost events/buffers and verify the captured DLL's hash-bound
symbols. Do not fix missing symbols by guessing nearest exported functions.

## Server-Only Repetition

```powershell
python tests/performance/server_load.py `
  --cluster-source "$perfSave" --injector "$perfInjector" `
  --vm "$perfVm" --lua "$perfLua" --jit on `
  --instances 1 --rounds 20 --output "builds/server-load-$perfBatch.json" `
  *> "builds/server-load-$perfBatch.console.log"
python tests/performance/run_report.py "builds/server-load-$perfBatch.console.log"
```

Use the repetition count requested by the user; 20 is only an example.
Normal shutdown executes the close/GC path and a nonzero exit fails a round.
`--stop-mode kill` intentionally removes that path and changes what is tested.
`DS_ALLOW_ASAN` is a diagnostic VM bypass, not performance validation.
Do not use it to make benchmark receipts pass.

Output includes per-round `.logs`, VM confirmation and exit codes. Dump
destinations include batch, instance and round; copy errors retain
`preserved_persist`. Native diagnostic wrappers are not part of this runner.

## Outputs and Failures

- Worldgen and existing-save startup: `results.json`, `results.csv`, per-process
  logs and optional observations/captures. Summaries exclude failed runs and
  warmups, so inspect `runs` as well as summary groups.
- Worldgen analysis: `hotspots.json`. Startup ETW: `.analysis.json`,
  `.jit-events.json`, export receipts/logs, statistics and image mappings;
  CSV is produced when requested.
- Native recordings: raw `.etl` plus `*-native-samples.json` linking targets
  and boundaries. Use `results.json` for VM provenance.
- Existing-save startup: require `source_unchanged=true`. Inspect
  `process_exit_codes` separately from startup success; client shutdown after
  readiness can record code 1 without invalidating the measured startup.
- `--keep-going` retains failures while finishing groups; it still exits
  nonzero if any startup failed. Missing game handling differs by runner:
  `run.py` uses harness skip semantics, while save/server-load CLIs require
  their game binaries. A skipped run is not a measured sample.

When collection fails, inspect the run log and controller/export receipts.
Stop or cancel only the owned `DsPerf-<UUID>` WPR instance. Preserve partial
artifacts, nonempty dumps and any retained persistence path before retrying.
Keep analysis artifacts together with their matching binary and symbols.
