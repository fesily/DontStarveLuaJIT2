# StressTest JIT-on crash reproduction retry

Date: October 16, 2026, Asia/Hong_Kong.

Six sequential server-plus-client startups completed without reproducing the
previous GC crash. All six reached both startup endpoints, passed VM/JIT/ETW
verification, and recorded server exit code 0. Each client recorded code 1
when stopped by the existing harness after readiness. No new nonempty game
dump or DST WER dump was observed.

This is a negative reproduction result, not evidence that the bug is fixed.
The script remains a workload that previously triggered a crash, rather than
a deterministic reproducer.

## Build identity

The two historical Release build directories were absent when this retry
started. They were rebuilt with the existing `build_release.py --runtime`
workflow before running the game. The LuaJIT source was clean at
`f1eb755aa6741ebfd59240bde96955631e7b2cd4`, matching the previous source revision.
The injector/plugins were rebuilt from the current root working tree.
This retry is not a replay of the exact October 15 DLL bytes.

Assertions, API checks, test diagnostics and sanitizers were disabled; the
runner validated the hash-bound Release receipts and compilation commands.
No LuaJIT core or Gum source was edited for this retry.

| Binary | SHA256 |
| --- | --- |
| `builds/game-performance-vm-etw-switch-release/luajit/lua51DS.dll` | `4dcadf56c2c55e94c9c96a50c8b8dc138d2691ba1b3a1fefd553a714f7f213cf` |
| `builds/game-performance-runtime-etw-release/src/DontStarveInjector/Release/Injector.dll` | `531fd34ecce3a437b5e1b9cf232c8e1e68703a0b28cfff92125b7b74fe3bec98` |

Build log: `builds/stress-repro-release-rebuild-20261016.log`.

## Workload

The existing `tests/performance/stress_startup.py` loaded a fresh temporary
copy of the StressTest Master save each time, then launched one offline client.
The loaded world reported 74,986 entities and cycles=4401. JIT was explicitly
enabled before main.lua and ETW publishing was disabled. No `--etw` capture,
Lua sampling, trace callbacks or game newProfiler was enabled.

Both batches used this command, with a different unused output directory:

```powershell
python -u tests/performance/stress_startup.py `
  --cluster-source C:\Users\fesil\Documents\Klei\DoNotStarveTogether\191485686\StressTest `
  --injector builds/game-performance-runtime-etw-release/src/DontStarveInjector/Release/Injector.dll `
  --lua builds/game-performance-vm-etw-switch-release/luajit/luajit.exe `
  --vm jit_on=builds/game-performance-vm-etw-switch-release/luajit/lua51DS.dll `
  --mode jit_on=on --repeat 3 --warmup 0 `
  --allow-missing-mod 2287303119 `
  --allow-missing-mod 3424065137 `
  --allow-missing-mod 3535964924 `
  --allow-missing-mod 3561785531 `
  --allow-missing-mod 3671964429 `
  --output builds/stress-dump-repro-20261016-1105 `
  *> builds/stress-dump-repro-20261016-1105.console.log
```

The second output directory was `builds/stress-dump-repro-20261016-1114`,
with console output in `builds/stress-dump-repro-20261016-1114.console.log`.
Both batches disabled the five explicitly allowed missing content mods and
the LuaJIT Lua mod in the temporary configuration, as in the previous workload.

## Results

Wall times are seconds. Server and client intervals run from their own launch
to their respective ready markers. Workflow runs from server launch to client
readiness, excluding shutdown.

| Attempt | Server PID | Client PID | Server | Client | Workflow | Server exit | Dumps |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 75552 | 30964 | 97.06 | 127.84 | 224.95 | 0 | 0 |
| 2 | 89192 | 40868 | 56.80 | 79.30 | 136.39 | 0 | 0 |
| 3 | 22620 | 99580 | 55.66 | 82.69 | 138.77 | 0 | 0 |
| 4 | 12668 | 67768 | 57.76 | 81.14 | 139.24 | 0 | 0 |
| 5 | 28684 | 79204 | 57.92 | 81.52 | 139.60 | 0 | 0 |
| 6 | 53948 | 15960 | 54.10 | 82.61 | 137.19 | 0 | 0 |

The first launch paid cold signature/bootstrap work before mod initialization.
These timings document the reproduction attempts; this was not a paired
performance benchmark.

Raw evidence is retained in both output directories as `results.json`,
`results.csv`, per-process logs and timestamped observations.

## Dump retention and cleanup

The runner now copies nonempty `.dmp` and `.mdmp` files from each run's own
temporary persistence tree before deleting it. Saved relative paths appear
in `runs[].crash_dumps`; a copy failure preserves the temporary tree and
records `dump_collection_errors` and `preserved_persist`.
Collection runs after process shutdown and does not change game startup.
It does not search unrelated folders or count historical dumps as new crashes.

The 28 existing performance tests and Python syntax check passed. A separate
temporary fixture verified that a nonempty dump survives cleanup and an empty
dump is ignored. Fixture files were removed and are not reproduction artifacts.

Both batches recorded `source_unchanged=true`. No DST process remained after
the second batch. The following shared game files matched their pre-run hashes:

- `bin64/Winmm.dll`:
  `ecbee535657ec8d1b686a5e4568e839f05d5b27502e1b629e9f69d2763456526`.
- `data/unsafedata/luajit_config.json`:
  `5c17a54b1c4ea148ee113b4052555eddef889ae45b47f726c154c90ba991cc86`.
