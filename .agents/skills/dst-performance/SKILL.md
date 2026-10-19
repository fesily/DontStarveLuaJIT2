---
name: dst-performance
description: "Run and maintain this repository's tests/performance module for DST world generation, existing-save server/client startup, game Lua versus LuaJIT comparisons, and Windows ETW hotspot analysis. Use for performance profiles, benchmark interpretation, and server-load crash soaks; not for unrelated LuaJIT semantic tests or generic debugger work."
---

# DST Performance

Use the repository's existing measurement tools and preserve their evidence.
Locate the checkout containing this skill and `tests/performance/run.py`;
run commands from that repository root. Read its `AGENTS.md` and the relevant
sections of `tests/performance/README.md`. Treat current source and `--help`
as authoritative when flags or behavior have changed.

## Choose the Workload

| Request | Entry point |
| --- | --- |
| Generate a fresh world and measure map generation | `tests/performance/run.py --profile worldgen` |
| Generate a fresh world, then start a client | `tests/performance/run.py --profile startup` |
| Load an existing large save, then start a client | `tests/performance/stress_startup.py` |
| Repeat server-only save loads, including crash soaks | `tests/performance/server_load.py` |
| Analyze worldgen timelines and native samples | `tests/performance/analyze.py` |
| Attribute existing-save startup CPU samples and JIT traces | `tests/performance/startup_etw.py` |
| Verify ETW JIT symbol publishing independently | `tests/performance/verify_jit_symbols.py` |

Read [references/workflows.md](references/workflows.md) for build commands,
paired runs, ETW capture/analysis, and server-only loops. Reuse the scripts;
do not substitute synthetic timings or create another sampling implementation.
An analysis-only request can use existing captures without launching the game.

## Establish the Comparison

- Confirm the requested save, phases, VM groups, compiler modes, and baseline.
  A known local large-save example is
  `C:/Users/fesil/Documents/Klei/DoNotStarveTogether/191485686/StressTest`;
  verify it exists and prefer the user's current selection.
- `game=game` selects the game's embedded Lua 5.1, with the same injector
  present. Loading a LuaJIT DLL does not establish that JIT is enabled:
  use `--vm-jit LABEL=on|off` for worldgen or `--mode LABEL=on|off`
  for existing-save startup, and verify recorded status.
- Use `build_release.py` for hash-bound optimized Release VM/runtime evidence.
  Assertions, API checks, test diagnostics, sanitizers and debug CRT builds
  are unsuitable for performance comparisons. Do not fabricate receipts or
  bypass validation. `server_load.py` permits `DS_ALLOW_ASAN` only for
  explicitly requested diagnostic investigations; label those results.
- Keep toolchain, GC variant, runtime and workload settings comparable.
  Record source revisions, dirty state, hashes, missing mods and JIT tuning.
  An old baseline or rebuilt binary is not the current or original measurement.
- Read game paths from `cmake/GameDir.cmake` or the harness resolver. Do not
  edit that generated file. Use absolute VM/injector paths; confirm the exact
  successful attachment log to rule out fallback to a bundled DLL.

## Run Within the Intended Scope

Use unique output directories. Keep formal timing batches separate from ETW,
Lua sampling, and `jit.attach` diagnostics. Do not use the game's `newProfiler`
for LuaJIT measurements. For native hotspots use WPR/ETW; elevation is routed
through Windows `sudo` by the controller while games retain their normal token.
Do not replace failed ETW collection with thread suspension or invented data.

Run benchmark batches serially: they temporarily share `Winmm.dll`,
`luajit_config.json`, probe mods and ports. Let the existing context managers
restore shared files. Existing-save tests write temporary copies; preserve the
source manifest check and require explicit missing-mod allowances.
Only stop processes/session instances owned by the run. Do not use the
untracked global CDB/dump watchers as an implicit fallback.

Use `--instances 1` for comparable server-load timings; concurrency is useful
for crash soaks and introduces CPU/disk contention. Keep the requested number
of repetitions. On failure, preserve logs and evidence and inspect the cause
before retrying; do not silently discard failures or run an unbounded retry.
Collect nonempty dumps only from each run's own persistence tree before
cleanup; copying errors must preserve that tree. Avoid broad historical dump
scans. A successful non-reproduction is not proof of a crash fix.

## Interpret the Evidence

- Wall intervals use `perf_counter` at stdout observation and include log
  delivery latency, but not polling delay. Process CPU is actual OS time
  (`GetProcessTimes` on Windows); it includes all process threads/native work.
- Map timing sums `forest_map.Generate` attempts, including failed retries.
  It excludes earlier module loading and later entity injection/serialization.
  Fixed seeds do not guarantee identical work across different VMs; inspect
  retry counts and generation settings. The current default map size is
  `default`; do not describe it as huge without checking the selected profile.
- Server readiness spans Popen entry to the session identifier log.
  `run.py` client readiness is the smoke world-ready milestone.
  `stress_startup.py` requires `ThePlayer` and HUD; neither proves a rendered
  first frame. Its workflow spans server launch through client readiness,
  whereas `run.py` includes cluster setup. Holds/teardown are separate.
- Every round starts fresh processes. `--warmup` reduces launch/cache effects;
  it does not retain JIT traces between rounds. Do not claim warmed JIT
  execution without repeated work in one VM.
- Validate ETW losses, target PID, complete phase boundaries, matching native
  symbol sidecars and method lifetimes before attributing CPU. A sampled PC
  is a CPU weight, not elapsed wall time; stack presence does not prove a full
  unwind, and a JIT trace name gives its starting line rather than every
  instruction's Lua source line.
- Compare successful measured rounds using the runner's paired ratios and
  ranges, excluding warmups. `change_percent = (candidate/baseline - 1)*100`
  is an elapsed-time change; negative is faster. If reporting speedup use
  `baseline/candidate`. Keep failed runs and shutdown codes visible:
  existing-save startup success describes readiness, not clean shutdown.

Report workload and exact boundaries, artifact/output paths, sample counts,
VM/JIT/ETW verification, timing ratios and variation, CPU hotspots when
requested, and concrete limitations. Distinguish direct measurements,
inferences and unverified possibilities. Small trace shares alone do not
establish why JIT benefit is small; use phase/function attribution.

## Maintain the Module

For changes to measurement contracts, run
`python tests/performance/test_performance.py` and relevant harness tests.
Use the configured CTest `game_performance_unit`/`harness_unit` entries when
available. Run Python compilation and syntax-check changed Lua probes with
`loadfile` without executing game-dependent scripts. Scale real-game or
ETW validation to changed behavior; do not claim end-to-end validation from
unit tests alone. Preserve unrelated edits and diagnostic tools outside the
requested scope.
