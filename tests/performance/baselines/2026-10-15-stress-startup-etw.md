# StressTest save startup with native LuaJIT ETW symbols

Date: October 15, 2026. Windows x64, DST build 756039. AMD Ryzen 9 7945HX,
16 cores / 32 logical processors.

In the two successful paired rounds, enabling JIT on LuaJIT reduces server
startup wall time by 8.56% and sequential server-plus-client startup by 3.94%.
Relative to the embedded game VM, JIT-on reduces these by 29.51% and 15.96%.
These are descriptive successful-startup results: the formal JIT-on group
only succeeds 2/3 and a separate warmup also crashes in JIT-triggered GC.
Native ETW confirms compiled code executes; remaining samples include
substantial game EXE work, GC, allocation and table/string operations.

## Workload and controls

The runner copies the existing cluster at
`C:\Users\fesil\Documents\Klei\DoNotStarveTogether\191485686\StressTest`
to an isolated temporary persistence directory for each run. Only Master and
one offline joining client are started. Caves, Shipwrecked and Volcano shards
are not started. The client always selects Wilson.

The source Master snapshot is `2C324D0593F1126C/0000005330`, approximately
12.76 MB. The loaded world reports 74,986 entities, cycles=4401 and
world_size=huge. The experiment loads that existing save; it does not generate
a new world. The complete source cluster manifest is hashed before and after
each batch.

Five enabled content mods are missing locally:
`2287303119`, `3424065137`, `3535964924`, `3561785531`, `3671964429`.
They are disabled only in the temporary modoverrides.lua. The LuaJIT Lua mod
`3444078585` is also disabled there to avoid its later JIT, GC and profiler
policy. Its bootstrap options are overridden because native bootstrap reads
that row even when its Lua mod is disabled.

The other eleven content mods are retained. Workshop directories are
temporarily mounted with junctions when absent from the game mods directory.
Chinese++ Pro reports a missing base runtime library, and Island Adventures
reports missing animation assets. Loading succeeds with these warnings. The
results describe this common modified configuration, not an exact restoration
of every mod in the original cluster.

## Release builds

The formal timing VM is a fresh build of clean LuaJIT revision `f1eb755a`
(the native ETW runtime switch). The injector and plugins are the existing
FastHook implementation, rebuilt in optimized Release before the test.
Assertions, API checks, test diagnostics and sanitizers are disabled.
Hash-bound build receipts include the actual compile commands.
The game-VM baseline uses the embedded retail Lua 5.1 under the same injector
environment; it is not a separate no-injector experiment.

- VM: `builds/game-performance-vm-etw-switch-release/luajit/lua51DS.dll`.
- VM SHA256:
  `35f5ef18f6b5fb83cd5ca04f59b6b3a668e782749849218195e2f0b79aca28d4`.
- VM full revision: `f1eb755aa6741ebfd59240bde96955631e7b2cd4`.
- Runtime:
  `builds/game-performance-runtime-etw-release/src/DontStarveInjector/Release/Injector.dll`.
- Runtime injector SHA256:
  `0306ea55e225b1619b0ffc98f2f28da9cd26b0c93476426f56028e8fc0e13a09`.

The early GAME_INIT entry sets the requested JIT state using a one-use wrapper
around the framework's initial jit.off(). It immediately restores the original
function. Startup milestones verify the compiler and ETW publishing state.
The delayed BEFORE_MAIN log is explicitly marked replayed=true and is not used
as an ETW phase boundary.

Formal timing disables native symbol publishing with jit.profile.etw(false).
Diagnostic captures enable it before main.lua. The jit.profile sampling
start/stop APIs, trace callbacks and the game's newProfiler are never used.

Each sample starts fresh processes and VMs. Game and JIT-off warmups completed
in the first timing batch. Its JIT-on warmup crashed; an independent JIT-on
retry then completed and serves as that group's successful warmup. These
samples warm filesystem and signature caches, not JIT traces in later
processes. The restarted formal batch has three measured rounds per group
and reverses group order each round. No warmup or retry is included in its
summary.

## Measurement boundaries

| Metric | Interval |
| --- | --- |
| Server wall | Popen entry to first session-identifier-ready stdout line |
| Client wall | Popen entry through frontend, assets, connection and loading to a local player with HUD |
| Server startup CPU | GetProcessTimes kernel+user total at server readiness, all process threads |
| Client startup CPU | GetProcessTimes kernel+user total at client readiness, all process threads |
| Server CPU during client startup | Server CPU difference immediately before client launch to client readiness |
| Workflow wall | Server Popen entry to client readiness, including the sequential handoff |
| Workflow CPU | Server total CPU at client readiness plus client total CPU at that point |

Preparation/copying, ETW start/stop, shutdown and cleanup are outside the wall
intervals. Stdout boundaries include log delivery latency. CPU clocks do not
include waiting and can differ from elapsed time because they include all
threads. This is a desktop benchmark with background applications, not an
isolated laboratory machine.

## Formal timing results

The restarted batch attempted all nine runs. Game and JIT-off succeeded 3/3;
JIT-on succeeded 2/3, with its final server process crashing before readiness.
The batch deliberately exits nonzero. No slow successful sample is discarded.
The two successful JIT-on samples cannot establish a stable end-to-end speedup
for a configuration that sometimes fails to start.

Values below are medians of successful runs, in seconds:

| Metric | Game Lua 5.1 (n=3) | LuaJIT off (n=3) | LuaJIT on (n=2) |
| --- | ---: | ---: | ---: |
| Server wall | 78.561 | 59.464 | 53.589 |
| Client wall | 83.623 | 82.216 | 80.594 |
| Workflow wall | 162.239 | 142.397 | 134.417 |
| Server startup CPU | 77.375 | 57.688 | 52.172 |
| Client startup CPU | 81.109 | 79.578 | 79.078 |
| Server CPU during client startup | 20.641 | 13.672 | 12.602 |
| Workflow CPU | 179.063 | 152.328 | 144.086 |

All individual wall times are retained:

| Round / metric | Game | JIT off | JIT on |
| --- | ---: | ---: | ---: |
| 0 server | 73.552 | 57.752 | 54.156 |
| 0 client | 84.064 | 79.436 | 80.748 |
| 1 server | 78.561 | 59.464 | 53.022 |
| 1 client | 83.623 | 82.801 | 80.440 |
| 2 server | 82.391 | 69.348 | crashed |
| 2 client | 82.036 | 82.216 | not launched |

The following changes use geometric means of ratios within the same successful
round, not ratios of the three different group medians. Negative means less
time/CPU. Comparisons involving JIT-on have only two paired rounds:

| Comparison | Pairs | Server wall | Client wall | Workflow wall | Workflow CPU |
| --- | ---: | ---: | ---: | ---: | ---: |
| JIT off / game | 3 | -20.62% | -2.12% | -10.96% | -13.78% |
| JIT on / game | 2 | -29.51% | -3.88% | -15.96% | -18.35% |
| JIT on / JIT off | 2 | -8.56% | -0.62% | -3.94% | -3.48% |

The successful samples show a useful server-side VM replacement benefit and a
smaller incremental compiler benefit. Client startup stays around 80 seconds
in all groups, so it dilutes the server gain in the sequential workflow. The
small sample count, variable server times and JIT-on failures preclude a
precise reliability or steady-state speedup claim. This benchmark does not
measure gameplay tick throughput after startup.

## Native ETW analysis

WPR records Windows kernel SampledProfile events and native StackWalk records,
process/thread lifetimes, image mappings, custom phase markers and native
Microsoft-JScript method load/unload/rundown events. Only the WPR controller
elevates, through Windows sudo. Game processes use the normal user token.

The analyzer uses OpenTrace/ProcessTrace. It joins stack fragments with their
original QPC and TID, observes thread reuse and uses StackWalk's explicit PID
to recover kernel-exit samples emitted after Thread/End. It resolves JIT PCs
against PID, context, source/method generation, address range and method
lifetime. Unloaded or reused code addresses do not retain old trace names.
Rundown duplicates do not count as new methods. Native VM labels come from a
sidecar bound to the exact measured DLL hash.

The original diagnostic JIT-on capture was cross-checked against xperf's CSV
consumer: all 247,358 startup sample events have identical PID, TID, PC and
Count multisets. Clock calibration spread is 0.7 microseconds. No target
StackWalk key remains unmatched. This verifies sample decoding/ownership,
not complete stack unwinding or symbol accuracy for every frame.

Sample shares are self CPU weights, not wall-time percentages or percentages
of Lua instructions compiled. JIT names identify trace entry source lines,
not every instruction represented by a trace. VM code labels can include
inlined code and padding. Subsystem label sums omit shared helper costs.
The game EXE has no verified private function names in this analysis; its
embedded Lua 5.1 interpreter and engine work cannot be separated in the game
baseline. No speculative names are assigned to EXE PCs.

### Latest warmed captures

Both diagnostic runs use the same `f1eb755a` Release DLL as formal timing, with
native publishing enabled before main.lua, cached bootstrap signatures and
Wilson selected. Both reach the startup endpoint. The JIT-on server later
crashes outside that endpoint; see the stability section.

Both ETLs have zero lost events and buffers. Clock calibration spread is
0.6 microseconds and unmatched target StackWalk keys are zero. Stack presence
is 99.98-99.99%; a present stack is not necessarily a complete unwind.

Self CPU sample percentages, restricted to each process's startup interval:

| Process / mode | Sample weight | Game EXE | LuaJIT VM DLL | Generated JIT |
| --- | ---: | ---: | ---: | ---: |
| Server, JIT off | 63,271 | 38.38% | 40.46% | 0% |
| Server, JIT on | 59,693 | 41.33% | 28.57% | 4.80% |
| Client, JIT off | 81,910 | 72.83% | 6.85% | 0% |
| Client, JIT on | 80,198 | 74.53% | 4.92% | 0.47% |

The server's game-EXE self weights are similar (24,281 vs 24,668) while its VM
DLL self weight falls from 25,601 to 17,055. Generated code executes, so this
is not simply a globally disabled compiler. That does not establish how much
Lua work is compiled or whether every hot path is compiled well.

Selected native label totals, as percentages of all CPU samples in that
process interval:

| Labels | Server off | Server on | Client off | Client on |
| --- | ---: | ---: | ---: | ---: |
| GC | 7.02% | 7.79% | 1.52% | 1.54% |
| Parser/lexer | 1.13% | 1.21% | 0.67% | 0.63% |
| Trace compiler/recorder/cache management | 0% | 1.22% | 0% | 0.11% |
| Trace exit/restore | 0% | 1.05% | 0% | 0.06% |

GC aggregates gc_*, lj_gc_* and propagatemark. Parser labels include lex_*,
expr*, bcemit_*, fs_*, lj_parse* and the sampled parser helpers. Compiler
labels include rec_*/lj_record_*, asm_*/lj_asm_*, lj_opt_*, IR, mcode, trace
management and snapshot construction, excluding exit/restore. Exit/restore
includes lj_vm_exit_*, lj_trace_exit, lj_snap_restore and snap_restoreval.
These are selected self-label totals, not inclusive subsystem timings.

Three server table-read labels (lj_BC_TGETV, lj_BC_TGETS and lj_tab_getinth)
fall from 6,781 samples (10.72%) to 979 (1.64%). The server GC labels instead
remain around the same absolute weight: 4,441 off and 4,653 on.
lj_str_new is also almost unchanged, 876 vs 879. The compiler reduces repeated
table-read work while substantial native game work, GC, allocation and shared
helpers remain. Parser/lexer self samples are small in this startup interval;
the data does not support parsing as the main remaining CPU cost.

In JIT-on server startup, the largest compiled trace-entry source groups are
Performance Pack modmain.lua:1 (1,176 samples), its 9.lua:1 (179),
scripts/mods.lua:268 (153), scripts/modindex.lua:146 (139),
scripts/mods.lua:240 (82), and scripts/modindex.lua:317 (72).
These are trace entry labels, especially coarse for single-line mod sources;
they are not whole-function inclusive profiles.

There are 44,054 distinct method lifetimes committed before server readiness
and 5,612 before client readiness. The server emits 55,436 MethodLoad records
over the complete server-plus-client capture, and 54,461 MethodUnload records;
the maximum trace number reaches 1000. These events show substantial code
lifecycle turnover. They do not directly report aborts, count complete cache
flushes, or establish that cache capacity is a performance bottleneck. No
maxtrace setting was changed for these runs.

Client startup is dominated by EXE and other native/system modules in both
LuaJIT modes. That supports a substantial floor outside the measured VM code,
consistent with the small client timing difference. Private EXE symbols would
be required to separate exact engine, asset, graphics, networking and other
native costs; this report does not infer those from module names alone.

## Initial capture caveat

The first `b1db1513` JIT-on diagnostic capture paid cold signature/bootstrap
work before mod initialization: 47.71 seconds on the server, with
function_relocation.dll accounting for 73.70% of that phase's CPU samples.
The client also paid substantial cold bootstrap work. The later cached
JIT-off server reached that milestone in 2.67 seconds.

That first JIT-on capture is useful for validating native symbol decoding, but
its complete startup duration is not a JIT throughput comparison. Its bot also
predates the fixed-Wilson policy. Formal timings and subsequent warmed
diagnostics are kept separately.

## Stability observation

The first JIT-on, ETW-off warmup exited with `0xC0000005` while loading
Performance Pack, before the server was ready. This is a real process crash,
not a timing-parser failure. It is not included in successful timing
statistics. An independent retry of the same Release build and settings
completed (server 59.619 seconds, client 82.128 seconds).

CDB maps RIP to RVA `0x48815`, `gc_traverse_thread+0x45`, using the hash-bound
Release code map. The faulting instruction reads `[rdx+8]` with `rdx=0`.
The valid native frames are `gc_traverse_thread`, `propagatemark`,
`lj_gc_step`, `lj_gc_step_jit`, then dynamically generated code. Export-only
debugger names such as filter/mktime are not the correct private code labels.

The small WER dump does not retain the relevant Lua heap/stack allocation or
generated code bytes, so it establishes the crash site, not the earlier write
or a root cause. The ETW switch commit is not established as the cause.
No VM core changes or crash workaround were applied for this benchmark.
The dump is copied to
`builds/game-performance-20261015-stress-timing/warmup-0-jit_on-crash.dmp`;
debugger transcripts are `builds/stress-jit-on-crash-cdb.log` and
`builds/stress-jit-on-crash-detail.log`.

The final formal JIT-on run also crashed, with server PID 54432 at 17:09:11
local time. This time the mapped RIP is RVA `0x484df`, `gc_sweep+0x9f`.
The code reads the object's type byte, subtracts four and dispatches through
the free-function table. EAX is `0xfffffffc`, consistent with a zero type byte;
the indexed indirect call faults. The native callers are `lj_gc_step+0x219`
and `lj_gc_step_jit+0x51`, followed by generated code.

Both crashes occur in JIT-triggered GC, at different operations. They do not
prove a shared root cause, nor distinguish an earlier bad stack value, corrupt
object header or premature lifetime termination. The formal crash is retained
at `builds/game-performance-20261015-stress-timing-v2/round-2-jit_on-crash.dmp`
and `builds/stress-jit-on-crash-round2-cdb.log`.

Startup success must also be distinguished from a normal process exit. In
the independent successful retry, the server later exits `0xC0000409` during
cleanup, with a CFileWriterThread illegal-worker-termination message. This may
depend on how the harness stops the process and is not counted as a startup
failure. In the final JIT-on ETW run, the endpoint is reached but the server
subsequently exits `0xC0000005`; its dump is in
`builds/game-performance-20261015-stress-etw-final/round-0-jit_on-after-ready-crash.dmp`.
CDB stops in `lj_err_unwind_win+0x10f` with repeated SEH exception frames, so
that small dump does not establish the original exception. Its transcript is
`builds/stress-jit-on-crash-etw-cdb.log`.

The formal successful JIT-on runs both exit normally (server code 0). Game
clients and some game-VM servers exit code 1 when terminated by the harness.
Raw final exit codes are in the console transcripts for this batch; the
runner has been updated to retain PID and process_exit_codes in future
results.json files. These observations do not change the defined startup
endpoints or convert post-endpoint failures into successful lifecycle tests.

## Artifacts

Paths below are relative to the repository.

| Directory under builds/ | Contents |
| --- | --- |
| game-performance-20261015-stress-timing-v2 | Restarted formal timing without optional diagnostics |
| game-performance-20261015-stress-timing | Initial warmups, including one JIT-on crash |
| game-performance-20261015-stress-jit-retry | Independent successful JIT-on retry |
| game-performance-20261015-stress-etw-v2 | Original cold JIT-on ETL and exact xperf sample cross-check |
| game-performance-20261015-stress-etw-rest | Initial game/JIT-off native captures |
| game-performance-20261015-stress-etw-final | Latest warmed JIT-off/on ETLs, native analysis and loss statistics |

Every batch retains logs, timestamped observations, results.json, results.csv,
source identity and source-integrity evidence. Failed smoke/deployment runs
remain in separate build directories and are excluded from timing.

## Validation and cleanup

All 28 measurement/analysis unit tests pass, the changed Python modules
compile, and git diff --check passes. The measured VM still matches its
Release receipt. The live source cluster still matches the captured manifest
after all runs. All four current batches record source_unchanged=true.

WPR is idle and no launched game process remains. Temporary Workshop
junctions are removed; the pre-existing luajit2 mod junction is retained.
The original Winmm.dll and luajit_config.json bytes are restored and
SHA256-verified:

- Winmm.dll:
  `b80c339b8db61ac5e9ac8dd189c1bdb1d0be1c8b7aaf5c0d591f28c3bd978847`.
- luajit_config.json:
  `a28e00f10b6ef324527bd279fa6b8624691c3f0512cc947db1946f73638305cd`.

No VM core or Gum source was changed and no commit was made.
