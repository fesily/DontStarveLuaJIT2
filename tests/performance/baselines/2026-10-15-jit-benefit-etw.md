# LuaJIT benefit investigation with ETW: October 15, 2026

JIT compilation is enabled and compiled code executes in the measured workload.
The remaining CPU work includes substantial game executable time, VM string and
C API operations, garbage collection, and trace exit/restore paths. The sampled
parser code is a small part of the measured Generate interval. This does not
establish that initial script loading outside Generate is cheap.

The default trace cache fills and flushes during generation. Raising maxtrace
removes the observed full flushes, but the two-round experiment does not show a
consistent throughput benefit. No production JIT settings or VM core code were
changed.

## Setup and measurement boundaries

- Windows x64, game build 756039, local date October 15, 2026.
- Root HEAD `75a4429ed3578e9b40ee107a22d891031b68757d`, including the existing
  uncommitted FastHook runtime. LuaJIT HEAD
  `deaa4ed76fbd099db4002d8e2c0a44d853e71cc3`, clean submodule.
- The same hash-verified optimized Release DLLs are used throughout. Assertions,
  API checks, test diagnostics and sanitizers are disabled.
- LuaJIT DLL SHA256:
  `f84c2734477250325a9b171f0fd72d9fe5bb0aec8f599462c604fc9546c10fdf`.
  Injector SHA256:
  `0db17cb97d82f453aea4bafc338d88f669af5544a1d6e7922ddbe0da1ceedd96`.
- Offline Master, SURVIVAL_TOGETHER, seed 123456, world_size=default. The
  generator begins with a 425 x 425 extent. One successful attempt per sample.
- Map wall and process CPU intervals cover entry through return of
  `forest_map.Generate`, as observed on stdout. Native generator calls inside
  Generate are included. Prior module loading, later entity injection and save
  serialization are excluded. Process CPU uses GetProcessTimes.
- Each sample starts a fresh process and VM. Warmups reduce initial
  launch/filesystem effects; they do not retain JIT traces for measured samples.
- The game's newProfiler is excluded. It was not enabled in any run.

## Timing without optional diagnostics

Directory: `builds/game-performance-20261015-jit-benefit-timing`.
One warmup and three measured rounds per group; all 12 runs passed.
No ETW, jit.profile, trace callbacks or require instrumentation in this batch.
Actual JIT status is verified at each map entry.

| Measured round | Game Lua 5.1, seconds | LuaJIT off, seconds | LuaJIT on, seconds |
| --- | ---: | ---: | ---: |
| 1 | 2.690158 | 1.920844 | 1.638192 |
| 2 | 2.501451 | 2.294324 | 1.846794 |
| 3 | 5.323527 | 3.845360 | 1.756020 |
| Median | 2.690158 | 2.294324 | 1.756020 |

These are descriptive results, not a stable speedup estimate. The third round
has large slowdowns in game and JIT-off groups; startup timings also vary.
Background CPU load was high during this investigation. Paired ratios and raw
CPU timings remain in results.json, but a precise improvement claim would
overstate the control provided by this small batch. No outlier was deleted.

The previous interpreter-only comparison is retained separately in
[the FastHook report](2026-10-15-fast-hook.md). Its `jit=false` runs do not
measure the benefit of enabling the JIT compiler.

## Real Windows CPU attribution

`--sample-native` records WPR ETW SampledProfile events and kernel-collected
SampledProfile stacks. Only the WPR helper elevates through Windows sudo; the
game uses its normal token. Each recording has a unique owned instance name
and start/stop receipts. There is no SuspendThread/GetThreadContext fallback.

The final WPR profile records process/thread events, image mappings, CPU
samples/stacks and a custom boundary provider. It does not collect CSwitch or
ReadyThread events. It cannot establish waiting-time causes.

The exporter uses xperf for trace statistics, image mappings and range-limited
CPU/stack CSV, with stack time shifting. Windows OpenTraceW/ProcessTrace decode
the string-only map and phase markers. CPU weights use SampledProfile Count,
filtered by the target PID, WorldSim TID and the ETW Generate interval. Markers
still include stdout delivery latency.

Compiled-code attribution uses recorded trace address/size, commit time and
flush validity intervals. Private Release code labels come from the original
object files relinked to a separate DLL with /MAP and the original link flags,
including /MANIFEST:EMBED. All executable-section RVAs, sizes and bytes match
the measured DLL; its .text SHA256 is
`4c5b1a16793be98d5264e20875c462c1df4be7237a4cc29d4ed10b5a79734fd4`.
The measured DLL was not replaced. The resulting 1707 code regions are
hash-bound to that DLL in its `.symbols.json` sidecar.

Code labels can include padding and inlined instructions. They are not private
source-line PDB symbols. The analyzer verifies the captured group's binary
hash, including when several compared DLLs have the same basename.

Two batches without jit.profile provide these WorldSim self weights:

| ETW run | Sample weight | Game EXE | LuaJIT DLL | Generated JIT code |
| --- | ---: | ---: | ---: | ---: |
| Three-way, JIT off | 2500 | 48.12% | 43.56% | 0% |
| Three-way, JIT on | 3604 | 49.31% | 26.83% | 8.32% |
| Final validation, JIT on | 2202 | 53.45% | 28.34% | 8.31% |

All five traces across these two batches have zero lost events and buffers.
WorldSim stack presence is 99.80-100%; presence does not guarantee a complete
unwind. Inclusive module percentages overlap and must not be added.
Sample shares are not equivalent to percentages of Lua instructions compiled.
Faster compiled code can consume a small share while replacing much slower
interpreted work.

The game baseline's EXE contains its embedded interpreter as well as generator
code. Its EXE samples cannot all be classified as native generator time. In
the LuaJIT groups, EXE dominance before Ocean and the observed Lua C-call
locations support a substantial engine-side floor; raw game PCs have not been
given speculative function names.

In the final validation, before_ocean takes 1.399197 seconds and 76.45% of its
WorldSim samples are in the EXE. The later square_fill takes 0.280370 seconds:
62.50% of its samples are in the LuaJIT DLL, 25.00% in generated code and 6.43%
in the EXE. The workload therefore has distinct native-heavy and Lua-heavy
phases; a single whole-process ratio hides that difference.

The earlier optional LuaJIT sampling batch, retained as
`game-performance-20261015-jit-benefit-etw-v2`, observes C state at
forest_map.lua and its on_region_added_fn callback. The installed source
contains WorldGen_VoronoiPass and AddRegionsToMainland in this region.
This is supporting evidence, not the main sampling source. Enabling
jit.profile also changes trace behavior, so its flush count is not used below.

## VM work that remains

These percentages are of all WorldSim CPU sample weight, including the EXE:

| Code labels | Three-way JIT on | Final validation JIT on |
| --- | ---: | ---: |
| lj_str_new | 2.47% | 4.50% |
| luaL_checkudata | 1.39% | 3.50% |
| GC labels | 5.55% | 2.72% |
| Exit/restore labels | 3.25% | 2.32% |
| Identified parser labels | 1.17% | 1.77% |

GC labels aggregate gc_*, lj_gc_* and propagatemark. Exit/restore labels
aggregate lj_vm_exit_*, lj_snap_restore and snap_restoreval. The parser
subtotal includes lex_*, expr*, bcemit_*, token2binop and lj_parse_* labels
that received samples. These selected self-label totals do not measure all
inclusive cost of those subsystems; inlining and calls into shared helpers
remain relevant. Allocation and string interning can serve several subsystems.

The evidence favors runtime/engine work over parsing as the next investigation
target inside Generate. It does not identify a single VM defect. Exit/restore
samples alone cannot distinguish ordinary guards, C stitching and compatibility
changes; claiming a RETM-specific regression would require another comparison.

## Trace cache and aborts

The final validation records 2622 starts, 2251 successful stops, 371 aborts and
2 full flush events during Generate, with no Lua sampling profiler enabled.
The max trace number reaches 1000. The local default is maxtrace=1000 in
lj_jit.h; lj_trace.c flushes all traces when no free trace slot is available.

Abort reasons include FNEW (129) and UCLO (10). FNEW locations include
scripts/util.lua:76 (66 aborts, closure in string splitting) and :918
(50 aborts, closure in deepcopy). Other aborts include inner loops and leaving
root loops. Abort counts do not directly measure lost CPU time or show that
every execution of those source functions remains interpreted.

Trace start-to-stop/abort spans total 0.050944 seconds in the final validation
and 0.090665 seconds in the earlier three-way JIT-on capture. These are wall
spans, including executed recording paths and callback effects, not pure
compiler CPU time. The data does not support treating compilation itself as
the majority of map time.

The cache experiment has trace diagnostics, no Lua/ETW sampler, two rounds and
no warmup. Both groups use the same Release DLL with JIT enabled:

| Round | Setting | Map wall, seconds | Successful trace stops | Full flushes |
| --- | --- | ---: | ---: | ---: |
| 0 | Default maxtrace=1000 | 2.747738 | 1455 | 1 |
| 0 | maxtrace=8000 | 3.690841 | 2625 | 0 |
| 1 | Default maxtrace=1000 | 2.736987 | 2315 | 2 |
| 1 | maxtrace=8000 | 2.284616 | 1134 | 0 |

Larger capacity removes the observed flushes but does not consistently reduce
total time. More retained traces can also change compilation and GC work.
This is a diagnostic experiment, not grounds for changing the default.
Its old long summaries were truncated by the engine; analysis retains only
complete leading fields and marks summaries incomplete. The final probe prints
a short summary plus individual abort-location records, validated in game.

## Artifacts and reproduction

| Directory under builds/ | Contents |
| --- | --- |
| game-performance-20261015-jit-benefit-timing | Uninstrumented timing, all 12 runs |
| game-performance-20261015-jit-benefit-etw-traces | Three-way ETL, CPU/stack exports, hotspots.json |
| game-performance-20261015-jit-cache-experiment | Two-round capacity experiment and trace diagnostics |
| game-performance-20261015-etw-validation | Final game/JIT-on validation, complete diagnostics and ETL |
| game-performance-vm-symbol-validation | Fresh Release build validating automatic map/sidecar generation |

The first attempted ETW diagnostic batch failed because its probe lacked the
matching generated jit.vmdef. That deployment failure is retained in
game-performance-20261015-jit-benefit-etw and excluded from comparisons.

Run the three-way ETW experiment without the Lua sampler:

```powershell
python tests/performance/run.py --profile worldgen --warmup 0 --repeat 1 `
  --sample-native --jit-diagnostics `
  --vm jit-off=builds/game-performance-vm-release/luajit/lua51DS.dll `
  --vm jit-on=builds/game-performance-vm-release/luajit/lua51DS.dll `
  --vm-jit jit-off=off --vm-jit jit-on=on `
  --injector builds/game-performance-runtime-release/src/DontStarveInjector/Release/Injector.dll `
  --output builds/game-performance/new-etw-run
python tests/performance/analyze.py builds/game-performance/new-etw-run
```

Use a new output directory. Omit --sample-native and --jit-diagnostics for
throughput timing. Add a separate on group with
`--vm-jit-option GROUP=maxtrace=8000` for a capacity comparison.

Validation: 26 measurement/analysis unit tests pass, probe syntax loads in the
verified Release interpreter, and the fresh Release build emits valid symbol
evidence. The final live pair passes with successful sudo/WPR receipts and no
trace loss. WPR is idle afterward; no launched game process remains. Original
Winmm.dll and luajit_config.json bytes are restored and SHA256-verified.
