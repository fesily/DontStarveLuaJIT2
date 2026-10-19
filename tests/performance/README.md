# Game performance profiles

`worldgen` creates a fresh offline Master world with a fixed seed and measures
map generation and server startup. `startup` runs the same generation, then
launches the existing loopback client and waits for its injection/world tokens.
Both include the game's embedded Lua 5.1 as their default comparison baseline.
World size, seed, hold duration and timeouts live in `profiles/*.json`.
Each sample uses its own temporary server save tree. The profiler does not
delete or reuse a player's world. Only processes it launches are stopped.
Startup samples also use an isolated client save tree, preventing player mod
options from switching the VM or enabling unrelated mods during the sample.
The loopback bot suppresses the first server-mod warning in memory for these
fresh clients; it does not change player settings.

## Run

```powershell
python tests/performance/run.py --profile worldgen
python tests/performance/run.py --profile startup
python tests/performance/run.py --profile worldgen --worldgen-jit on

# Run only the embedded game VM.
python tests/performance/run.py --profile worldgen --vm game=game

# Build a candidate using the same Release-only wrapper.
python tests/performance/build_release.py --source C:/bench/before/luajit `
  --build-dir builds/game-performance-before-release

# The embedded game VM is automatically prepended to both candidates.
python tests/performance/run.py --profile worldgen --warmup 1 --repeat 5 `
  --vm before=builds/game-performance-before-release/luajit/lua51DS.dll `
  --vm after=builds/game-performance-vm-release/luajit/lua51DS.dll `
  --output builds/game-performance/worldgen-comparison
```

Without `--vm`, the runner builds the local LuaJIT in
`builds/game-performance-vm-release` and compares it with `game=game`.
The native selector uses `lua_vm_type=game`: the game executable's actual
embedded VM, not a separately compiled Lua 5.1 DLL. The injector and probe
remain present in both groups so the measurement boundaries match.
Server and client logs must confirm the requested VM type.

The first VM is the comparison baseline. Order reverses each round (ABC, CBA).
Members of every pair use the same seed, world settings, injector,
plugins and game installation. `--seed` overrides the profile's seed.
Use matching toolchains, build flags and GC variants for both libraries.
Source revision, build flags and each DLL's SHA256 are included in
`results.json`. A comparison of two different commits
measures all of their changes, not just RETM stitching.

## Release policy

Profiles require optimized **Release** VMs without `LUA_USE_ASSERT`,
`LUA_USE_APICHECK`, RETM/OOM test diagnostics, sanitizer or debug CRT flags.
`build_release.py` uses a compile-time guard and writes hash-bound evidence
beside each DLL. VM builds clean before compiling so stale headers/objects
cannot survive between source revisions. The runner rejects missing evidence, changed DLLs and
instrumented compilation commands. This deliberately rejects the earlier
assertion/API-check review binaries, including optimized RelWithDebInfo builds.

The optional ETW JIT symbol provider (see *JIT symbols in WPA / PerfView*) is
not such an instrumented build: it adds no assertion, sanitizer, debug-CRT or
diagnostic switch, so a normal Release VM keeps publishing its trace symbol
records when explicitly enabled. That metadata maintenance is allowed in diagnostic profiles,
and its cost (per-VM, per-trace and prewarmed-execution numbers, plus the one
worker thread) is measured in the same section.

The runner also builds the root injector/plugins with Release in the isolated
`builds/game-performance-runtime-release` and launches directly from that build tree.
Dependencies are staged by the existing `stage_mod_deps` target on Windows,
and signature databases are copied into that runtime root.
The deployed `Mod/Injector.dll` is not replaced.
On Windows the injector shell is also built with Release. The game directory's
`Winmm.dll` is temporarily replaced for the profile and its original bytes are
restored on success or exception.
For each sample, the game's `luajit_config.json` is temporarily directed at the
Release runtime to prevent its saved `modmain_path` from loading Debug plugins.
Its exact original bytes are restored on success or exception. Actual bootstrap
and plugin-load logs are checked; plugins outside that runtime fail the sample.
This is repeated for every sample because the main game mod may rewrite the
configuration while the client runs.
Run profiles serially and avoid changing this configuration while they run.
An existing runtime built with `build_release.py --runtime` can be selected
with `--injector PATH`; its module hashes and Release flags are verified.
Local builds require the normal compiler/CMake/Ninja environment.

`--worldgen-jit default|on|off` controls only the measured map-generation calls.
`default` preserves the game's existing behavior. The injector currently
disables JIT at bootstrap, so a LuaJIT VM does not imply compiled execution.
Each attempt records its actual JIT status at entry, and explicit `on`/`off`
runs fail if that status does not match. Client and server simulation retain
their normal initialization behavior. Enabling JIT does not establish that a
particular RETM path compiled; this remains a workload-level measurement.
The embedded game VM always records `jit=false`; this option applies to
LuaJIT groups only.

Use `--vm-jit LABEL=on|off|default` to compare both compiler modes in one batch:

```powershell
python tests/performance/run.py --profile worldgen --warmup 1 --repeat 3 `
  --vm jit-off=builds/game-performance-vm-release/luajit/lua51DS.dll `
  --vm jit-on=builds/game-performance-vm-release/luajit/lua51DS.dll `
  --vm-jit jit-off=off --vm-jit jit-on=on `
  --injector builds/game-performance-runtime-release/src/DontStarveInjector/Release/Injector.dll
```

`--vm-jit-option LABEL=option=number` applies explicit LuaJIT tuning to one
group, for example `--vm-jit-option jit-on=maxtrace=8000`. The requested
options are recorded in the results. Use separate repetitions to establish
whether a diagnostic finding, such as a full trace cache, affects throughput.

Library overrides use the existing `GAME_LUA_MODULE_NAME` and `lua_vm_type=jit`.
The run fails if the requested library lacks an exact successful attachment/load log,
the worldgen probe cannot confirm the selected VM, or any timing boundary is absent.
A LuaJIT fallback to the embedded VM cannot silently become a successful sample.

## Measurements

| Field | Boundary |
| --- | --- |
| `worldgen_map_wall_seconds` | Sum of `forest_map.Generate` attempt intervals, observed on process stdout |
| `worldgen_map_cpu_seconds` | Sum of process CPU time spent in those attempts, including native generator work |
| `worldgen_attempts` | Every failed retry and the successful attempt, with separate wall/CPU times |
| `worldgen_jit_enabled` | JIT status at map-attempt entry; null if attempts differ |
| `server_launch_to_world_seconds` | Immediately before Popen through the server's session-ready log |
| `client_launch_to_inject_seconds` | Immediately before Popen through `LG_CLIENT_INJECT_OK` |
| `client_launch_to_world_seconds` | Immediately before Popen through `LG_CLIENT_WORLD_READY` (same milestone as smoke tests) |
| `workflow_to_ready_seconds` | Cluster setup, server startup, and optional client startup through readiness |
| `test_total_seconds` | Setup through hold and process teardown; save-tree removal follows this measurement |

Readiness timings exclude the fixed stability hold and process shutdown.
Wall timings use `perf_counter` at the first stdout observation and include
log buffering/delivery latency. They do not include the wait loop's polling
delay. Map timing excludes worldgen module loading, entity injection and save
serialization; the server startup metric includes those stages.
Client readiness is a world-loaded smoke milestone, not first rendered frame
or first playable character.
CPU timing is sampled by the Python harness when it observes begin/end logs:
`GetProcessTimes` on Windows and `/proc/<pid>/stat` on Linux. Both VMs use the
same external clock and neither probe loads FFI. Other platforms report CPU
time as null until a process clock is implemented there; wall time remains
available. Like wall timing, CPU boundaries include log delivery delay.

Output consists of per-process logs, raw CSV/JSON, descriptive medians/ranges,
and geometric means of paired candidate/baseline ratios (negative change
means faster). Warmup rounds remain in raw output but are excluded from the
summary. A failed run is retained and stops the comparison.

Every sample, including warmups, starts a fresh game process and VM.
`--warmup` discards initial runs to reduce filesystem-cache and first-launch
effects; it cannot preserve JIT traces for later samples. These profiles measure
the first world generation in each VM, including compilation when it occurs.
Measuring generation with warmed traces requires repeated generation within
the same VM and separate control of generator state and random seeds.

The first embedded-game VM comparison using this Release policy is preserved
in [the October 14, 2026 baseline](baselines/2026-10-14-release.md).

Default profiles are coarse end-to-end measurements. They cannot
attribute CPU time to RETM or separate native worldgen, graphics, disk and
network costs. Fixed seed does not guarantee identical output across VMs with
different random-number or table-iteration semantics. Check retry counts.
Filesystem caches, background load and Steam/client initialization remain
sources of variation. One sample validates the harness, not a small speedup.

## Hotspot diagnostics

Use the optional samplers to investigate a large difference before changing
the VM. Both retain the same Release binaries and compile-time checks above.
Sampling adds overhead, so keep these results separate from normal benchmarks.

```powershell
python tests/performance/run.py --profile worldgen --worldgen-jit on `
  --sample-lua --sample-native --jit-diagnostics --warmup 0 --repeat 2 `
  --vm luajit=builds/game-performance-vm-release/luajit/lua51DS.dll `
  --injector builds/game-performance-runtime-release/src/DontStarveInjector/Release/Injector.dll `
  --output builds/game-performance/hotspots
python tests/performance/analyze.py builds/game-performance/hotspots
```

`--sample-lua` enables LuaJIT's `jit.profile` at a requested 5 ms interval.
It aggregates VM states and up to 12 Lua frames between map markers, then prints
the samples after generation ends. Function names accompany source lines;
engine-loaded scripts may have `[string]` chunk names. It also records
outermost uncached `require` begin/end markers in both VMs. These intervals
include file loading, parsing and module execution, and cover nested loads
without double counting. Modules loaded before `forest_map.Generate` remain
outside the map measurement. Cached require calls are not individually logged.
The embedded VM has require/timeline observations but no LuaJIT stack samples.

`--sample-native` now uses WPR/ETW CPU sampling and kernel-collected native
stacks. Install Windows Performance Toolkit (WPR and xperf). An unelevated
runner invokes `etw_control.py` through Windows `sudo.exe`; the game itself
retains its normal token. Each recording has a unique WPR instance name.
Only that instance is stopped/cancelled. The helper writes start/stop receipts
so a new-console sudo mode does not hide failures. Collection failures fail
the sample; no thread-suspension fallback exists.

The CPU profile records process/thread and image mappings, SampledProfile
events and SampledProfile stacks. An ETW provider emits Generate begin/end
and Ocean stage markers from the stdout observer. The raw `.etl` opens in WPA.
`analyze.py` invokes Microsoft's xperf dumper with stack time shifting, saves
the CSV and exporter log, then filters CPU samples by target PID and ETW map
boundaries. String-only marker events are decoded through Windows
`OpenTraceW`/`ProcessTrace`; xperf exports the CPU and stack events. Export
receipts distinguish completed exports from interrupted or partial CSV files.
It reports process-wide and WorldSim self/inclusive module
weights, top PCs/stacks and stack presence coverage. Inclusive weights
overlap. Missing unwind frames and private symbols remain limitations; a
present stack is not necessarily complete. Lost events or missing map
markers reject the analysis.

`--jit-diagnostics` records trace starts, successful compilations, abort
reasons, code ranges and memory before/after generation. It uses `jit.attach`
trace callbacks, not `debug.sethook`. Code ranges help identify ETW samples
in compiled LuaJIT code without a JIT PDB. Attribution uses trace commit
times and should be checked for flush/reuse. The game's `newProfiler` is
deliberately excluded because its debug hooks are unsuitable for this use.

Trace recording/compilation spans measure start-to-stop/abort wall time,
including execution during recording and callback overhead. They are not
compiler CPU measurements. Flushes close the validity interval of earlier code
ranges so reused addresses do not inherit old trace labels. Abort locations
are printed separately to stay below the engine's single-line print limit.

New MSVC VM builds also emit a linker map and a hash-bound `.symbols.json`
sidecar. The analyzer checks the measured DLL hash before using these code
symbol regions, including static C functions and VM assembly labels. Regions
may include padding and inlined code. Without the sidecar, only exports with
an exact x64 unwind boundary are named. Private source-line PDBs are not
required. For an older DLL, relink its unchanged Release objects with `/MAP`
to a separate output, then run `symbol_map.py --module ORIGINAL_DLL
--linked-image RELINKED_DLL --map LINKER_MAP`. This rejects the map unless all
executable sections, including their RVAs and bytes, match the measured DLL.

### JIT symbols in WPA / PerfView

`lua51DS` and `lua51DS_gengc` can publish LuaJIT trace symbols through the
Microsoft-JScript ETW provider (`57277741-3638-4a4b-bdba-0ac6e45da56c`): no
manifest install, no JIT PDB, one provider per process shared by all VMs. Each
committed trace publishes a source record and a method record over the same
protocol Windows/Chakra use, so `CPU Usage (Sampled)` resolves a sampled PC
inside `[T->mcode, T->mcode + T->szmcode)` to
`LuaJIT::TRACE_<traceno>::<chunk>:<startline>`.

**The publisher is off by default and is switched at runtime from Lua:**

```lua
local profile = require("jit.profile")
profile.etw(true)    -- enable; also flushes this VM's traces (see below)
profile.etw(false)   -- disable; unloads the published records immediately
print(profile.etw()) -- query the current state
```

- The switch is **process-global**: any VM's call applies to every VM. Each
  VM keeps a small context while it is off, so turning it on later still
  publishes that VM's *new* traces; traces compiled before the switch was
  turned on are not retrofitted.
- `etw(true)` runs `jit.flush`-equivalent `lj_trace_flushall` for the calling
  VM: the traces compiled while the provider was off are dropped, so every
  live trace has a record and no stale identity survives. Other VMs are not
  flushed from here (their old traces simply stay unpublished) - call
  `etw(true)` from a VM that needs a clean symbol table.
- `etw(false)` reports the `MethodUnload`/`SourceUnload`/`ScriptContextUnload`
  records at once and stops publishing new ones; the records are freed by
  their owning VM, never by another thread.
- **The game must therefore enable it explicitly**: nothing is published until
  something in the injected VM calls `profile.etw(true)` (a mod, a bootstrap
  hook). `etw-symbols-*.exe --hold-for-profile` and the integration tests do
  that themselves, so the capture/verification path below stays valid.
- `-DLUAJIT_DISABLE_ETW=ON` still removes the feature from the build entirely
  (and `LJ_HASETW` is 0 on non-Windows and JIT-less builds, where
  `profile.etw()` simply reports `false`).

- `cpu.wprp` subscribes the provider with keywords `0x3` (runtime load/unload
  plus the start rundown), so attaching to a process whose traces were
  published (i.e. the switch was already on) still resolves them. WPR keeps
  running the controller; the game keeps its normal user token.
- The symbol name is the trace's **starting line**. It does not claim to map
  every machine instruction or inlined call back to a Lua line.
- The chunk part of the name comes from the Lua side: an `@`/`=` prefix is
  stripped, a bare path is kept verbatim (the DST engine passes
  `scripts/main.lua` without `@`, so game traces read
  `LuaJIT::TRACE_12::scripts/worldgen_main.lua:243`), and a name that looks
  like source text (newlines, or longer than 512 bytes) becomes `(string)` so
  a whole source blob never ends up in the symbol.
- Exit stubs and the interpreter dispatch path are not covered, and
  `RtlAddFunctionTable` is deliberately not called (`lj_err.c:347-371`
  identifies JIT frames by the absence of a `RUNTIME_FUNCTION`), so native
  unwinding across JIT frames is unchanged.
- The Microsoft-JScript GUID is shared with every Chakra host on the machine
  (Edge/WebView2 emit thousands of their own JIT events). The recording keeps
  all of them - filter the view by the game PID - and the event collector
  buffers in `cpu.wprp` are sized for that volume.
- `--jit-diagnostics` and `analyze.py` stay a separate stdout/`jit.attach`
  path: they are not ETW symbol consumers, and an older ETL does not gain JIT
  events retroactively.
- Turning it off at runtime is `profile.etw(false)`; to remove it from the
  build entirely use `-DLUAJIT_DISABLE_ETW=ON` (CMake) or
  `XCFLAGS+=-DLUAJIT_DISABLE_ETW` (Makefile). Windows with JIT is the only
  target that has it; the runtime API is a single `jit.profile.etw` function
  that reports `false` where the feature is not compiled in, and no other Lua
  or C ABI surface changes.

`-DLUAJIT_TEST_ETW=ON` builds `etw-symbols-default` / `etw-symbols-arenagc` and
registers `luajit_<variant>_etw_symbols`. Both drive a real session
(`StartTraceW` / `EnableTraceEx2` / `ProcessTrace`), enable the provider with a
PID filter and compare the payloads against the traces the VM actually
committed. They need an elevated or *Performance Log Users* shell: failing to
create a session exits with code 77 (CTest SKIP), while a missing or mismatched
event fails. `etw-symbols-default.exe --hold-for-profile` prewarms a VM, prints
`ETW_PROFILE_READY pid=<pid>`, waits for a newline on stdin and then keeps
executing the prewarmed code for 10 s - start the WPR controller against that
PID, press Enter to let the workload run, and press Enter again after `stop` to
close it. That is the live "attach after warmup" check.
`verify_jit_symbols.py --exe <etw-symbols exe> --out <dir>` automates that
capture through the same controller. WPR's system collector is
administrator-only, so the script prints `[info] admin=… sudo=…` and runs the
controller through Windows `sudo` by default when this shell is not elevated
(`--no-elevate` opts out; unelevated `wpr -start` fails with `0xc5585011`).
It then joins the xperf CPU samples of the target PID with
the method ranges WPT's dumper decodes from the ETL - the same manifest-driven
decode and address join WPA/PerfView perform. Default order is "workload first,
then record" (attach); `--start-first --launch "<cmdline>"` records *before*
launching the target instead, i.e. capture-from-process-start, where the
startup traces arrive as runtime load events and no rundown is needed.
`--hold-for-profile` prewarms
*before* it prints `ETW_PROFILE_READY`, so the traces exist before the
profiler attaches; a recorded run of that script measured:

| measurement | value |
|---|---|
| CPU samples of the target PID | 9998 |
| samples whose PC is inside `[MethodStartAddress, +MethodSize)` | 9968 |
| resolved symbol | `LuaJIT::TRACE_1::etw-a.lua:2` |
| attach-after-warmup rundown (MethodDCStart/SourceDCStart) | present (1, 7, 39, 5, 2) |
| runtime load/unload + context records | present (11, 41x2, 9x2, 10x2, 42x2, 12) |
| lost events / buffers (tracestats and the dumper) | 0 / 0 |

Manual WPA step (no CLI exists for the CPU view, so this part is a human
check): open the recorded `jit-symbols.etl`, go to *CPU Usage (Sampled)*,
filter by the target PID and read the symbol column - the rows for that PID
must show `LuaJIT::TRACE_...::<chunk>:<startline>`. PerfView was not usable
for automation on the machine used here (the single-file download produced no
`/nogui` output and had to be killed), so the PerfView column is untested; the
underlying parser contract is the same `JScriptTraceEventParser` field set this
repository emits and WPT decodes.

Cost with the switch off (the default) and with it on
(RelWithDebInfo, one 8-core desktop, no session attached; `LUAJIT_DISABLE_ETW`
is the compile-time baseline):

| path | switch off | `etw(true)` | compiled out |
|---|---|---|---|
| VM create+open+close (min of 3 runs x 400) | 46.3 us | 45.5 us | 45.7 us |
| compiling distinct traces | no work (addtrace returns on one flag) | ~10.5 us/trace | n/a |
| executing already-prewarmed code | unchanged | unchanged | unchanged |

The per-VM path is at run-to-run noise level in every state: with the switch
off a build only pays one small `HeapAlloc` per VM (its context, kept so any
VM can turn publishing on later) - no provider registration, no worker thread,
no per-trace record. Only while publishing is enabled does the process carry
one worker thread plus the provider registration, one heap record per live
trace (bounded by the trace count) and two `EventWrite` calls per committed
trace (two more when it is unloaded), all gated by `EventEnabled`, so with no
session listening enabled still only maintains records. Nothing is added to
generated code, which is why the prewarmed execution column does not move.

Any diagnostic option saves complete stdout observations with monotonic timestamps.
`analyze.py` divides map attempts using the game's existing Ocean stage markers
and reports require intervals, VM states, native CPU modules and top PCs/stacks
in `hotspots.json`. Stage boundaries include log delivery latency.
Require totals are meaningful when `--sample-lua` was enabled.

For archived pre-ETW captures, `--disassemble` uses the Python `capstone` package
to decode captured dynamic thunks. `--signatures FILE --game-lua-base-rva HEX`
maps observed hook context candidates to the project's verified game Lua API
addresses; the RVA must match the exact recorded game executable. The October
14 server used `0x483660`, established by the existing `luaModuleSignature`
anchor. Do not reuse that value for a different game binary.

The historical C API interception regression is documented
in [the October 14 hotspot investigation](baselines/2026-10-14-hotspots.md).
The current compiler/interpreter investigation using ETW is documented in
[the October 15 JIT benefit investigation](baselines/2026-10-15-jit-benefit-etw.md).

## Existing test suite

The existing client smoke tests now always print `[lc] TIMINGS {...}`, including
failed runs that reach the launch phase. To retain a machine-readable report:

```powershell
python tests/plugin_client/run_client_inject_smoke.py --timings-json builds/client-timings.json
python tests/plugin_client/run_client_inject_smoke.py --mode host `
  --timings-json builds/host-timings.json
```

`LC_TIMINGS_JSON` is the equivalent environment override. Timing output does
not change the smoke test's pass criteria or stability hold.

`game_performance_unit` runs without the game. The game profiles are opt-in
CTest entries, serialized with existing game tests by `dst_game_server`:

```powershell
cmake --preset ninja-multi-vcpkg -DDS_TEST_GAME_PERFORMANCE=ON
ctest --test-dir builds/ninja-multi-vcpkg -C Release `
  --output-on-failure -R game_performance
```

The CTest profiles use one measured round per VM and no warmup. Use the standalone
runner for paired repetitions. Missing game installations follow the harness
SKIP convention; `DS_REQUIRE_GAME=1` turns a skip into failure.

## Existing Save Startup

`stress_startup.py` loads the existing Master snapshot from a temporary copy,
then launches an offline client and waits for its local player and HUD. It does
not generate a new map. The bot always spawns Wilson. Caves, Shipwrecked and
Volcano are not started.

```powershell
python tests/performance/stress_startup.py `
  --cluster-source C:\Users\fesil\Documents\Klei\DoNotStarveTogether\191485686\StressTest `
  --injector builds/game-performance-runtime-etw-release/src/DontStarveInjector/Release/Injector.dll `
  --lua builds/game-performance-vm-etw-switch-release/luajit/luajit.exe `
  --vm game=game `
  --vm jit_off=builds/game-performance-vm-etw-switch-release/luajit/lua51DS.dll `
  --vm jit_on=builds/game-performance-vm-etw-switch-release/luajit/lua51DS.dll `
  --mode jit_off=off --mode jit_on=on `
  --repeat 3 --warmup 1 `
  --output builds/stress-startup-timing
```

Required Workshop mods already cached by Steam are temporarily mounted using
directory junctions when absent from the game's mods directory. Existing mod
folders are retained. Missing mods cause an error unless each ID is explicitly
listed with `--allow-missing-mod ID`. Such runs measure a modified configuration
and must report the disabled IDs. The LuaJIT Lua mod itself is disabled in the
copy to isolate the VM and avoid its later JIT, profiler and GC policy changes.
Its native bootstrap options are also overridden in the copy, since the
bootstrap reads that entry even when the Lua mod is disabled.

The existing `GAME_INIT` entry installs a one-use wrapper around the framework's
initial `jit.off()`. The wrapper restores the original API immediately and sets
the requested mode before main.lua. The early status is retained and printed
once the game logger exists, with `replayed=true`; it is not an ETW phase
boundary. Later startup milestones verify the global compiler state again.
There is no Lua sampling, trace callback or game newProfiler in this runner.
On VMs with the native publishing switch, `jit.profile.etw(false)` is set before
main.lua for timing. `--etw` instead enables publishing there. Later milestones
verify both the compiler and publishing state. The `jit.profile` sampling
start/stop functions are never called.

Server wall time spans Popen entry to its session-ready log. Client wall time
spans Popen entry through connection and loading to a local player with HUD.
GetProcessTimes records kernel plus user CPU for all threads. The server's CPU
while the client starts and the combined workflow CPU are recorded separately.
These CPU clocks do not count waiting. Wall boundaries include stdout delivery
latency and are independent of the harness's polling interval.

Use a separate `--etw --repeat 1 --warmup 0` batch for diagnostics. WPR starts
before launching the server and stops after client readiness. Each PID has its
own launch and ready markers. Analyze completed captures with:

```powershell
python tests/performance/startup_etw.py `
  builds/stress-startup-etw/round-0-jit_on-native-samples.json
```

The analyzer uses Windows OpenTrace/ProcessTrace to decode the new native
Microsoft-JScript method events. CPU PCs are joined by PID, context, generation,
address range and method lifetime, including unload and context destruction;
reused addresses do not inherit old trace names. The CPU consumer reads kernel
SampledProfile records and joins StackWalk fragments by their original QPC and
TID, using thread lifecycle events for PID ownership. Marker events calibrate
the QPC clock against the converted ETW timestamp axis. xperf supplies image
mappings and trace-wide loss counts, which must be zero. `--validate-csv`
exports an xperf dump and compares every startup sample's PC, TID and Count;
`--csv-samples` retains the full xperf dumper path as an alternate consumer.
Private VM code
labels are accepted only from a sidecar bound to the measured DLL hash.

The source cluster's file manifest is hashed before and after the batch and
stored in results.json. Only the temporary save is written by the game.
`success` means that both startup endpoints and mode checks passed; shutdown
is outside that interval. PIDs and final process exit codes are recorded
separately. `--keep-going` retains failed runs and completes other groups, but
still returns a nonzero batch exit code if any startup failed.

Nonempty `.dmp` and `.mdmp` files inside each run's own temporary save tree
are copied to the output before cleanup. Copy failures retain the original
tree in `preserved_persist`, record `dump_collection_errors`, and fail the run.
No unrelated crash directories are scanned.

## Server Load Loops

`server_load.py` repeatedly loads the same Master snapshot without a client.
It retains per-round server logs, checks the actual VM/JIT/ETW state and save
load marker, and collects dumps with the same preservation rules as
`stress_startup.py`. A nonzero graceful shutdown exit or a nonempty dump fails
the round. `--stop-mode kill` deliberately skips normal shutdown and its GC.

```powershell
python tests/performance/server_load.py --cluster-source C:/bench/StressTest `
  --vm C:/bench/vm/lua51DS.dll --lua C:/bench/vm/luajit.exe `
  --injector C:/bench/runtime/Injector.dll --instances 1 --rounds 20 `
  --output builds/server-load.json *> builds/server-load.console.log
python tests/performance/run_report.py builds/server-load.console.log
```

`DS_CLUSTER_SOURCE`, `DS_VM_PATH`, `DS_LUA_PATH` and `DS_INJECTOR_PATH` provide
defaults. Every missing Workshop mod requires an explicit `--allow-missing-mod ID`;
no machine-specific list is automatically accepted. Output JSON and its
`.logs` directory must be new for each batch; the shared dump directory uses
the batch output name plus instance and round to separate evidence.
Use `--instances 1` for comparable readiness times. Concurrent instances share
CPU and disk and are intended for crash soaks.

Normal runs require the hash-bound Release evidence. Setting `DS_ALLOW_ASAN`
explicitly permits an instrumented VM for crash investigations and marks the
output `diagnostic=true`; those runs are unsuitable for performance comparisons.
The runtime injector still requires Release evidence.

Historical measurements and their binary identities live in `baselines/`.
They describe the builds and dates stated in each report and do not claim to
measure the current working tree. Standalone debugger watchers and semantic
comparison helpers are separate investigation tools.
