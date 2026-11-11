---
name: dst-thesim-profiler-toolset-re
description: "Locale DST TheSim:Profiler* toolset across platforms with Ghidra MCP: find the luaL_Reg binding slot, the FrameProfiler switch, and whether a build compiled the profiler out."
---

# DST `TheSim:Profiler*` toolset — locate & classify via Ghidra MCP

Use when asked what `TheSim:ProfilerPush/ProfilerPop/ProfilerLoadPush/ToggleFrameProfiler/ToggleDataProfiler/Profile` does, how to enable it, or whether a given build has it. NOT for LuaJIT `jit.profile` or `TheSim:SendProfileStats` network reporting.

## 0. Ghidra MCP argument quirks (hit these every time)
- `search_functions` `name_pattern` = literal substring, NOT regex (`A|B` returns nothing).
- `decompile_function` needs `address` only; `name_or_address` is rejected.
- `search_strings` needs `search_term`; case-sensitive (use `(P|p)rofiler`).
- `search_instructions` needs `mnemonic` or `operand_pattern`, not `operand_substring`.
- Always pass `program` when >1 program is open.

## 1. Find the Lua binding (works on any platform)
1. `search_strings` for the exact name (`ProfilerPush`, `ToggleFrameProfiler`, `Profile`).
2. `get_xrefs_to` that string address → a `…[DATA]` ref in `.data.rel.ro` is the luaL_Reg slot.
3. Read 32–64 bytes there (`read_memory`): slot = `{name_ptr@+0, func_ptr@+8, …}`; stride is 0x20 on Android AArch64, 0x18 on Windows x64 — and effective `0x20` for the package's interleaved tables — so always decode by the string xref address, not by assuming a stride.
4. Cross-check with `get_xrefs_to <func_ptr>`: one `…[DATA]` ref should come back from the same slot.
5. `decompile_function` the func_ptr. A `mov w0,wzr; ret` (AArch64) or `return 0` means the API exists but is inert in that build.

## 2. Classify the build
- Inert build (seen: Android 1.1.28): the whole API is stubs, `cSimulation::Profile/HandleProfiler/SendProfileStats` are bare `ret`, and there is NO `FrameProfiler`/`StartRecording`/`FlushToDisk`/`GetSpinTime`/`WriteHeader`, no `sProfileLock`/`sThreadIDs`/`_TLS_key_FrameProfiler`, and none of the strings `profile.json`, `profile_%03d.json`, `ProfileIndex:%.2f`, `Profiler started.`, `{"traceEvents":[`. Verify by string search, not by the API table alone.
- Live build: `SimLuaProxy::ProfilerPush` → `FrameProfiler::Push(inst, name, "…simlib/simluaproxy.cpp", line)`; `ToggleFrameProfiler` → `FrameProfiler::ToggleRecording`.
- Guard against Ghidra artifacts: decompile one known-real sibling in the same table (e.g. `SpawnPrefab`); if that is full-bodied, the stubs are genuine.

## 3. The switch semantics (read these two functions)
- `FrameProfiler::ToggleRecording` = under `sProfileLock`: `if(!bRecording) StartRecording(this,false); else { bRecording=0; FlushToDisk(); }`
- `FrameProfiler::StartRecording(bool bumpIndex)` = record `dwThreadID`, clear each thread's TLS SampleStack, `dwProfileCount=0`, `nFileIndex = bumpIndex ? +1 : 0`, `Timer::Reset`, `bRecording=1`.
- `StopRecording` = `bRecording=0; FlushToDisk()`. `ContinueRecording` = stop+flush+`StartRecording(true)`; it is the ONLY path that increments the file index, called from `Pop` when `dwProfileCount > 0x3c00` (15360) and the recording thread's depth returns to 0.
- `Push/Pop` no-op unless `bRecording`.

## 4. Answer the "how do I turn it on" question
- Enable/disable from Lua: `TheSim:Profile(secs)` (`luaL_optinteger` default 3 on mac/Win, 10 on Android) → `cSimulation::Profile` → print "Profiler started." + `flProfilerTime` + ToggleRecording; auto-off in `cSimulation::HandleProfiler(dt)` → print "Profiler stopped - profile located at …".
- Manual toggle: `TheSim:ToggleFrameProfiler()` → `ToggleRecording`. It is a pure sampling switch: no UI state, no network, no countdown.
- `TheSim:ToggleDataProfiler()` is `return 0` (dead) everywhere seen; do not describe it as functional.
- `ProfilerPush/Pop` never start recording.
- Output: Chrome Trace Event JSON at `<donotstaredir>/profile.json`, or `profile_%03d.json` after auto-chunking; header `metadata` args come from global `mDataFunc` = `GetProfilerData` (which also calls Lua global `GetProfilerMetaData`).

## 5. Cross-platform comparison shorthand
Keep mac (Jenkins dev build with symbols) for names/line numbers and Windows x64 shipping for the true release shape; Android for mobile. Do not assume a PC-found string exists on Android — grep the binary for the tracer's own literals to decide.
