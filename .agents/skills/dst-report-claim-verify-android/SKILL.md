---
name: dst-report-claim-verify-android
description: Verify DST performance/RE claims against Android libDontStarve.so via Ghidra MCP; not generic binary analysis.
---

# DST Report-Claim Verification via Android Ghidra DB

Use when checking a DST performance report/benchmark/RE blog (Steam workshop, server lag, mspt claims, function addresses) against engine reality. Verified against `libDontStarve.so 1.1.28` (AArch64, DB `/libDontStarve_android_1.1.28.so`, base `0x100000`).

## Canonical symbols (1.1.28)
- `cSimulation::SimUpdate @ 0x889ba0` — fixed-timestep tick: autopause → Lua `CallLuaFunction` (lua_pcall) → `cEntityManager::Update` → `SimPhysicsUpdate` → `PostSimUpdate`. Lua + C++ run in the SAME tick.
- `cSimulation::CallLuaFunction @ 0x885a98` — wraps `lua_pcall` (LuaJIT 2.1 static); the only Lua execution entry.
- `cEntityManager::CheckSleepers @ 0x86a6c0` — spatial-hash queries (64.0/76.8/4.01) driven by flags/destroyed-positions, NOT a per-tick full-map scan.
- `cSpatialHash<cEntity>::ApplyPred<PhysicsPred> @ 0x86f4e0` — grid double-loop, inverse-cell-size index math, distance-squared filtering, per-cell `operator_new+memcpy` buffer copies.
- `cNetworkConnection::QueryReplicaList @ 0x97f3f8` — per-connection iteration over potential-awake entities, vector/map copies → O(players×entities) shape.
- `lua_pcall @ 0xc3e45c`, `lua_gc @ 0xc3e9a8` — NO per-tick lua_gc call inside SimUpdate.
- Threading exists: `gUseThreadedPhysics`, `JobThread<ThreadPhysics>`, `tPhysicsJobThread`, render post-update Semaphore → never claim “no multithreading”.

## Procedure
1. Search symbols: `SimUpdate`, `CheckSleepers`, `SpatialHash`, `Replica`, `cBPWorld`, `lua_pcall`, `lua_gc`.
2. Decompile `SimUpdate` to establish what runs inside the tick vs parallel jobs.
3. Decompile `CheckSleepers` + `ApplyPred*` to check scan semantics.
4. For network: decompile `QueryReplicaList`; confirm per-client entity iteration.
5. Check claim addresses against ALL loaded binaries (Android 0x1xxxxxx, win64 base 0x140000000, mac32 ~0x000d3bdc for CheckSleepers). Tons of “analysis” posts mix 32-bit-looking addresses with x64 registers — red flag.
6. Sanity-check CPU math: if mspt times the whole tick and all systems are inside SimUpdate, then “10ms mspt but 80% CPU” ⇒ parallel job threads, not hidden in-tick work.

## Quirks
- Each function exists twice: normal + overlay copy ~ `0xe9xxxx–0xeaxxxx`; xrefs may resolve to overlay.
- Ghidra MCP `get_function_xrefs`/`get_function_callers` take `{name|address}` keys — `function_address` errors.
- `search_strings` wants `search_term`, not `regex`.
- Percentages in third-party reports are unverifiable statically; structure and hot-path existence can be confirmed, numbers cannot.
