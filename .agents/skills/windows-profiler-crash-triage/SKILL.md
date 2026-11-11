---
name: windows-profiler-crash-triage
description: "Triage rare crashes/truncated stacks in a Windows sampling profiler (SuspendThread+RtlVirtualUnwind, ETW, sysprof-like): VEH diagnostics, soak repro, map symbolization, common root causes."
---

# Triage rare crashes in a Windows sampling profiler

Use when a profiler that samples by `SuspendThread` + `GetThreadContext` + `RtlVirtualUnwind` crashes intermittently, produces truncated/looping stacks, or attributes frames wrongly. Not for building the sampler (see the `*sysprof*` / sampling skills) and not for single-shot deterministic crashes.

## 1. Repro strategy (a crash per 200–1000 sessions is normal)

- Loop `start`/`stop` **inside one process** (60–80 sessions per run) and repeat the process 6–10 times; a fresh process per session hides the bug and multiplies startup cost.
- Workload matters: interpreter-only (`jit.off()`), heavy allocation, and FFI calls reproduce different paths.
- Record per-run exit codes; a single crash in 10 runs is a signal, not noise.

## 2. First-chance VEH that identifies the faulting side

Add (temporarily or behind an env var) an `AddVectoredExceptionHandler` that prints:

- `er->ExceptionInformation[0/1]` when `NumberParameters > 1`: `0` = read, `1` = write, and the **address** — a near-NULL address (e.g. `0x1F8`, `0x4B`) means a bogus pointer/`NULL+offset`, not a stack overrun.
- faulting `Rip`/`Rsp`.
- module path of `Rip` via `RtlPcToFileHeader` + `GetModuleFileNameA`.
- current thread id, plus the sampler thread id updated on **every** timer tick (setting it once per process is wrong: the timer thread is recreated per profiling session).

Return `EXCEPTION_CONTINUE_SEARCH` so the process still dies and the exit code stays meaningful.

Interpretation: `(sampler)` + `ntdll.dll` ⇒ a bad input to an ntdll API (usually `RtlVirtualUnwind`); profiled thread inside the runtime's own code ⇒ memory corruption or a stale read by the sampler, not a unwind problem.

## 3. Identify the faulting function

- Export table first: parse `.pdata` and the export directory offline to name the containing function (helps for ntdll/kernel32).
- For your own DLL, relink with `-Wl,-Map=<file>.map` (GNU) or `/MAP` (MSVC) and resolve `Rip - module_base` through the map. Map addresses are link-time; compute the delta from **a symbol from the same run** (ASLR changes per process) or from `GetProcAddress` printed by the VEH.

## 4. Known root causes seen in practice

| Symptom | Cause | Fix |
|---|---|---|
| Chain stops at JIT/generated code; caller frames replaced by repeated addresses / image base | address→range snapshot updated only after an early `return` (e.g. while a symbol dump is pending), so code compiled in the first interval is unknown | update the range snapshot **before** any early return; plain-data appends are safe while another thread owns the output stream |
| Sampler crashes inside `ntdll!RtlVirtualUnwind`, read at near-NULL | `RtlVirtualUnwind` applied to hand-written `.xdata` (JIT code, custom asm blob, SEH-only unwind info) | recognise such frames by function entry (returned `BeginAddress`, and the second half = first `EndAddress`) and skip the frame with the runtime's own entry-frame contract instead of unwinding it |
| Walk loops (`f; g; f; g; …` up to the frame cap) | one fixed "entry frame" pointer reused for every skipped frame | keep a cursor and consume one entry frame per skip (`cframe_prev()`-style chain) |
| Sampler crash reading small offsets; profiled thread mid-update | dereferencing a stack slot that is not a live object (sampling off safepoints) | type-check the slot before dereferencing; skip anything that is not the expected cell |
| Wrong symbol names, modules mixed up | one map/PDB applied to addresses of another module | require the resolved link-time address to fall inside the map's range |

## 5. Verify the fix

- Soak until the previous failure rate would have appeared at least 5×: ~1000+ sessions across both toolchains.
- Re-check semantics, not just stability: chains must show the expected frame order, counters must equal parsed events, and a mid-profile flush must not mis-attribute samples.
- Remove VEH/logging before committing; keep the diagnostic recipe in the commit message or design notes.
