---
name: luajit-int3-interrupt-maintenance
description: "Maintain or extend the LuaJIT BC_INT3 one-shot interpreter interrupt: selective trace flush, PROTO_NOJIT protection, per-backend handlers, dump format"
---

# BC_INT3 one-shot interpreter interrupt — invariants and pitfalls

Feature lives in `src/lj_profile.c` (guarded by `LJ_HASPROFILE`; `!LJ_HASPROFILE` stubs return `UNAVAILABLE`), declared in `src/luajit_rolling.h` (public) and `src/lj_profile.h` (internal). Opcode `_(INT3, rbase, ___, ___, ___)` sits directly after `BSAR` in `src/lj_bc.h`; all seven `vm_*.dasc` have a real handler.

## State machine
- `INT3_NONE` / `INT3_ENABLED`, one process-wide owner (`int3_state.g`), one pending request per VM.
- Owner-ness, callback, pending proto + `bcpos` + full original `BCIns` ("shadow"), `nojit` (we set `PROTO_NOJIT`), `delivering`.
- Pending proto is kept alive by `GCROOT_INT3` (`src/lj_obj.h`); cancelled in `close_state()` before finalizers.

## Semantics that must not regress
- The **JIT stays on** and no trace is flushed at `start`. `arm` flushes only traces that *can reach* the bytecode, then excludes the prototype from compilation for the request's lifetime.
- Hit: restore the original instruction, consume the request, then run the read-only native callback, then execute the original instruction once (`lj_dispatch_call`, hook/branch dispatch and the asm handlers all rely on this ordering).
- Per-VM gate: refusing a request must not abort an unrelated recording, so the `luaJIT_setmode` gate runs **before** `lj_trace_abort`.

## Trace selection (arm time, C only — never run Lua from the API)
A trace is flushed if any of:
1. `gcref(T->startpt) == obj2gco(pt)` -> root and side traces of the prototype;
2. a GC constant of the trace identifies the prototype: iterate `for (ref = T->nk; ref < T->nins; ref++)`, `ir->o == IR_KGC`, `ir_kgc(ir)` either `== pto` (poly specialization) or `!isluafunc || funcproto(gco2func(o)) == pt` (mono closure);
3. a snapshot PC lies in `[proto_bc(pt), proto_bc(pt)+sizebc)` — `snap_pc(&T->snapmap[snap->mapofs+snap->nent])`.

Why (2) is mandatory: `snap_pc` only encodes the **innermost** frame, so a prototype inlined with no guard/snapshot of its own is invisible to (3) alone. Why (2) must be native: `jit.util.tracek` would require re-entering Lua (allocation/GC/errors) inside `arm`, is absent in `LUAJIT_DISABLE_JITUTIL` builds, and is ~3 orders of magnitude slower (measured: C scan 0.41 µs @30 traces, 4.55 µs @302 traces ≈ 15 ns/trace).

Also zero `T->link` of live traces that point at a flushed trace (stitched links must not resume flushed mcode). Order: flush **before** planting the trap, because `trace_unpatch` writes `*T->startpc` and would otherwise overwrite the `BC_INT3` byte.

## JIT exclusion and its trap
- `PROTO_NOJIT` blocks new root traces (`trace_start`) and inlining (`rec_func_setup` -> `LJ_TRERR_CJITOFF`); callers of the armed function therefore abort recording — same cost model as `jit.off(func)`.
- `PROTO_NOJIT` also makes the recorder **lazily blacklist** hot spots (`IFUNCF`/`ILOOP` patch + `PROTO_ILOOP`). That blacklisting outlives the request and keeps the prototype uncompilable, so on hit/cancel/stop you must call `lj_trace_reenableproto(pt)` after restoring the bytecode. Symptom if forgotten: after `stop`, every fresh caller aborts with `LJ_TRERR_BLACKL` (trace `abort` event arg 5 == 5).
- A recorded function header is never re-dispatched through the dynamic `DISPATCH[BC_FUNCF]` entry from the asm handler when a call hook is active: `lj_dispatch_call` detects `bc_op(pc[-1]) == BC_INT3`, calls `lj_int3_hit`, restores `L->top`, and returns the plain JIT-off-converted `IFUNCF`/`IFUNCV` target — otherwise the call hook and `call_init` run twice.

## Per-backend handler invariants
- Re-decode the restored instruction exactly like that backend's `ins_NEXT` right before the dispatch jump (C calls clobber the operand registers: RC/RA on x86-family, INS/OP on ARM/MIPS/PPC).
- Preserve `nargs` across the C call and restore it only for `BC_FUNCF`/`BC_FUNCV`; form differs per backend (`RD = nargs+1` on x86/x64, `NARGS8:RC` = nargs*8 on arm/arm64/mips/mips64/ppc, absolute `RA = BASE+framesize*8`, and ARM64 additionally needs tagged `LFUNC:CARG3` reloaded from `[BASE, FRAME_FUNC]`).
- Re-dispatch must use the **dynamic** table; `GG_DISP2STATIC` is only for opcodes below `GG_LEN_SDISP`.
- ISNEXT/ITERN despecialization: test the target slot for `BC_INT3` **outside** `.if JIT` and route it to `lj_int3_setbc_op(g, target, BC_ITERC)`, which updates the shadow and keeps the trap.
- MIPS has no symbol relocation in buildvm: extern calls go through `DISPATCH_GOT(name)`, so `lj_int3_hit`/`lj_int3_setbc_op` must be in `GOTDEF` in `src/lj_dispatch.h`.

## Transparency and dumps
- Logical view helpers `lj_int3_bcins/setbc/setbc_op/bcpos` must be used by every semantic reader of the pending slot: `lj_dispatch_topslot`, the return-hook test in `lj_dispatch_ins`, `lj_debug_funcname`, `jit.util.funcbc`. `lj_dispatch_call`'s physical opcode read must NOT use them.
- `BCDUMP_VERSION` is bumped to `0x80` (private); `lj_bcwrite` patches the copy back to the shadow instruction; `lj_bcread` rejects any persistent `BC_INT3`.

## Verification ladder
1. `mingw32-make clean && mingw32-make` (see skill `luajit-windows-mingw-build-verify`).
2. Harness `int3-smoke.c` (repo root): live-JIT selectivity, nested-proto gate, armed protection (CJITOFF aborts), engine-off, bytecode variants, ISNEXT + hooks, GC/teardown, dump/reload, profiler exclusion, unsafe contexts; plus `-DSMOKE_NO_JIT` / `-DSMOKE_NO_PROFILE` modes.
3. `XCFLAGS=-DLUAJIT_DISABLE_GC64` run (exercises `vm_x86.dasc`).
4. dynasm preprocessing for all seven dascs + `buildvm -m elfasm` for arm64/mips64.
