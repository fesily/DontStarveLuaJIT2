---
name: luajit-core-jit-mechanism-source-map
description: "Map LuaJIT core JIT mechanism questions (trace start, calling compiled mcode, mcode layout, guards/snapshots, IR_PROF) to exact src files/lines and their runtime semantics."
---

# LuaJIT core JIT mechanism source map

Use when asked how LuaJIT itself behaves (not a fork feature): "does a trace abort/stitch when it calls compiled mcode", "what is a trace's layout", "when are guards handled", "where does profiling instrumentation go". Read these anchors instead of grepping blindly.

## Trace start (`lj_trace.c`)

- `trace_stop` switch (`lj_trace.c:504-556`) is the **complete** set of startins: `FORL/LOOP/ITERL/FUNCF` -> patch hot bytecode to JLOOP-family roots; `ITERN/RET/RET0/RET1` -> `*pc = BCINS_AD(BC_JLOOP, nslots, traceno)`; `JMP` -> side trace (patch parent exit); `CALLM/CALL/ITERC` -> stitch (`traceref(J, exitno)->link = traceno`).
- Hotcount sites are only `BC_LOOP/ITERL/FORL/ITERN` (`hotloop`) and `BC_FUNCF/FUNCV` (`hotcall`) — `vm_x64.dasc:332,340`. RET traces come from `trace_abort` `LJ_TRERR_DOWNREC` -> `trace_downrec` (restarts at the return instruction), not from hotcount.
- Side traces start at `BC_JMP` with the exit snapshot's PC (`lj_record.c:2911`).

## Recording a call into already-compiled code (`lj_record.c:1951 rec_func_jit`)

Dispatched from `case BC_JFUNCF: rec_func_jit(J, rc)` (`lj_record.c:2746`).

| Callee trace linktype | Behavior |
|---|---|
| `LJ_TRLINK_RETURN` | Unpatch `J->patchpc` back to `T->startins`, keep recording the callee's **bytecode** inline; `check_call_unroll` limits to `callunroll` (default 3) -> `LJ_TRERR_CUNROLL` |
| anything else | `J->instunroll = 0`, `lj_record_stop(J, LJ_TRLINK_ROOT, lnk)` = **stop + link** (not abort) |
| `J->pc == J->startpc && framedepth+retdepth == 0` | `LJ_TRLINK_TAILREC` |

mcode is **never executed while recording**: `lj_dispatch.c:521` downgrades FUNC* to IFUNC*, and `lj_trace.c:962` unpatches JLOOP->RET/ITERN with `bcskip=1`. Aborts nearby: `LJ_TRERR_CJITOFF` (PROTO_NOJIT), `LJ_TRERR_LINNER` (root trace hits compiled inner loop, `lj_record.c:665`). `LJ_TRLINK_STITCH` is unrelated: C fast-function continuation stitching (`lj_ffrecord.c:109 recff_stitch`).

## mcode layout (`lj_asm.c:2471 lj_asm_trace`)

Emission is backwards from `mctop`, so ascending address order equals source order; `T->mcode` is the lowest address = entry.

```
mcbot: exit stub groups (asm_exitstub_setup runs BEFORE the body,
       at mcbot, 32 stubs/group, J->exitstubgroup[] shared+lazy,
       each = push imm8 exitno + jmp lj_vm_exit_handler)
       | free | T->mcode (head: vmstate + spadjust [+GC check]) |
       body in IR order (inline guards) | tail (epilogue) | NOP pad | mctop
```

- Tail by linktype: `link==0` -> set `RID_LPC`/`RID_RET`(MULTRES) then `jmp lj_vm_exit_interp`; `link!=0` -> `jmp traceref(lnk)->mcode`; loop -> back-jump to `T->mcloop` (`asm_loop_fixup`); small loops trigger `as->realign` re-assembly for 16-byte alignment.
- `T->szmcode = mctop - mcode` (excludes stubs); icache flush uses `mctoporig`.
- Bookkeeping: `T->mcode/mcloop/spadjust/topslot/link/linktype`, `snap[].mcofs`; `jit.util.traceinfo` exposes mcloop (`lib_jit.c:379`).

## Guards and snapshots

1. Record time: guard = IR with `IRT_GUARD` (`IRTG(o,t)`); `lj_snap_add` merges snapshots when no guard intervened (`lj_snap.c:181`).
2. Asm time, per IR (`lj_asm.c:2566-2576`): `asm_snap_prev` records `snap[].mcofs` and drops guard-free spans; DCE skips only non-guard IRs because `ir_sideeff` is always true for `IRT_GUARD` (`lj_ir.h:600`); `irt_isguard` -> `asm_snap_prep` (`asm_snap_alloc` pins snapshot values into regs/spills on first use).
3. `asm_guardcc` emits `jcc exitstub_addr(J, snapno)`; when the write pointer is the loop-tail slot (`p == as->invmcp`) it inverts the guard into the loop back-edge (`loopinv=1/2`).
4. Runtime: stub -> `lj_vm_exit_handler` -> `lj_trace_exit` -> `lj_snap_restore` (rebuild Lua stack from snapmap, `snap_unsink` for sunk allocs, `SNAP_NORESTORE`) -> interpreter with MULTRES. `trace_hotside` counts `snap->count` to `hotexit` (10) then `lj_asm_patchexit` rewrites the `0F 8x` to jump straight to the side trace mcode and sets `SNAPCOUNT_DONE`.
5. Never-hit guards are never deleted.

## Profiler instrumentation (`IR_PROF`)

- `rec_profile_ins` is called at the very top of `lj_record_ins` (`lj_record.c:2312`); inserts `IRTG(IR_PROF, IRT_NIL)` + `lj_snap_add` when the line changes (`prof_mode == 'l'`) or the proto changes (both modes); `rec_profile_ret` adds one per RET in `'f'` mode.
- Assembled by `lj_asm_x86.h:2700 asm_prof`: `test byte [DISPATCH+hookmask], HOOK_PROFILE` + `jne exitstub` -> one predictable not-taken branch per line.
- Adjacent duplicate IR_PROF is folded (`lj_opt_fold.c:2465`); `rec_itern` compensates with `REF_FIRST + LJ_HASPROFILE` (`lj_record.c:696`).
- On hit: `lj_trace_exit` returns to the interpreter only (skips `trace_hotside`, `lj_trace.c:940`), then `lj_dispatch_profile` -> `lj_profile_interpreter` -> user callback. `jit.profile(...,'l')` also does `lj_trace_flushall`.

## Method notes

- Cite file:line for every claim; these are stable anchors, not symbol names.
- Verify with targeted `grep`/`sed -n` reads before answering; do not infer from memory of older LuaJIT versions (2.1 differs: no `BC_LOOP` jump, exit stub groups, `EXITTRACE_VMSTATE`).
