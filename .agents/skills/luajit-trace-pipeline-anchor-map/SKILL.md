---
name: luajit-trace-pipeline-anchor-map
description: "Use when answering/verifying LuaJIT trace questions (trace start kinds, mcode layout, guards, exit stubs, snapshots, IR_PROF) in this repo; not for profiling tooling internals."
---

# LuaJIT trace pipeline anchor map (this repo)

Goal: answer "how does tracing/mcode/guard/snapshot work" questions from source, not from memory. Every claim below was read in `src/`.

## Lookup table

| Question | Read |
|---|---|
| Which bytecodes can start a trace | `trace_stop` switch `src/lj_trace.c:504-556` (FORL/LOOP/ITERL/FUNCF, ITERN/RET*, JMP=side, CALL*=stitch) |
| What triggers a hot start | `vm_x64.dasc:332 hotloop`, `:340 hotcall` (LOOP/ITERL/FORL/ITERN, FUNCF/FUNCV); `lj_trace_hot` `src/lj_trace.c:781`; side: `trace_hotside` `:796`; stitch: `lj_trace_stitch` `:814` |
| Recording into an already-compiled function | `rec_func_jit` `src/lj_record.c:1951`; dispatch `case BC_JFUNCF:` `:2746` |
| Why recording never runs mcode | `lj_dispatch.c:521` (IFUNC while recording), `lj_trace.c:962` (unpatch JLOOP→RET/ITERN, bcskip) |
| mcode region order / accounting | `lj_asm_trace` `src/lj_asm.c:2471-2640`; `asm_tail_prep`/`asm_tail_fixup` `lj_asm_x86.h:2947/2979`; exit stubs `lj_asm_x86.h:9,51` |
| Guard emission | `irt_isguard` → `asm_snap_prep` `lj_asm.c:2574`; `asm_guardcc` `lj_asm_x86.h:71`; loop inversion `loopinv` `:2425-2445` |
| Exit stub sharing/addressing | `jit_State.exitstubgroup[16]` `lj_jit.h:483`; `exitstub_addr_` `lj_target.h:152`; `EXITSTUB_SPACING/PER_GROUP` `lj_target_x86.h:164`; freed with mcode in `lj_trace.c:296-299` |
| Restore path | `vm_exit_handler` `vm_x64.dasc:2449`; `lj_trace_exit` `lj_trace.c:836`; `lj_snap_restore` `lj_snap.c:940`; `snap_restoreval` (uses `ir->prev` + rename) |
| Snapshot content/layout | `snapshot_stack` `lj_snap.c:160`; `snapshot_framelinks` (LJ_FR2 packs `pc<<8|baseslot`); `snap_pc` `lj_jit.h:217` |
| Snapshot creation/merging | `lj_snap_add` `lj_snap.c:181`; per-bytecode hook `lj_record.c:2287-2292` (`J->needsnap`) |
| Snapshot/IR limits | `LJ_TRERR_LLEAVE` `lj_record.c:2302`; maxrecord `:2793`; maxsnap `lj_snap_grow_buf_` |
| Profiler IR_PROF | `rec_profile_need/ins/ret` `lj_record.c:752-790`; `asm_prof` `lj_asm_x86.h:2700`; hook exit `lj_trace.c:940`, `lj_dispatch_profile` `lj_dispatch.c:551` |

## Answer shape that worked

1. Conclusion first, then the code path, then a table of "region/field → who writes → who reads".
2. Distinguish **code** (shared, exitno-indexed) from **data** (per-trace `snap`/`snapmap`/`ir`) whenever asked why sharing is safe.
3. When asked "is it per X?", check for a merge/cache rule before agreeing: mcode emission is backwards (IR order == ascending address); snapshots merge; exit stubs are global by exitno; `snapno == exitno`.
4. Quote the invariant that makes an optimization legal (e.g. `vmstate` == traceno inside a trace, `emit_setvmstate` in head).

## Verify

`grep -n` the symbol in `src/`; never answer mcode/snapshot questions from memory — the fork's GC64 `LJ_FR2` paths differ from upstream 2.1 docs.
