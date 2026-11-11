---
name: luajit-hook-trace-abort-map
description: "LuaJIT hook (debug.sethook / jit.profile / HOOK_PROFILE) vs trace recorder: list of abort entries, when recording survives, non-aborting hook-point recipe; not generic JIT profiling."
---

# LuaJIT hook ↔ trace recorder map

Use when: a hook/profiler callback behaves inconsistently with JIT traces; you need to know whether a hook aborts the in-flight trace, or you want a hook point that does not disturb recording (LuaJIT 2.1 / Tarantool fork).

## Core model

- Recorder is per global_State (`J->state`), single-pass; hooks only exist on the interpreter dispatch path.
- `lj_trace_abort(g)` = `G2J(g)->state &= ~LJ_TRACE_ACTIVE` (lj_trace.h:45). **Deferred**: next dispatched instruction with `state != IDLE` hits `trace_state` `default:` -> `trace_abort(RECERR)` (lj_trace.c:751-760). If the trace finished in that same `lj_trace_ins`, abort is a no-op.
- Dispatch modes (lj_dispatch.c:106-190): LINE/COUNT -> INS (`lj_vm_inshook`), CALL -> `lj_vm_callhook`, RET -> `lj_vm_rethook`, REC -> `lj_vm_record`, PROF -> `lj_vm_profhook`; `f = PROF ? profhook : REC ? record : inshook` so PROF preempts REC.
- `lj_vm_inshook` re-dispatches to the static table; `BC_JLOOP` static entry jumps into mcode. So line/count hooks do **not** stop already-compiled traces: one hook event at JLOOP, then mcode runs.

## All direct abort sites (11 total)

| Site | Condition |
|---|---|
| lj_err.c:771 `lj_err_throw` | any throw, even caught by pcall |
| lj_err.c:893 `lj_err_run` | runtime error with errfunc |
| lj_dispatch.c:345 `lua_sethook` | any debug.sethook change (incl. clear / same mask) |
| lj_dispatch.c:372 `callhook` | every real hook delivery (line/count/call/ret); skipped when HOOK_ACTIVE |
| lj_dispatch.c:257 `luaJIT_setmode` | jit.on/off/flush, func/proto/trace variants |
| lib_jit.c:567 `jit_profile_callback` | **unconditional after every Lua `jit.profile` callback** |
| lj_gc.c:513 `gc_call_finalizer` | `__gc` finalizer |
| lj_state.c:391 `lj_state_free` | freeing coroutine with open upvalues |
| lj_ccallback.c:731 `lj_ccallback_enter` | any FFI C->Lua callback |
| lj_ccall.c:1253 | x86-32 Windows stdcall fixup only |
| lib_aux.c:45 `luaL_fileresult` | os/io failure path |

Synchronous aborts: `lj_trace_err` / `lj_trace_err_info` (~119 sites) -> `lj_err_throw` -> `LJ_TRACE_ERR` -> `trace_abort` with specific code (BADTYPE, NYI*, limits, MCODEAL, CJITOFF, ...). Silent drops: `lj_trace_flushall` (jit.flush, profiler start 'l'/'f', profiler stop, no free trace, mcode alloc fail, lua_setmetatable basemt) and `trace_start` early returns (PROTO_NOJIT, already JLOOP, no free trace). Not aborts: `lj_record_stop`/`trace_stop`, side exits, and HOOK_VMEVENT/GC/ACTIVE suppression.

## HOOK_PROFILE path

- Timer: `profile_trigger` sets `hookmask |= HOOK_PROFILE` + `lj_dispatch_update` under profile lock; no abort.
- Handler: `vm_profhook` -> `lj_dispatch_profile` -> `lj_profile_interpreter`: clears PROF, sets `hookmask = HOOK_VMEVENT`, calls cb, restores mask; then `sub PC,4; jmp cont_nop` re-dispatches the same instruction.
- Under VMEVENT: `vm_record` skips `lj_dispatch_ins`; `lj_dispatch_call` skips `lj_trace_ins`; `lj_trace_hot`/`hotside`/`stitch` refuse. Callback code is never recorded and cannot start traces (verified: 196 callbacks, 0 trace starts).
- C API `luaJIT_profile_start` -> no abort in core (verified: 115 samples, 0 RECERR). Lua wrapper -> RECERR aborts (verified). `luaJIT_profile_stop` always flushes all traces; start 'l'/'f' flushes (needed to bake IR_PROF guards).
- Do not set HOOK_PROFILE manually: `lj_vm_profhook` unconditionally enters `lj_profile_interpreter`, which uses the global `profile_state` (uninitialized lock, NULL cb).

## Non-aborting hook-point recipe

1. `luaJIT_profile_start(L, "i1", cb, data)` from C (or copy the lib_jit wrapper and delete `lj_trace_abort`). Mode `i1` = interpreter-only, no flush; `i1l`/`i1f` = flush once, then IR_PROF guards allow mcode line/function hook points.
2. Callback: pure C, read-only (`G2J(G(L))->state`, `J->cur`, `hookmask`, `luaJIT_profile_dumpstack`), no Lua execution, no throw, no FFI closure, no debug/jit/metatable writes, no start/stop inside.
3. Caveats: callback pauses recording; debug hooks are disabled during it; allocation->GC can still abort via `__gc` / coroutine free; profiler start/stop flush whose cost you must accept.

## Quick verification

Use `jit.attach(fn, "trace")` + `jit.attach(fn, "texit")`; count `start`/`stop`/`abort` per function and texit deltas. Set `jit.opt.start("hotloop=1")` for fast repro; avoid probe loops (they get traced). A fine-grained line/count hook test: warm a 2000-iteration loop, install hook, rerun -> 0 new traces, ~8-10 hook calls vs ~2002 interpreted.
