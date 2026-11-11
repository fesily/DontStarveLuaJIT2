---
name: luajit-bcint3-trap-audit
description: "Audit/debug a LuaJIT BC_INT3-style one-shot bytecode trap against VM re-dispatch and JIT bytecode-patch paths: prove duplicate deliveries, enumerate physical-slot readers/writers, and fix with armability limits + immediate trace termination."
---

# Auditing a LuaJIT bytecode trap (BC_INT3) against re-dispatch and JIT patches

Use when a bytecode-slot trap (one-shot interrupt, breakpoint, patched opcode) can fire
twice per execution, crash with an invalid opcode, or vanish, especially together with
`rearm`, hot counters, hooks, or the JIT.

## 1. The one invariant

> The physical bytecode of a trapped slot may only be read or written through the
> logical view (`lj_int3_bcins()` / `lj_int3_setbc*()`). Everything else that needs the
> original instruction must take the value returned by the trap handler.

Any site that re-reads `*pc` / `PC_OP` / `pc[-1]` after a delivery, or writes the slot
with raw `setbc_op`/`*pc =`, is a bug of this class. The trap is *in* the bytecode; there
is no "re-arm later" hook between one execution and the next dispatch of the same slot,
so deferring the re-arm cannot remove the class.

## 2. Prove it before fixing

| Question | Probe |
|---|---|
| Which code path delivers? | In the trap handler, histogram `__builtin_return_address(0)` into a static array, print at session stop. One DLL address = the VM handler, another = C re-dispatch. |
| Same execution delivered twice? | Print a frame slot that changes per iteration, e.g. the loop variable `L->base[k].u64`, for the first ~24 hits. Duplicate values = duplicate delivery; the period equals the hot-count base. |
| Is the JIT machinery involved? | Count `lj_trace_hot` entries (`pc & 1` hot marker), `lj_dispatch_ins` calls, and `trace_start()`'s NOJIT branch. All three should be 0 while only a trap drives execution. |
| Hot-count dependence? | Run the same loop with `jit.opt.start('hotloop=0')`, `1`, `32768`, default. `hotloop=0` stores `0` into a 16-bit `HotCount` (`HOTCOUNT_LOOP == 2`), the trampoline subtracts and branches straight back. |

## 3. Enumerate readers and writers (do not trust a partial audit)

Writers of a live proto's bytecode:
- `lj_trace.c`: `trace_start()` (NOJIT lazy I-variants and J-variants), `trace_stop()` (root
  start patches: FORL/LOOP/ITERL/FUNCF, whole instruction for ITERN/RET/RET0/RET1), the
  `FORI` companion of `JFORL`, `blacklist_pc()`, `lj_trace_reenableproto()`, `trace_unpatch()`.
- **The VM itself**: `BC_ISNEXT` in every backend writes *its own slot* (`BC_JMP`) and
  rewrites the ITERN target to `BC_ITERC` or a whole `JLOOP` instruction.
- `blacklist_pc()`'s `pc+1+bc_j(pc[1])` target is the parser-emitted ISNEXT slot
  (`parse_for_iter`), not an arbitrary slot — so the mutable set is statically enumerable.

Readers: `lj_dispatch_call()` (`pc[-1]`), the BC_INT3 handler's re-dispatch (`[PC-4]`),
`vm_hotloop` (`PC_OP` into the *static* half, which INS mode does **not** redirect),
`lj_dispatch_topslot`, `lj_debug`, `jit.util.funcbc`, the bytecode writer.

Unreachable for an armed prototype (because arming sets `PROTO_NOJIT`): `lj_parse`,
`lj_asm`, `lj_ffrecord`, `lj_crecord`.

## 4. Preferred fix: two constraints, then delete the patches

1. **Armability**: refuse slots the JIT/VM rewrites — FUNCF/FUNCV, FORI/FORL/ITERL/LOOP,
   ITERN, ISNEXT, RET/RET0/RET1 and the already patched I*/J* variants (return
   `LUAJIT_INT3_UNARMABLE`). Tell callers to arm the first instruction of the function or
   loop body instead: same events, no race.
2. **Immediate trace termination**: at arm time flush traces touching the prototype and set
   `PROTO_NOJIT`, then refuse *starting* any trace for it at the earliest point —
   `lj_trace_hot()` and `lj_trace_stitch()` return before the recorder state machine
   (`lj_int3_jit_on_blocked(g, curr_proto(J->L))`). `trace_start()`'s lazy patch then never
   runs for an armed prototype; hot counters keep ticking and each trip is a cheap refusal.

With both, the hot-count clamp, the trapped-header block in `lj_dispatch_call()` and the
logical-view rewrites of the JIT patchers become dead code: delete them. Keep the handler's
returned instruction (a callback may re-arm the slot) and the logical view for readers and
the dump.

## 5. Re-dispatch contract

Have the trap handler return the instruction it consumed; the VM must jump to the returned
instruction, not re-read the slot (`[PC-4]`). For x64/x86 the return value already lands in
`RC` (rax/eax), so the handler only needs to drop the slot load.

## 6. Legal alternative, and its costs

A central deferred plant is possible (`lj_dispatch_update` switches all *dynamic* dispatch
to `vm_inshook`, `lj_dispatch_ins` runs before each instruction), but: INS mode does not
redirect the static half used by `vm_hotloop`; the first `lj_dispatch_ins` for the same pc
is the current re-dispatch, and self-loop bytecode makes "same pc, new execution"
undecidable; the step flag is VM-global and can latch across return/error/yield
(measured ≈1.8x interpreter slowdown while active). Prefer §4.

## 7. Test recipe

- Arm a body slot, re-arm from the callback, and assert `hits == iterations` (5000/5000).
- Repeat with `hotloop=0`, `1`, `32768`, default: identical counts.
- Assert `TR.start == 0`: an armed prototype reports zero trace starts.
- Assert `UNARMABLE` for each excluded opcode and that the corresponding *body* slot works.
- Keep the teardown/GC assertions: run the suite against `-DLUA_USE_ASSERT` so
  `close_state()`'s `gc.total == sizeof(GG_State)` and the white/mark invariants catch
  leaked roots and dangling slot writes.
