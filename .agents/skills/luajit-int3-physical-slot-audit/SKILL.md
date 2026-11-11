---
name: luajit-int3-physical-slot-audit
description: "Audit BC_INT3/physical-bytecode slot readers and writers in this LuaJIT fork; diagnoses double delivery, illegal opcode, SIGBUS and hotloop hangs"
---

# When to use

Touching anything that patches or reads Lua bytecode in this fork while a BC_INT3 request (or any other
"physical slot rewrite") may be pending, or debugging "the callback fired twice / twice per N iterations",
"illegal opcode", SIGBUS after `jit.flush`/lazy blacklist, or hangs after `jit.opt.start('hotloop=0')`.

# Invariant

> A bytecode slot that may carry a trap is read and written **only** through
> `lj_int3_bcins()` / `lj_int3_setbc()` / `lj_int3_setbc_op()`.

Anything else that needs the "original" instruction must take the value returned by `lj_int3_hit()`.

# Audit checklist (grep these, not every opcode handler)

| Kind | Sites | Rule |
|---|---|---|
| derive opcode from a live slot | `lj_dispatch_topslot`, `lj_dispatch_ins` (RET check), `lj_debug`, `jit.util.funcbc`, `lj_bcwrite` | use `lj_int3_bcins` |
| re-dispatch after a delivery | `lj_dispatch_call` block, 7 backends' BC_INT3 handler | use the `lj_int3_hit` return value |
| trampoline re-dispatch | `->vm_hotloop` (uses `PC_OP` + `GG_DISP2STATIC`) | reset the loop instruction's hot counter in `lj_int3_hit` (clamped) |
| write a live slot | `trace_start` NOJIT lazy patch, `blacklist_pc`, `lj_trace_reenableproto`, `trace_unpatch` | `lj_int3_setbc*`; `reenableproto` needs `global_State *` |
| unreachable while armed | `lj_parse`, `lj_asm`, `lj_ffrecord`, `lj_crecord` | safe: arming sets `PROTO_NOJIT`, so no recording/assembly for that proto |

# Numbers / traps that bite

- `HOTCOUNT_LOOP` is **2**; `HotCount` is `uint16_t`; `jitopt_param()` accepts any non-negative `hotloop`, so
  `hotloop=0` and `hotloop=32768` (32768*2 truncates to 0) store 0. Always clamp a hot-count write to
  `[HOTCOUNT_LOOP, 0xffff]`.
- Call hooks (`LUA_MASKCALL`) fire at the **callee header** dispatch (`disp[BC_FUNCF] -> lj_vm_callhook ->
  lj_dispatch_call`), not at the CALL. So skipping a delivery there must not skip the hook.
- INS mode (`lj_dispatch_update`) rewrites only the *dynamic* half `disp[0..GG_LEN_SDISP)`; the *static* half
  (`+GG_DISP2STATIC`) keeps real opcode entries — that is where `vm_hotloop` re-dispatches.
- Re-arm timing is not the lever: the trap *is* the bytecode rewrite, and there is no general hook between
  "instruction executed" and "same slot dispatched again". Deferring the plant only moves the window.

# Verification recipe

1. `int3-smoke.exe 11` — call hook + re-armed header must give `hits=1 events=2`; hot loop
   (`G.loop(5000)` with FORL trapped and re-armed) must give `hits` in `[5000, 5001]`.
2. `int3-smoke.exe 12` — `hotloop=0/1/32768/56`, each `hits == 200` for 200 iterations.
3. Assertion build: `XCFLAGS="-DLUAJIT_ENABLE_GC64 -DLUA_USE_ASSERT"`; it also checks
   `close_state`'s `gc.total == sizeof(GG_State)` leak assert and white/mark invariants.
4. x86 non-GC64 (`mingw32-make` without `-DLUAJIT_ENABLE_GC64`) runs the same suite.
5. dynasm all seven backends after touching any `.dasc`.

# Instrumentation that localised the duplicate

- Histogram `__builtin_return_address(0)` inside `lj_int3_hit` (it proved all hits came from the asm handler,
  not `lj_dispatch_call`).
- Print the frame's loop-variable slot on each hit; duplicates showed the **same** value in pairs, spaced by
  the hot-count period (hits #58, #116, ...).
- Build windows through a `*.bat` with quoted `XCFLAGS`, because git-bash/cmd `^"` escaping breaks make;
  the tool shell sometimes lands in WSL, so pass `cwd` instead of `cd`.
