---
name: luajit-deferred-single-step
description: "LuaJIT: implement deferred (next-instruction-boundary) actions such as re-planting a BC_INT3 trap, via a hookmask step bit, inshook/PDC dispatch and lj_dispatch_ins; includes PPC and buildvm pitfalls."
---

# Deferred single-step work in LuaJIT ("do X before the next instruction")

Use when a native feature must take an action (plant a bytecode trap, patch a slot) *after* the currently executing instruction has finished, without touching opcode handlers.

## 1. Get a pre-instruction hook without a user hook
- Add a step marker to `global_State.hookmask`. The byte is full (`LUA_MASKCALL..COUNT` 0x01-0x08, `HOOK_ACTIVE` 0x10, `HOOK_VMEVENT` 0x20, `HOOK_GC` 0x40, `HOOK_PROFILE` 0x80), so either reuse a bit that cannot co-occur or widen the asm load.
- Safe reuse: `HOOK_GC` for a feature that is mutually exclusive with GC steps, because a real GC step always also sets `HOOK_ACTIVE` (`hook_gc()`), so `hookmask & HOOK_ACTIVE` distinguishes them.
- Keep the marker in the byte: buildvm's PE-object assembler rejects `test r/m32, imm32` (>0xFF) and `movzx r32, word [mem]` — it crashes with 0xC0000005 while emitting `lj_vm.o`, and dynasm still reports success.

## 2. Route dispatch through the hook trampoline
- `lj_dispatch_update()`: `mode |= (g->hookmask & (LUA_MASKLINE|LUA_MASKCOUNT|STEP)) ? DISPMODE_INS : 0;`
- In all 7 `vm_*.dasc` `->vm_inshook`, extend the two existing masks that gate the `lj_dispatch_ins` call so the step bit alone reaches it (do not add a new label; x64/x86).
- PPC is special: it tests `HOOK_ACTIVE`, then extracts only the LINE bit and does `beq cr1, <5`, so a step-bit-only state never reaches the call. Insert `andix. TMP1, TMP3, STEP; bne >1` **immediately after the ACTIVE exit, before the CR1/count sequence** (do not clobber `TMP0`, which still holds the LINE bit).
- ARM64: replace `tbz TMP2w, #LUA_HOOKLINE, <5` with `tst TMP2w, #LUA_MASKLINE|STEP; beq <5`.

## 3. Run the deferred action at the boundary
- At the top of `lj_dispatch_ins()`: `lj_int3_step(g, pc-1);` — `pc` points **past** the current instruction, so compare against `pc-1`; the first attempt used `pc` and never matched, producing an infinite delivery cascade.
- Plant only entries whose slot is not the instruction about to run; skip such a slot once per entry (`skipped`) and plant at the following boundary (handles self-referencing slots).
- Clear the step bit and call `lj_dispatch_update(g, 0)` when nothing is suspended; also do this from cancel/stop/close, otherwise the VM stays in per-instruction C dispatch (~1.8x slower measured).
- `lua_sethook()` truncates the mask to bytes: preserve the step flag (`(g->hookmask & ~HOOK_EVENTMASK) | mask`, no `(uint8_t)` cast).

## 4. Why not just act immediately?
Every instruction-slow path and the hook trampoline read the **physical** opcode (`PC_OP` / `byte [PC-4]`):
- `vm_inshook` reloads it before the static re-dispatch → a re-planted trap re-delivers the same execution (with an unbounded re-arm: no progress).
- `vmeta_arith`/`vmeta_comp`/`GGET`/`GSET` pass it to `lj_meta_arith()`/`lj_meta_comp()`; a trap opcode selects the wrong metamethod.
So any deferred action must keep the slot's real opcode until the instruction is done.

## 5. Verification
- Count **executions**, not just callbacks: bounded counters hide duplicates (hits=6 looked fine but 100001/100 exposed the cascade).
- Cover: user line/count hook + re-arm, a metamethod slow path, no-hook loop, cancel/stop/close while suspended, and `jit.opt.start('hotloop=0')`.
- After any change to a `.dasc`, regenerate the arch header and **rebuild `host/buildvm.exe`**; a stale buildvm crashes on `lj_vm.o`.
