---
name: luajit-dasc-encoding-validation
description: Validate .dasc instruction encodings and control flow after backend asm edits; dynasm success does not prove encodability (DASM_CHECKS is off).
---

LuaJIT's DynASM encodes most backends at preprocessing time, but its operand checks (`CK`, `dasm_imm13`, `dasm_imm12`, ...) are wrapped in `#ifdef DASM_CHECKS`, which is **not defined** when dynasm is built here. A dasc edit can therefore pass `dynasm.lua` and still emit an illegal instruction (this cost two blockers: ARM64 `tst w, #0x8c` and a PPC control-flow bug that dynasm cannot see at all).

## Procedure

1. **Never treat preprocessing success as validation.** After editing a dasc, run dynasm for every backend and check exit status *and* stderr; then do the checks below.
2. **Audit immediate encodability statically.** Extract every instruction+immediate pair from the `.dasc` and validate against the target's rule:
   - AArch64 `tst/and/orr/eor/add/sub`: bitmask immediate = 2/4/8/16/32/64-bit element of *contiguous* ones rotated, replicated (so `0x0c` ok, `0x8c`/`0x84` NOT; `0x00007fffffffffff` ok as a 64-bit element). For a single bit use `tbnz/tbz #bit, label` instead of folding the bit into a mask.
   - ARM32 `tst/and/orr/eor/cmp`: modified immediate = 8-bit value rotated right by an even amount.
   - MIPS/MIPS64 `andi/ori/xori`: 16-bit unsigned.
   - PPC `andi./andix.`/`oris`: 16-bit; remember r0 cannot be an address base.
   - x86/x64 `test r/m, imm`: imm32 (and `test r/m8, imm8` if the operand is a byte).
   A ~30-line Python evaluator of the mask expressions (LUA_MASKLINE=4, LUA_MASKCOUNT=8, HOOK_ACTIVE=0x10, HOOK_VMEVENT=0x20, HOOK_GC=0x40, HOOK_PROFILE=0x80, ...) over the dasc lines is enough and catches the class.
3. **Review control flow by hand.** dynasm cannot validate it: check that a newly added test is actually reachable (not behind an earlier conditional exit) and that each branch changes the outcome. Prefer a dedicated single-bit test placed right after the preceding early exit rather than extending an existing mask whose other bits gate later branches.
4. **Only x64/x86 are runnable here**; for arm/arm64/mips/mips64/ppc state explicitly that the verdict rests on steps 2–3, and say so in the commit message.
5. **Beware stale host tools**: `host/buildvm.exe` built against an older `host/buildvm_arch.h` crashes (0xC0000005) on `-m peobj`. Delete `host/buildvm*.o`/`host/buildvm.exe` (or touch the dasc) and rebuild; the generated header is `host/buildvm_arch.h`, not `src/buildvm-arch.h`.
