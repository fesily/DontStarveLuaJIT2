---
name: luajit-backend-asm-change-verify
description: "Verify a change to LuaJIT's vm_*.dasc backends when only x64/x86 can run: dynasm success is not validation, so check immediate encodability per architecture and control flow by hand, and avoid stale buildvm/header failures."
---

# Verifying LuaJIT backend (.dasc) changes across architectures

Context: a change is applied to several `src/vm_*.dasc` files but only x64 can be executed.
`dynasm/dynasm.lua` running with rc=0 proves nothing: the range/encoding checks are guarded by
`#ifdef DASM_CHECKS`, which the host build does not define (see `dynasm/dasm_arm64.h`). Examples of
bugs that pass dynasm: `test r, #0x8C` (not an AArch64 logical immediate), a `bne` that is
unreachable behind an earlier `beq`, a `cmp` that clobbers a register still needed.

## 1. Regenerate and rebuild before trusting anything

    rm -f host/buildvm_arch.h host/buildvm*.o host/buildvm.exe
    mingw32-make -j1 "XCFLAGS=-DLUAJIT_ENABLE_GC64" luajit.exe

A stale `host/buildvm.exe` against a regenerated `host/buildvm_arch.h` makes `lj_vm.o` die with
`Error -1073741819` (0xC0000005) — that is a build artefact, not your change. `src/buildvm-arch.h`
(dash) is a leftover from manual experiments; the real generated header is `host/buildvm_arch.h`.

## 2. Preprocess each backend you touched (syntax only)

    host/minilua.exe ../dynasm/dynasm.lua -D ENDIAN_LE -D JIT -D FFI -D DUALNUM -D FPU [-D P64] \
        -o /abs/out.h vm_<arch>.dasc

Run with and without `-D JIT` (`.if JIT` blocks disappear, labels must stay balanced).

## 3. Validate immediate encodability per architecture (the real check)

Scan every immediate operand of the integer instruction set in each edited dasc and test it:

| Backend | Instruction/operand | Rule |
|---|---|---|
| arm64 | `and/orr/eor/tst/add/sub` with `#imm` | AArch64 logical immediate: contiguous run of ones in a 2/4/8/16/32/64-bit element, replicated and rotated (`dasm_imm13`); 64-bit elements cover masks like `and #LJ_GCVMASK` (47 ones) |
| arm | `tst/and/orr/eor/cmp #imm` | modified immediate: any 8-bit value rotated right by an even amount |
| mips/mips64 | `andi/ori/xori #imm` | unsigned 16 bit |
| ppc | `andi./andix./oris #imm` | unsigned 16 bit |
| x86/x64 | `test r/m, #imm` | imm32 (imm8 form only for ≤255) |

Prefer single-bit tests (`tbnz`/`tbz`, `bt`, `test reg, 1<<n`) over folded multi-bit masks: new
combinations such as LINE|COUNT|0x80 frequently become unencodable on arm64.

## 4. Check control flow by hand

Read the emitted block as straight-line code and answer: "with only the new condition true, which
branch is taken?" Re-check each early exit (`bne <5`, `beqz AT, <5`, `beq cr1, <5`) — a later test is
dead if an earlier branch already left. Place dedicated tests for the new condition right after the
existing `HOOK_ACTIVE`/status exit and *before* any sequence that can branch away.

## 5. Run what can run, and say what cannot

Build x64 (GC64) and, for 32-bit paths, x86 (`XCFLAGS` without `GC64`) and run the project harness,
plus `LUA_USE_ASSERT` and the reduced configs (`DISABLE_JIT`, `DISABLE_PROFILE`, both, `amalg`).
State explicitly in the commit message that the non-runnable backends were validated by immediate
encodability plus control-flow review, not by execution.
