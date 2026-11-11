---
name: luajit-new-opcode-backend-port
description: "Use when adding a new bytecode opcode or VM-level hook to LuaJIT across all 7 dasc backends, or porting an asm VM handler; covers opcode insertion, dispatch, per-backend register rules, and compiler-free verification."
---

# Adding a bytecode opcode / asm handler to LuaJIT (all backends)

Verified on the LuaJIT 2.1 rolling fork with `BC_INT3` (see `int3-smoke.c` in that worktree for a full acceptance harness).

## 1. Opcode plumbing

- Insert into `BCDEF` in `src/lj_bc.h` at the position that preserves existing ranges/assertions (e.g. after `BSAR`, before the `FUNCF` block). Never hand-edit generated `luajit.h` — change `src/luajit_rolling.h`.
- `GG_LEN_SDISP == BC_FUNCF`: opcodes `< BC_FUNCF` live in the *dynamic* dispatch table `disp[op]`; opcodes in `[SDISP, DDISP)` (e.g. `IFUNCF`) also live plain at `disp[op]` (the "gap"), and only `op < SDISP` has a *static* copy at `disp[GG_LEN_DDISP+op]`. That is why hook re-dispatch uses `+GG_DISP2STATIC` for body ops but header entries are indexed plainly. Getting this wrong jumps into garbage.
- A `case BC_x:` in a `.dasc` opcode switch is what creates the opcode's pc label used by `lj_bc_ofs[]`; a missing case makes `buildvm` fail with `Error: undefined opcode BC_x`. Source order of cases need NOT match `BCDEF` order (the file groups sections), but a new case must sit next to its section.
- Force any special dispatch entry in `lj_dispatch_update` *after* the mode-change block, otherwise the inshook/record branch overwrites it whenever hooks are active.

## 2. Writing the handler (portable shape)

1. Save the nargs register (`RD`=nargs+1 on x86/x64; `NARGS8:RC`=nargs*8 on arm/arm64/mips/ppc) into a C-callee-saved register or VM stack slot; C argument registers may alias `BASE`/`PC`.
2. `L->base = BASE` (mirror that file's `->vm_inshook`), set `SAVE_PC`, `call extern`.
3. Reload `BASE`; re-decode the operand registers exactly as `ins_NEXT` does (x64: `mov RCd,[PC-4]; movzx RAd,RCH; movzx OP,RCL; shr RCd,16`) — handler macros read operands from those registers, not memory.
4. Restore nargs **only** when the restored opcode is `FUNCF`/`FUNCV`, and for ARM64 also reload the tagged function (`ldr LFUNC:CARG3,[BASE,FRAME_FUNC]; and LFUNC:CARG3,CARG3,#LJ_GCVMASK`) plus `RA = BASE + A*8`; PPC/MIPS need `RB/LFUNC` reloaded and `RA` made absolute.
5. Jump to the **dynamic** entry `DISPATCH[op]` (same form as `ins_callt`).

Traps: `ins_NEXT` leaves decoded operands only in registers (x64/x86/ppc/mips-decoded); on arm64 only INS/RA/RC/TMP1 are materialised. For a hit at a function header the state comes from `ins_callt`, not `ins_NEXT`.

## 3. Hooks

If a trapped function header must not re-run the call hook (it already ran: CALL -> `vm_callhook` -> `lj_dispatch_call` -> `lj_bc_ofs[physical op]`), handle it in C (`lj_dispatch_call`: detect the special opcode, deliver, restore `L->top`, then return the plain `IFUNCF/IFUNCV` target). Do not try to reach a raw `IFUNCF` from asm: with `LUA_MASKCALL` active the whole `[SDISP,DDISP)` range is replaced by the callhook trampoline.

## 4. MIPS

`buildvm` has no MIPS symbol relocation: never `call extern` from `vm_mips*.dasc`. Add every new C callee to `GOTDEF` in `src/lj_dispatch.h` and call it with `load_got name` + `call_intern name` (`jalr r25`).

## 5. Verification without a cross toolchain (Windows/MinGW host)

- Always `make clean` before rebuilding after header/opcode edits (stale `GG_State` offsets cause crashes at trace exits).
- Run built binaries only through `cmd.exe /c "cd /d C:\path && exe args"` (bash exec of new binaries is blocked).
- Per-backend dasc syntax: `cmd.exe /c "... host\minilua.exe ..\dynasm\dynasm.lua <flags> -o <scratch>\buildvm_arch.h vm_<arch>.dasc"` in both JIT and no-JIT flag sets.
- Full assembly generation only for 64-bit targets: copy `host/buildvm*.c` + `buildvm.h` + `buildvm_libbc.h` into a scratch dir, generate `buildvm_arch.h` **there**, put that dir first in `-I` (a stale `src/host/buildvm_arch.h` is otherwise picked up), stub `emit_peobj` (it does not build for non-x86 targets on a Windows host), then `gcc -DLUAJIT_TARGET=LUAJIT_ARCH_<X>` and run `buildvm -m elfasm`. 32-bit targets fail with "pointer size mismatch" unless the host compiler is `-m32`.
- `vm_x86.dasc` can be exercised at runtime on x64 with `mingw32-make XCFLAGS=-DLUAJIT_DISABLE_GC64` (x64-no-GC64 uses that file).
- Conditional configs: `XCFLAGS=-DLUAJIT_DISABLE_JIT` and `-DLUAJIT_DISABLE_PROFILE` (both need a clean build).

## 6. Harness lessons

- `jit.attach(fn, 'trace')` is the only way to observe start/stop/abort/flush; the handler gets the sub-event name as its argument. Attaching to `'flush'` silently never fires, and a C function (light C function) is an invalid vmevent handler — wrap it: `jit.attach(function(w) if w=='flush' then PROBE() end end, 'trace')`.
- Bounds-check every assumption: `jit.util.funcbc` gives the logical instruction, `jit.vmdef.bcnames` is 6 chars per opcode, and JMP slots in `if`/`while` bodies may never execute — probe which slots actually run before asserting a trap fires.
