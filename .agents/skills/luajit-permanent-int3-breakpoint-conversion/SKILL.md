---
name: luajit-permanent-int3-breakpoint-conversion
description: "Convert LuaJIT's one-shot BC_INT3 trap into permanent breakpoints: entry lifecycle, logical-instruction continuation per backend, slow-path opcode resolution, harness migration, teeth checks."
---

# LuaJIT permanent BC_INT3 breakpoint conversion

Use when a LuaJIT fork's `BC_INT3` interrupt is one-shot/deferred and must become a
permanent breakpoint (fires on every execution until explicitly disarmed). Applies to
the `int3` worktree (`src/lj_int3.c`, `int3-smoke.c`).

## Model

- `Int3Entry { GCproto *pt; BCPos bcpos; BCIns ins; int nojit; }`; `pt != NULL` means
  "armed and planted". No `planted`/`skipped`/`last_pt`/`last_bcpos` state.
- Arm = `setbc_op(slot, BC_INT3)` **keeping A/B/C/D** (operand re-reads stay valid);
  capture the full original instruction into `ins` first, root the proto
  (`GCROOT_INT3+i`), set `PROTO_NOJIT`, flush traces only when the proto has no entry.
- Hit = copy `{pt,bcpos,ins}` to locals, deliver callback, return `ins`. **Never**
  restore the slot, never decrement count, never drop root/NOJIT. A callback that
  cancels/stops still gets its own instruction executed once.
- Restore only in `cancel_entry()`/`cancel_all()` (explicit cancel, stop, `lj_int3_close`).
  Pass `nojit` ownership to a surviving entry of the same proto; only the last one
  clears `PROTO_NOJIT` + `lj_trace_reenableproto`.
- Delete `HOOK_INT3` entirely (it borrowed `HOOK_PROFILE`): `hook_entergc`/`hook_restore`
  become plain macros, `lj_dispatch_update` loses the reconcile/stepping branches,
  `lj_dispatch_ins` loses the plant-at-boundary call. Keep the
  `disp[BC_INT3] = makeasmfunc(lj_bc_ofs[BC_INT3])` pin in `lj_dispatch_update`.
- Arming from a Lua debug hook becomes **immediate**; start/cancel/stop stay refused.

## The one thing that bites: opcode re-reads

Because the slot keeps `BC_INT3`, every path that re-reads the *opcode* of the
instruction it is about to execute needs the shadow. Add a leaf helper and call it:

```c
LJ_FUNCA BCIns LJ_FASTCALL lj_int3_ins(lua_State *L, const BCIns *pc)
{ return lj_int3_bcins(G(L), pc-1); }   /* !LJ_HASPROFILE: return pc[-1]; */
```

Sites requiring it (all seven `vm_*.dasc`):

- the hook/recorder continuation where the C hook returns (`4:`/`5:` labels) and the
  `cont_hook` yield-resume which jumps into the same path — compare the physical
  opcode against `BC_INT3`, and on match call the helper, re-decode A/op/D and dispatch
  through `GG_DISP2STATIC` (the hook already ran);
- `lj_meta_arith`/`lj_meta_bitop`/`lj_meta_comp`/`lj_meta_equal_cd`: those slow paths
  load the opcode with `PC_OP`; resolve with
  `bc_op(lj_int3_ins(L, cframe_pc(cframe_raw(L->cframe))))` (guarded by `op == BC_INT3`),
  which works because `lj_int3_hit` set `cframe_pc` to `slot+4` and nothing else runs
  before the slow path;
- x86/x64 `vmeta_tgets`/`vmeta_tsets`: they used `cmp PC_OP, BC_GGET` to pick the
  `tmptv` (global) vs `BASE+RB` (slot) operand. Replace with two entries —
  `vmeta_tgets` (table value in `RB`, store to `g->tmptv`) and
  `vmeta_tgets1` (reload `RB` from `PC_RB` → `&BASE[RB]`) — and point `checktab` at
  `...1`. Getting this backwards stores a non-table TValue tagged `LJ_TTAB` and crashes
  on ordinary string method calls (`s:sub`);
- ARM only: `vmeta_unm` pre-reads the slot; set `OP = #BC_UNM` instead.

Do **not** touch operand-only readers (`PC_RA/PC_RB/PC_RC/PC_RD`, call-dispatch and
stitch `lw INS,-4(PC)` decodes) — the trap preserves them.

Per-backend C-call contract, copy from the existing `BC_INT3` handler: x64
`L:RB=SAVE_L; L:RB->base=BASE; CARG2=PC; CARG1=L:RB; SAVE_PC=PC; call; BASE=L:RB->base;
decode from RCH/RCL/RCd`. x86 uses `@8` decoration and `FCARG1/FCARG2`. ARM rebuilds
`INS` (=lr) from `CARG1`. ARM64 `mov INSw, CARG1w`. MIPS/MIPS64 need
`load_got` + `call_intern` + `CARG1` set (delay slot holds SAVE_PC) and stash MULTRES.
PPC `bl extern` + stash MULTRES. x64/x86/arm/arm64 keep MULTRES in a stack slot.

## Harness migration (int3-smoke.c)

- Counts become exact execution counts (loop of N → N deliveries), no ranges; cancel
  between phases because slots stay armed.
- Hook arming: the instruction the hook belongs to must deliver **0** hits (continuation
  resolves the shadow), a later slot / call-hook-armed callee body delivers immediately.
- Cover RETM + `LUA_MASKRET`, ITERC (needs a non-`next` iterator, else the parser emits
  ISNEXT/ITERN), yield-from-hook resume, cancel/stop at hit N (side effects of the Nth
  hit must still happen), full-table stays full after hits, idempotent self-arm.
- Add a delivery watchdog (cap ~100000, print + `exit(1)`) so a re-dispatch defect
  reports instead of hanging.
- Guard `jit.opt`/`jit.off` sub-cases with `#if !defined(SMOKE_NO_JIT)`; the no-JIT run
  must pass.

## Verification protocol

1. MinGW: `mingw32-make clean && mingw32-make -j8 XCFLAGS="..."` then
   `gcc -I . ../int3-smoke.c libluajit-5.1.dll.a -o int3-smoke.exe`; **clean rebuild
   after every dasc/flags change** (stale `host/buildvm_arch.h` masks errors).
   Matrix: GC64 + `LUA_USE_ASSERT`; non-GC64 (vm_x86); `LUAJIT_DISABLE_JIT` +
   `-DSMOKE_NO_JIT`; `LUAJIT_DISABLE_PROFILE` + `-DSMOKE_NO_PROFILE`; both.
2. DynASM: `host/minilua.exe ../dynasm/dynasm.lua <ENDIAN/P64/JIT/FFI/DUALNUM/FPU/HFABI/VER=21/WIN> -o out.lua vm_X.dasc`
   for all 7 backends × JIT/no-JIT (x86 with `-D P64` covers x32).
3. Non-host arches: copy `host/buildvm*.c buildvm.h buildvm_libbc.h` + the generated
   `buildvm_arch.h` into a temp dir and `gcc -fsyntax-only ... -DLUAJIT_TARGET=LUAJIT_ARCH_<A> buildvm_asm.c`
   (catches removed C macros). Do not expect `buildvm -m elfasm` to run on this host.
4. Teeth: re-add the consume call in `lj_int3_hit` → expect ~46 failures; drop the
   `BC_INT3` branch in one continuation → watchdog failure; stub the meta opcode
   resolver or revert the tgets split → crash in the slow-path tests. Revert each variant.
