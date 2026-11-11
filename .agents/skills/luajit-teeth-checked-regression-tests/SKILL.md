---
name: luajit-teeth-checked-regression-tests
description: "Regression tests in this LuaJIT fork that pin a guard/refusal/ABI invariant: pre-state assertion, teeth check by deleting the guard, bounded livelock caps, Win64 register probe."
---

# When to use

Adding or repairing a regression test in this LuaJIT fork that must FAIL if a guard, refusal or asm invariant is reverted (armability lists, context guards, ABI preservation). A test that cannot fail is worse than none, so every new assertion gets a *teeth check* before commit.

# Recipe

1. **Pin the pre-state first.** Never assert only the outcome. Read the actual state with a public probe and assert it, so the test cannot silently degrade into exercising a different path:
   - bytecode: `jit.util.funcbc` + `jit.vmdef.bcnames` (`funcbc` returns int32; mask with `& 0xffu` because instructions with the high bit set come back negative);
   - JIT shape: build the state deliberately (`jit.off(f, true)` → `PROTO_NOJIT`; `jit.opt.start('hotloop=1')` + one hot call → `trace_start()` patches `FORL→IFORL`, `FORI→JFORI` per lj_trace.c:517), then assert the opcode actually changed before testing the refusal;
   - armability: pick a slot whose state is deterministic (a freshly defined function has not been run, so `FORI`/`FUNCF`/`RET1` are still unpatched); avoid reusing a function that already ran hot, and avoid a slot another sub-test already armed (duplicate arm returns `OK`).
2. **Make one sub-test per opcode/guard**, each in its own `lua_State` if it dirties JIT/hook state, with `memset(&rec, 0, sizeof(rec))` at the start of each block (a stale `rearm/stop_after` flag from a previous case turns a passing test into an 8-failure cascade once the guard is removed).
3. **Teeth check** (mandatory): delete exactly the guard entry / bit / asm line under test, rebuild, run, and confirm ONLY the new assertions fail; quote the FAIL lines. Restore and prove `git diff <file>` is empty (or compare the blob hash) before committing.
4. **Bound anything that could livelock** when the guard is removed: cap hook events (`if (++n > 10000) return;` + `CHECK(n <= 10000)`) so a teeth run fails instead of hanging.
5. **ABI / register invariants are testable, not "unobservable"**: seed the non-volatile registers in a `__attribute__((naked))` Win64 wrapper (8 pushes, `sub rsp, 40` for 32-byte shadow space + alignment, args in rcx/rdx/r8/r9), call `lua_pcall`, compare a 7-bit mask. `lua_pcall` itself pushes/restores r12–r14, so ALSO sample from C functions called *inside* the Lua call (naked snapshot functions writing r12–r15 to globals) and compare before/after the trapped instruction. Skip when the loaded library is not GC64 (non-GC64 x64 runs the x86 backend; detect via the `BCDUMP_F_FR2` bit of `string.dump`).
6. **Non-vacuity**: assert the mechanism actually fired (`rec.calls >= N`, sample counter equals expected) before checking the payload, and assert the negative case too ("second call delivers nothing").

# Pitfalls seen

- Reduced configs (`-DSMOKE_NO_JIT`): `luaJIT_setmode(ENGINE|ON)` returns 0 without a JIT, so gate JIT-ownership assertions on `SMOKE_NO_JIT`; `trace_count()` is JIT-only.
- A harness run needs cwd = `src/` (it does `require('jit.vmdef')`).
- Build/relink commands: `mingw32-make clean`, `mingw32-make -j1 "XCFLAGS=-DLUAJIT_ENABLE_GC64" luajit.exe`, then `gcc -I src int3-smoke.c src/libluajit-5.1.dll.a -o src/int3-smoke.exe`.
- Non-host backends have no runtime: verify only via `minilua dynasm/dynasm.lua <flags> -o vm_<arch>.h vm_<arch>.dasc` (buildvm's `-m` selects an output format, not an architecture).
