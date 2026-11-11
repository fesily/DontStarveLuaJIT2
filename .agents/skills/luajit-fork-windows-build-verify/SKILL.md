---
name: luajit-fork-windows-build-verify
description: "Build and acceptance-verify changes in the LuaJIT fork on this Windows host: MinGW-only toolchain, sandbox exec rules, clean-rebuild discipline, Makefile/Makefile.dep/ljamalg wiring, C harness linking, and cross-arch dasc/buildvm validation."
---

# Build + acceptance-verify LuaJIT fork changes on this Windows host

Repo: `C:/Users/fesil/LuaJIT` (Tarantool/sysprof fork). Work happens in git worktrees under `C:/Users/fesil/.omp/wt/<name>`; all worktrees share one `.git`, so refs/remotes are shared.

## Toolchain reality
- **No MSVC installed** (vswhere returns nothing) → ignore `src/msvcbuild.bat`; use MinGW: `mingw32-make` (gcc 16.2 at `C:/ProgramData/mingw64/mingw64/bin`).
- **Sandbox blocks exec of arbitrary binaries** from the worktree (`./foo.exe`, `/c/Windows/System32/x.exe` → "command not found"). Everything runs through cmd:
  `cmd.exe /c "cd /d C:\path\to\repo\src && luajit.exe script.lua"`.
- Native tools (gcc, python, minilua) do **not** see MSYS `/tmp` or `/c/...`: use `C:/tmp/...` for python/gcc, `/c/tmp/...` only for shell redirects, and repo-relative paths in scripts.

## Build loop
```sh
cd src && mingw32-make clean && mingw32-make -j8            # serial-ish; -j is fine after deps are right
mingw32-make -j8 XCFLAGS=-DLUAJIT_DISABLE_GC64             # x86 backend (vm_x86.dasc)
mingw32-make -j8 XCFLAGS=-DLUAJIT_DISABLE_JIT
mingw32-make -j8 XCFLAGS=-DLUAJIT_DISABLE_PROFILE
```
- **Always `make clean` after header edits.** Stale objects that embed `GG_State`/`GG_LEN_*` offsets or opcode tables build fine but crash (SIGSEGV in trace exit / VM) — root cause every time so far.
- After adding a new `.c`: add it to `src/Makefile` `LJCORE_O`, to `src/ljamalg.c`, then `mingw32-make luajit.h && mingw32-make depend` (depend needs a generated luajit.h first), then **re-restore** `lj_assert.o` and `lj_opt_split.o` stanzas from the previous `Makefile.dep` (a regeneration on x64 drops their target-conditional headers).
- Windows/Xbox build scripts glob `lj_*.c` → no edits needed there.

## Acceptance harness pattern (C, public API only)
- Put the harness at the repo root (`int3-smoke.c`), compile: `gcc -O1 -Wall -Wextra -I src <harness>.c src/libluajit-5.1.dll.a -o src/<harness>.exe`, run via cmd. It links the MinGW import lib and finds `lua51.dll` in `src/`.
- Give the harness `#ifdef` modes for reduced builds (e.g. `SMOKE_NO_JIT`, `SMOKE_NO_PROFILE`) and guard test functions with `#if !defined(...)` so `-Wall -Wextra` stays warning-free.
- Do **not** call Lua APIs after `lua_close(L)` (looks like a VM crash in `lua_loadx`/`lj_vm_cpcall` with an unmapped `L`).
- Static build for symbolised gdb traces: `mingw32-make libluajit.a && gcc -g -O0 -I src <harness>.c libluajit.a -o x.exe -lws2_32 -lpsapi -luuid -lm`.
- vmevent probes: `jit.attach` rejects light C functions; attach a Lua wrapper `function(w) if w == 'flush' then PROBE() end end` and the event **category** (`'trace'`, `'record'`), not the sub-event name.

## Cross-arch VM validation without cross toolchains
- Preprocess every backend: `cmd.exe /c "cd /d <win>\src && host\minilua.exe ..\dynasm\dynasm.lua -D ENDIAN_LE -D JIT -D FFI -D DUALNUM -D FPU [-D P64|-D ENDIAN_BE] -o <win>\tmp\h.h vm_<arch>.dasc"`.
- Generate real assembly for 64-bit targets on an x64 host: copy `host/buildvm*.c buildvm.h buildvm_libbc.h` to a scratch dir, generate that arch's `buildvm_arch.h` there, add a stub `emit_peobj`, compile `-I <scratch> -I src -I dynasm -DLUAJIT_TARGET=LUAJIT_ARCH_<ARCH>`, then run `buildvm -m elfasm`. Undefined pc labels surface as "Error: undefined opcode BC_xxx" (useful opcode-coverage check).
- 32-bit targets (x86/arm/mips/ppc) cannot be cross-built here: buildvm aborts with "pointer size mismatch in cross-build" (needs `HOST_CC="gcc -m32"`, no multilib available).
- Baseline defect on `sysprof-v2.1`: non-x64 backends still use `LJ_VMST_C`; add **build-only** `-DLJ_VMST_C=LJ_VMST_CFUNC` to validate without touching the tree.

## Reporting
State per configuration: build result, harness pass/fail count, and any pre-existing (not ours) breakage with its exact error. Never claim cross-arch runtime passes; name the level actually verified (dynasm / elfasm generation / runtime).
