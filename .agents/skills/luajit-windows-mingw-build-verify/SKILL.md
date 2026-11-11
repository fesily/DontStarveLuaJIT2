---
name: luajit-windows-mingw-build-verify
description: "Build and verify a LuaJIT fork on this Windows box with MinGW (no MSVC), incl. clean-rebuild discipline, cmd.exe execution, and cross-arch dasc/buildvm checks"
---

# Windows MinGW build & verification recipe (LuaJIT fork)

## Build
- VS is absent (`vswhere -latest -products * -property installationPath` prints nothing) -> `src/msvcbuild.bat` and the plan's `cl ...` commands are NOT runnable. Use MinGW:
  - `cd src && mingw32-make -j8`
  - variants: `XCFLAGS=-DLUAJIT_DISABLE_JIT`, `-DLUAJIT_DISABLE_PROFILE`, `-DLUAJIT_DISABLE_GC64` (the last switches the backend to `vm_x86.dasc`).
- **Always `mingw32-make clean` after touching headers that feed generated layout** (`GG_State`/`GG_LEN_*` in `lj_dispatch.h`, `lj_bc.h` opcode list, `lj_obj.h`). Incremental builds leave stale objects -> random SIGSEGV inside `vm_exit_handler`/trace exits that look like VM bugs.

## Run
- The bash tool refuses to exec built binaries by path (`error: command not found` even when `ls` shows them) and `cmd //c` starts an interactive shell. Use:
  `cmd.exe /c "cd /d C:\...\src && prog.exe args"`
- Same for host tools: `cmd.exe /c "cd /d ...\src && host\minilua.exe ..\dynasm\dynasm.lua ..."`.
- Paths handed to native tools must be repo-relative or `C:/...`; `/tmp/...` is invisible to gcc/minilua.

## C harness against the DLL
- Link the import lib: `gcc -O1 -Wall -Wextra -I src harness.c src/libluajit-5.1.dll.a -o src/harness.exe` (MinGW names the import lib `libluajit-5.1.dll.a`, not `lua51.lib`).
- For symbolized crashes, build the static lib: `mingw32-make libluajit.a` then `gcc -g -O0 -I src harness.c src/libluajit.a -o src/static.exe -lws2_32 -lpsapi -luuid -lm`; gdb then resolves LuaJIT frames (DWARF in a DLL is not loaded).
- gdb: write a command file and run `cmd.exe /c "gdb.exe -batch -x g.gdb --args app.exe args"` (inline `-ex` quoting breaks on Windows paths). Breakpoints on asm entries (`lj_vm_cpcall`, `lj_vm_pcall`) are the fastest way to locate a crash call chain; `p $_siginfo.AccessViolationInformation` gives the faulting address.

## Cross-arch checks (no cross toolchain)
1. dasc preprocessing for every backend, JIT and no-JIT:
   `cmd.exe /c "cd /d <repo>\src && host\minilua.exe ..\dynasm\dynasm.lua -D ENDIAN_LE -D JIT -D FFI -D DUALNUM -D FPU [-D P64] -o <repo>\scratch\h.h vm_X.dasc"`
   (rmc: P64 only for arm64/mips64; ppc uses `-D ENDIAN_BE`.)
2. Real assembly generation (64-bit targets only): copy `host/buildvm*.c` + `host/buildvm_libbc.h` into a scratch dir, generate the target `buildvm_arch.h` **there** (name must be exactly `buildvm_arch.h`), add a stub `void emit_peobj(BuildCtx *ctx){(void)ctx;}`, then
   `gcc -O1 -I <scratch> -I src -I dynasm -DLUAJIT_TARGET=LUAJIT_ARCH_<ARM64|MIPS64> <scratch>/buildvm*.c <scratch>/peobj_stub.c -o <scratch>/buildvm.exe`
   and run `buildvm -m elfasm -o vm.S`. `buildvm` also validates opcode coverage: a `case BC_X:` missing from a dasc fails with `Error: undefined opcode BC_X`.
   ARM32/MIPS32/PPC die with `Error: pointer size mismatch in cross-build` (needs `HOST_CC="gcc -m32"`, unavailable here) — report them as unverified, never as passing.

## Harness pattern that works here
- Split scenarios into functions, `main` runs 1..N or all, print one line of measured facts per scenario, return non-zero if any check failed.
- Attach VM events only through a **Lua wrapper** (`jit.attach(function(...) _PROBE() end, 'trace')`); a raw `lua_pushcfunction` value is not a valid vmevent handler. Event names must be categories (`trace`); sub-events (`start`/`stop`/`abort`/`flush`) are matched on the first argument; the trace `abort` event's args are `(what, traceno, func, pos, errorcode, errinfo)` — the error code is the numeric `TraceError`.
