---
name: luajit-windows-build-and-backend-verify
description: "Build this LuaJIT fork with MinGW on Windows, run a C-API harness against it, and validate all 7 VM dasc backends (dynasm + cross buildvm elfasm) when no cross toolchain exists."
---

# Build + verify a LuaJIT fork change on Windows (MinGW, no MSVC)

Repo = the LuaJIT rolling fork worktree; all commands are bash with `cd <repo>/src`.

## 0. Hard constraints on this box
- No Visual Studio (`vswhere` empty) → `msvcbuild.bat` path is unverifiable; use `mingw32-make` (gcc 16.2 at `C:/ProgramData/mingw64/mingw64/bin`).
- The sandbox blocks exec of arbitrary `.exe` paths (`./luajit.exe` → "command not found"), but `cmd.exe /c "cd /d <winpath> && tool.exe args"` works. Use `cmd.exe /c` for every built binary (luajit.exe, minilua.exe, buildvm.exe, harness).
- Paths handed to native tools must be Windows-ish: `/tmp/...` fails for gcc/ld; use repo-relative paths or `C:/...`.

## 1. Clean build (ALWAYS after header/BCDEF changes)

```
cd <repo>/src && mingw32-make clean && mingw32-make -j8
```

`make` does NOT track header dependencies. Changing `lj_bc.h` (BCDEF/opcode order) or `lj_dispatch.h` (`GG_State`, `GG_LEN_*`) without `clean` leaves stale `.o` files that assume the old layout → crashes inside `vm_exit_handler` on the first JIT trace exit. Always `clean` after header edits.

Variants: `XCFLAGS=-DLUAJIT_DISABLE_JIT`, `-DLUAJIT_DISABLE_PROFILE`, `-DLUAJIT_DISABLE_GC64` (the last switches x64 to `vm_x86.dasc`, giving a runnable path for that backend in 64-bit mode).

## 2. C-API harness

```
gcc -O1 -Wall -Wextra -I . ../<harness>.c libluajit-5.1.dll.a -o <harness>.exe
cmd.exe /c "cd /d <win repo>\src && <harness>.exe [mode]"
```

Import lib is `libluajit-5.1.dll.a` (not `lua51.lib`); the DLL must sit next to the exe. Build the harness with the matching `-DSMOKE_NO_JIT` / `-DSMOKE_NO_PROFILE` mode for conditional builds. Prefer a static link for symbolized crashes:

```
mingw32-make libluajit.a
gcc -g -O0 -I . ../<harness>.c libluajit.a -o static.exe -lws2_32 -lpsapi -luuid -lm
```

Debugging: `printf` with `setvbuf(..., _IONBF, 0)` — a crash loses buffered stdout. `gdb -batch -x script.gdb` works for the static build (DWARF in a DLL is not resolved), and `p $_siginfo.AccessViolationInformation` gives the faulting address.

## 3. Cross-validate all VM dasc backends (no cross gcc needed)

Only two checks are possible here:

(a) dynasm preprocessing of every backend (catches dasc syntax/macro errors; also validates JIT-off variants):

```
mkdir -p tmpbuild/dyn_<arch>
cmd.exe /c "cd /d <win repo>\src && host\minilua.exe ..\dynasm\dynasm.lua <flags> -o <win>\tmpbuild\dyn_<arch>\h.h vm_<arch>.dasc"
```

Flags: x64/arm64/mips64 `-D ENDIAN_LE -D JIT -D FFI -D DUALNUM -D FPU -D P64`; arm/mips `... -D DUALNUM -D FPU` (no P64); x86 `-D ENDIAN_LE -D JIT -D FFI -D FPU`; ppc `-D ENDIAN_BE ...`. Drop `-D JIT` for the no-JIT variant.

(b) real assembly generation for 64-bit targets via a scratch buildvm:

```
cp src/host/buildvm*.c src/host/buildvm.h src/host/buildvm_libbc.h tmpbuild/bv_<arch>/
printf '#include "buildvm.h"\nvoid emit_peobj(BuildCtx *ctx) { (void)ctx; }\n' > tmpbuild/bv_<arch>/peobj_stub.c
gcc -O1 -I tmpbuild/bv_<arch> -I src -I dynasm -DLUAJIT_TARGET=LUAJIT_ARCH_<ARM64|MIPS64> \
    tmpbuild/bv_<arch>/buildvm*.c tmpbuild/bv_<arch>/peobj_stub.c -o tmpbuild/bv_<arch>/buildvm.exe
cmd.exe /c "cd /d <win repo> && tmpbuild\bv_<arch>\buildvm.exe -m elfasm -o tmpbuild\bv_<arch>\vm.S"
```

Must generate `buildvm_arch.h` from the same dasc earlier (with `host/minilua.exe`). The peobj stub is required because the real emitter has no branch for non-x86 targets on a Windows host. `buildvm` also acts as the opcode-coverage checker: a missing `case BC_x:` fails with "undefined opcode BC_x".

32-bit targets (x86/arm/mips/ppc) cannot be assembled here: buildvm aborts with "pointer size mismatch in cross-build" (needs a 32-bit host buildvm), so report dynasm-only for them.

## 4. Finish
- Restore the default configuration (`clean && make`) so the worktree is left with the standard x64 build.
- Delete scratch dirs (`tmpbuild/`, `*.gdb`, probe `.c`/`.exe`) — they are untracked noise.
- Run the harness of every configuration one last time and keep its stdout as evidence.
