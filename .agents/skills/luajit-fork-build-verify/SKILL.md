---
name: luajit-fork-build-verify
description: "Build and verify a LuaJIT fork on this Windows box with MinGW: clean-rebuild rule, stale Makefile.dep traps, running native binaries via cmd.exe, cross-arch dasc/buildvm checks."
---

# LuaJIT fork: build + verify on this Windows box (MinGW, no MSVC)

Applies to `C:/Users/fesil/LuaJIT` and worktrees under `C:/Users/fesil/.omp/wt/*`.
Toolchain: MinGW gcc 16.2 + `mingw32-make`. No Visual Studio (vswhere returns nothing), so
`src/msvcbuild.bat` cannot be exercised — say so instead of claiming it.

## 1. Always clean-rebuild after touching a header or a struct

```
cd src && mingw32-make clean >/dev/null 2>&1 && mingw32-make -j8
```

`src/Makefile.dep` is checked in but stale/target-specific, so an incremental build happily
keeps objects compiled against the old `GG_State`, `lj_bc_mode`, `global_State`, etc. Symptoms
seen: SIGSEGV inside `vm_exit_handler`/`lj_vm_cpcall`, wild jump targets (`0x6c0000006b`),
`CCallState has no member` / `'nfpr'` style errors from a stale `buildvm_arch.h`, or a crash that
*moves* when you add a `printf`. If any of those appear, suspect stale objects before the code.

## 2. `make depend` on this host degrades the file

`mingw32-make depend` regenerates `Makefile.dep` with the host flags, which loses
`lj_assert.o`'s headers (guarded by `LUA_USE_ASSERT`) and `lj_opt_split.o`'s headers
(guarded by `LJ_HASJIT && (LJ_SOFTFP32 || (LJ_32 && LJ_HASFFI))`). After regenerating, restore
those two stanzas from `git show HEAD:src/Makefile.dep`, then verify the diff semantically:

```python
# compare per-object token sets, ignoring line wrapping
txt = txt.replace('\\\n', ' ')
```

Expected diff: only the new/changed object stanzas and added headers.

## 3. Running built binaries from the agent shell

Native `.exe` under the repo cannot be exec'd directly (`command not found`, or a silent
exit code such as 88/5). Use:

```
cmd.exe /c "cd /d C:\Users\fesil\.omp\wt\<wt> && prog.exe args"
```

Crashes eat buffered stdout: put `setvbuf(stdout, NULL, _IONBF, 0);` first in `main`.
`gcc`/`mingw32-make`/`git`/`cmd.exe` are runnable; `cygpath` may be missing under `bash -c`, so
compute Windows paths by hand (`/c/...` → `C:/...`) in scratch scripts, and keep every path
repo-relative or drive-qualified — MinGW/Python binaries do not understand MSYS `/tmp`.

## 4. Harness pattern that works here

Embed Lua through the public C API (never internal headers) and link:

* `src/libluajit-5.1.dll.a`  — fast, needs `lua51.dll` next to the exe.
* `src/luajit.a` via `mingw32-make libluajit.a` then `gcc ... libluajit.a -lws2_32 -lpsapi -luuid -lm`
  — preferred for debugging: gdb resolves symbols in a static exe, not in the MinGW DLL.

Assertion style: one scenario per `lua_State`, print measured values (counts, `jit.status()`,
`jit.util.traceinfo`, Lua return values), `return failures ? 1 : 0`, and add a per-test selector
(`argv[1]`) because each case costs seconds and a crash hides the rest.

gdb: `gdb.exe -batch -x script.gdb --args prog.exe 2`; `p $_siginfo` prints the Windows
access-violation address, `bt` is useful only with the static link.

## 5. Configurations worth re-verifying after a VM/수 core change

Each needs `mingw32-make clean` first; rebuild the harness against the new lib each time.

| flag | exercises |
|---|---|
| (none) | `vm_x64.dasc`, GC64 — the default target |
| `XCFLAGS=-DLUAJIT_DISABLE_GC64` | `vm_x86.dasc` picked for the x64 build → x86 backend runs at runtime |
| `XCFLAGS=-DLUAJIT_DISABLE_JIT` | interpreter-only builds, `#if LJ_HASJIT` gaps |
| `XCFLAGS=-DLUAJIT_DISABLE_PROFILE` | `#if LJ_HASPROFILE` gaps, stub APIs |
| `mingw32-make amalg` | `ljamalg.c`; `LJ_FUNC` becomes `static`, so unused helpers surface as `-Wunused-function` |

## 6. Validating VM backends that cannot run here

Per-dasc preprocessing (catches bad `|` directives, macro/register misuse):

```
cmd.exe /c "cd /d ...\src && host\minilua.exe ..\dynasm\dynasm.lua <flags> -o <scratch>\buildvm_arch.h vm_<arch>.dasc"
# flags: -D ENDIAN_LE -D JIT -D FFI [-D DUALNUM] [-D FPU] [-D P64 for 64-bit] | ppc uses -D ENDIAN_BE
```

Real assembly generation for 64-bit targets on an x64 host: copy `host/buildvm.c buildvm_asm.c
buildvm_lib.c buildvm_fold.c buildvm.h buildvm_libbc.h` to a scratch dir, add the generated
`buildvm_arch.h` plus a stub

```c
#include "buildvm.h"
void emit_peobj(BuildCtx *ctx) { (void)ctx; }
```

then `gcc -I <scratch> -I src -I dynasm -DLUAJIT_TARGET=LUAJIT_ARCH_ARM64 <files> -o buildvm.exe`
and `buildvm.exe -m elfasm -o vm.S`. This also proves every `BCDEF` opcode has a `case` in the
dasc (buildvm errors `undefined opcode BC_x` otherwise). 32-bit targets (x86/arm/mips/ppc) stop
with `Error: pointer size mismatch in cross-build` — they need a 32-bit host buildvm
(`HOST_CC="gcc -m32"`, unavailable here). Record them as unverified; `host/minilua.exe` must be
built first (`mingw32-make host/minilua.exe`) and a fresh `make clean` deletes it.

## 7. Reporting

Never claim cross-arch/MSVC results that were not produced. State per configuration: built?
ran? which tests? and which surfaces are review-only.
