---
name: tarantool-luajit-windows-mingw-build
description: Build the tarantool/luajit tree (sysprof fork) with MinGW on Windows and verify the profilers; not for upstream v2.1 or MSVC.
---

# Building tarantool/luajit on Windows with MinGW

Tarantool's fork ships only a CMake build that hard-fails on Windows
(`CMakeLists.txt`: "Please use the old build system") and has no
`src/Makefile` / `msvcbuild.bat`. Build it with the upstream v2.1 Makefile.

## Setup (once per worktree)

```sh
git worktree add --detach <dir> tarantool/master   # or your branch
cp <upstream-v2.1>/src/Makefile      <dir>/src/Makefile
cp <upstream-v2.1>/src/Makefile.dep  <dir>/src/Makefile.dep
```

Patch the copied Makefile:

1. Object lists: drop `lib_buffer.o`, `lj_prng.o`, `lj_serialize.o`; add
   `lib_misc.o` to `LJLIB_O` and `lj_wbuf.o lj_utils_leb128.o lj_memprof.o
   lj_profile_timer.o lj_symtab.o lj_sysprof.o lj_mapi.o` to `LJCORE_O`.
2. Delete the `luajit.h:` rule that needs `luajit_rolling.h` /
   `host/genversion.lua` (tarantool checks in `luajit.h`), and remove
   `luajit.h` from `ALL_HDRGEN` so `make clean` keeps it.
3. Pass the sysprof flag to dynasm (the VM only stashes the Lua frame
   pointer under `|.if LJ_HASSYSPROF`, and that conditional is dynasm-side,
   not C-preprocessor-side):

   ```make
   ifneq (,$(findstring LJ_HASSYSPROF 1,$(TARGET_TESTARCH)))
     DASM_AFLAGS+= -D LJ_HASSYSPROF
   endif
   ```

   Without it the first guest sample walks a NULL `top_frame_info.top_frame`
   and crashes. Same requirement for `msvcbuild.bat` (`DASMFLAGS`) and for
   CMake (`cmake/SetDynASMFlags.cmake`).
4. `sed -i 's/ lj_prng\.h//g; s/ lj_serialize\.h//g; s/ lib_buffer\.h//g'
   src/Makefile.dep` (the dep file came from upstream).

## Build

```sh
cd <dir>/src
mingw32-make BUILDMODE=static CCDEBUG=-g XCFLAGS=-DLUAJIT_ENABLE_GC64   # symbols, for tests
mingw32-make XCFLAGS=-DLUAJIT_ENABLE_GC64                              # release (dynamic)
```

Pitfalls:

- Use `CCDEBUG=-g`, not `CCOPT="-O2 -g"`: only `CCDEBUG` also disables
  `--strip-unneeded`, otherwise `nm`/gdb show nothing.
- Build serially (no `-j`): `Makefile.dep` has no rule for `lib_misc.o`, so a
  parallel build races `lj_libdef.h` and fails.
- Switching `BUILDMODE` requires `make clean` (stale objects then link
  against `__imp_lua_error`).
- `make clean` deletes generated headers; restore tracked `src/luajit.h` with
  `git checkout -- src/luajit.h`.
- Run the exe by full path; this shell does not resolve `./luajit`.

## Verify

```sh
luajit -e 'print(jit.version); print(type(require("misc").sysprof))'
# parse a profile: the event count must equal report().samples
luajit -e 'package.path="tools/?.lua;tools/?/init.lua;src/?.lua;"..package.path
           local e=require("utils.evread"); local sp=require("sysprof.parse")
           local ev=e(sp.parse, os.getenv("TEMP").."/p.bin"); local n=0
           for _,c in pairs(ev) do n=n+c end; print(n)'
luajit -ts <profile.bin>                     # tool entry (needs luajit.c -t)
```

Note: `luajit tools/sysprof.lua <file>` does nothing — that module *returns*
a function and must be entered through `-t` (tarantool extension) or called
from `-e`.

For stack/merge work, `test/win-probes/veh-unwind-probe.exe 300` must exit 0
(unwinder agrees with `RtlCaptureStackBackTrace`, no leaked TF).

## Profiler-specific gotchas

- Profile files must be opened `O_BINARY`: text mode expands `0x0a` and
  corrupts the stream.
- `lj_trace_flushall` calls `lj_gdbjit_deltrace` directly, not through
  `lj_trace_free`; trace-deletion hooks need both sites.
- Windows compiles `save_vmstate`/`restore_vmstate` out of `vm_x64.dasc`, so
  a CFUNC sample's stashed base can be stale — start the Lua walk from
  `L->base` with stack bounds checks.
- JIT mcode: unwind past it via the SEH entry frame,
  `RA = [L->cframe + CFRAME_SIZE - 8]`, caller `RSP = cframe + CFRAME_SIZE`.
- The sampler must never walk `J->trace` (it can be reallocated mid-suspend):
  keep a snapshot sized `JIT_P_maxtrace + 1` written by the profiled thread.
