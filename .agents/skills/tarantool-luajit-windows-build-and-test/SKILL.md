---
name: tarantool-luajit-windows-build-and-test
description: Build tarantool/luajit on Windows with MinGW (no CMake support) and run its sysprof/jit.profile test harness
---

# Build

1. `git worktree add <tmp> tarantool/master` (the CMake build refuses Windows: "Please use the old build system").
2. Copy upstream LuaJIT v2.1 `src/Makefile` + `Makefile.dep` into `<tmp>/src` and patch:
   - LJLIB_O: `lib_buffer.o` -> `lib_misc.o`.
   - LJCORE_O: drop `lj_prng.o`, `lj_serialize.o`; add `lj_wbuf.o lj_utils_leb128.o lj_memprof.o lj_profile_timer.o lj_symtab.o lj_sysprof.o lj_mapi.o`.
   - Delete the `luajit.h:` rule and remove `luajit.h` from ALL_HDRGEN (tarantool checks it in; `make clean` deletes generated headers).
   - `sed -i 's/ lj_prng\.h//g; s/ lj_serialize\.h//g; s/ lib_buffer\.h//g' Makefile.dep`.
   - Add the sysprof dynasm flag: `ifneq (,$(findstring LJ_HASSYSPROF 1,$(TARGET_TESTARCH))) DASM_AFLAGS+= -D LJ_HASSYSPROF endif`.
3. `cd src && mingw32-make BUILDMODE=static CCDEBUG=-g XCFLAGS=-DLUAJIT_ENABLE_GC64` (serial; `-j` races on lj_libdef.h). Without GC64 the arch probe yields LJ_FR2=0 and dynasm picks vm_x86.dasc.
4. `mingw32-make clean` needs `git checkout -- src/luajit.h` afterwards.

Symbols: CCDEBUG=-g disables the strip and keeps the COFF symbol table (nm resolves `lj_sysprof_*`, `lj_vm_profhook`); without it the exe has only import symbols.

# Test harness

- Run scripts with the full path to `luajit.exe` (this shell fails on `./luajit.exe`).
- Profile tools load through the `-t` option: `LUA_PATH="tools/?.lua;tools/?/init.lua;src/?.lua;;" luajit.exe -ts out.bin` (the script returns a function; running the .lua file directly does nothing).
- Direct API: `require("misc").sysprof.start{mode="C", interval=1, path=...}`; `jit.profile.start("i1h", cb)` + `jit.profile.hoststack/mixedstack/symtab`.
- `jit.profile` samples at VM safepoints only, so `-joff` workloads avoid trace noise; sysprof samples arbitrary PCs from a timer thread.

# Debugging

- `gdb -batch -x cmds --args luajit.exe` with `run -joff script.lua` + `thread apply all bt` works once CCDEBUG=-g is set; use CCOPT=-O0 for readable locals.
- A crashed SAMPLER shows up on a non-main thread inside lj_sysprof.c; check lj_sysprof.c, not the workload.
