---
name: tarantool-luajit-sysprof-windows
description: "Build/verify tarantool LuaJIT on Windows x64 with MinGW and work on the sysprof sampler (suspend+CONTEXT unwind, symbol stream, jit.profile host stacks)."
---

# Tarantool LuaJIT on Windows x64 (MinGW) + sysprof work

## Build (tarantool tree has no Windows build)

`CMakeLists.txt` aborts with "Please use the old build system" on Windows, so:

1. `git worktree add --detach <dir> tarantool/master`.
2. Copy upstream LuaJIT v2.1 `src/Makefile` + `src/Makefile.dep` into the tree, then:
   - `LJCORE_O`: drop `lj_prng.o`, `lj_serialize.o`; add `lj_wbuf.o lj_utils_leb128.o lj_memprof.o lj_profile_timer.o lj_symtab.o lj_sysprof.o lj_mapi.o`.
   - `LJLIB_O`: replace `lib_buffer.o` with `lib_misc.o`.
   - Delete the `luajit.h:` rule (tarantool checks `luajit.h` in) and drop `luajit.h` from `ALL_HDRGEN`, else `make clean` deletes a tracked file.
   - Strip `lj_prng.h`/`lj_serialize.h`/`lib_buffer.h` from `Makefile.dep`.
3. Build: `mingw32-make XCFLAGS=-DLUAJIT_ENABLE_GC64` (GC64 is mandatory: without it `LJ_FR2=0` and dynasm picks `vm_x86.dasc`).
   - First build must be serial: `lib_misc.o` has no dependency on generated `lj_libdef.h` and `-j8` races.
   - Debug symbols: `BUILDMODE=static CCDEBUG=-g` (a `-g` in `CCOPT` does NOT survive: the linker strips unless `CCDEBUG` is set). Never leave a DLL-built `luajit.o` when switching to `BUILDMODE=static` - `make clean` first.

## Pitfalls that cost hours

1. **dynasm must get `-D LJ_HASSYSPROF`** (tarantool's `cmake/SetDynASMFlags.cmake:121` does). Without it `vm_*.dasc` drops the `top_frame_info` stores, `g->top_frame_info.top_frame` stays NULL and the first guest sample segfaults in `stream_backtrace_lua`. Add to the Makefile: `ifneq (,$(findstring LJ_HASSYSPROF 1,$(TARGET_TESTARCH))) DASM_AFLAGS+= -D LJ_HASSYSPROF endif`.
2. **`open()` is text mode on Windows**: the profile stream gets `\n` -> `\r\n`, so the symtab parse drifts and dies in the middle of a name. Use `O_BINARY` (`lib_misc.c` `PROFILE_OPEN_FLAGS`).
3. `misc.sysprof` was compiled out by `#if !LJ_TARGET_WINDOWS` together with memprof; registration must move to `#if LJ_HASSYSPROF`.

## Verification loop

- Parse with the in-tree tool: `LUA_PATH="tools/?.lua;tools/?/init.lua;src/?.lua;;" luajit.exe tools/sysprof.lua out.bin`, or a small driver on `utils.evread` + `sysprof.parse` (`evread(sysprof.parse, path)` returns `events`).
- Success criterion: sum of event counts == `misc.sysprof.report().samples`, and `#ljp` prologue is found at the end of the symtab.
- Symbol resolution only works with a debug/static build (COFF symbol table); release MinGW binaries degrade to module-base entries. Resolve collected addresses with `nm -n luajit.exe` (base `0x140000000`) or subtract the sampled module base.
- Freeze-window measurement: QueryPerformanceCounter around `SuspendThread..ResumeThread`, print avg/max in `lj_sysprof_stop`. The tail comes from `write()` inside the frozen window; buffer-swap deferral removes it.
- `Sleep` granularity dominates sampling accuracy (~1.8 ms/sample even at interval=1 with `timeBeginPeriod(1)`); do not chase it in the sampler.

## Sampler design rules

- Lua stack must be read while the thread is stopped (VM stashes `BASE` at every vmstate transition in `vm_*.dasc`); host stack needs `RtlPcToFileHeader` + `RtlLookupFunctionEntry`/`RtlVirtualUnwind` from the saved CONTEXT. JIT mcode has no `.pdata`: stop the walk there (trace samples are streamed separately).
- Nothing may allocate or take locks the target could hold while it is frozen; defer `write()` and heap use until after `ResumeThread`.
- Any stream write from the profiled thread (symbol events) must be serialized against the sampler: re-check the profiler state after `SuspendThread` and skip the sample if the thread announced a symbol event.
- `jit.profile` (`lj_profile.c`) delivers callbacks on the profiled thread, so host capture happens in the timer thread and is published under `profile_lock` when the hook is armed; exposed via `jit.profile.hoststack([depth])` / `luaJIT_profile_hoststack()`.
