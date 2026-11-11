---
name: luajit-sysprof-windows-build-and-port
description: "Build tarantool/luajit with MinGW on Windows and port/debug sysprof + jit.profile host sampling; use for sysprof crashes, stream corruption, or missing Lua/host stacks on Windows."
---

# LuaJIT (tarantool fork) on Windows: build + sysprof/jit.profile host sampling

Use when working on tarantool/luajit's sysprof or `jit.profile` under Windows x64 (no MSVC project; CMake build refuses Windows).

## Build (MinGW-w64)

1. `git worktree add --detach <dir> tarantool/master` from the user's LuaJIT clone.
2. Copy `src/Makefile` and `src/Makefile.dep` from an upstream LuaJIT v2.1 checkout (tarantool ships only CMake), then:
   - object lists: drop `lj_prng.o`, `lj_serialize.o`, `lib_buffer.o`; add `lib_misc.o lj_wbuf.o lj_utils_leb128.o lj_memprof.o lj_profile_timer.o lj_symtab.o lj_sysprof.o lj_mapi.o`;
   - delete the `luajit.h` generation rule and drop `luajit.h` from `ALL_HDRGEN` (tarantool checks it in);
   - remove `lj_prng.h`/`lj_serialize.h`/`lib_buffer.h` deps from `Makefile.dep`;
   - add to the dynasm flags:
     `ifneq (,$(findstring LJ_HASSYSPROF 1,$(TARGET_TESTARCH)))` / `DASM_AFLAGS+= -D LJ_HASSYSPROF`.
3. Build **serially** (`-j` races: `lib_misc.o` may compile before `lj_libdef.h` exists):
   - `mingw32-make XCFLAGS=-DLUAJIT_ENABLE_GC64` (release, DLL)
   - `mingw32-make BUILDMODE=static CCDEBUG=-g XCFLAGS=-DLUAJIT_ENABLE_GC64` (symbolized)
   - For pageable debug vars use `CCDEBUG=-g CCOPT=-O0`; `CCOPT=-g` alone is stripped by TARGET_STRIP.
4. `mingw32-make clean` between static and dynamic builds (luajit.o/lib flags differ); restore `src/luajit.h` afterwards if it was deleted (it is tracked).
5. Run binaries by absolute path including `.exe` (the shell does not resolve `./luajit`).

## Mandatory invariants

- `LJ_HASSYSPROF` must reach **dynasm**, not only the C compiler. Missing -> vm_x64.dasc omits `top_frame_info` stores -> sampler walks NULL and crashes on the first sample.
- GC64 is required on x64 (`XCFLAGS=-DLUAJIT_ENABLE_GC64`); without it the arch probe yields `LJ_FR2 0` and dynasm picks vm_x86.dasc.
- Profile output files must be opened with `O_BINARY` on Windows, otherwise `0x0a` becomes `0x0d 0x0a` and the stream misparses (symptom: symtab ends early, "Bad LuaJIT symbol table format prologue").

## Known Windows-specific trap: stale BASE in CFUNC

`save_vmstate`/`restore_vmstate` in vm_x64.dasc are `#if not WIN` no-ops, so `g->vmstate` and `top_frame_info.top_frame` are not refreshed around C calls. A sampler that suspends the thread in CFUNC state can read a stashed BASE pointing at reused slots -> crash inside the Lua frame walk. Fix: for `LJ_VMST_CFUNC` walk from `L->base`, and validate the chain against `[tvref(L->stack)+LJ_FR2, L->top]` and the stack end before dereferencing.

## Deterministic Lua/host merge without symbols

- PE `.pdata` survives stripping. `RtlLookupFunctionEntry(pc)` gives the containing function's `BeginAddress`; emit `pc - begin + 1` (0 = unknown) next to each host frame so the merge needs no symbol table.
- buildvm_peobj emits exactly two `.pdata` entries for the whole VM asm blob: look up `lj_vm_asm_begin` and `lj_vm_profhook` to learn both function starts and mark VM frames (a `SYMTAB_VM` record in the ljs symtab).
- Merge rule: match each Lua CFUNC frame to the host frame with the same entry address and splice its callees; bound fast-function (FFUNC) groups by the next VM frame; drop VM frames. Never match on symbol names (e.g. `lua_pcall`).
- `jit.profile` samples at a VM safepoint on the profiled thread: capture in-thread with `RtlCaptureStackBackTrace(skip=4)` (skip capture helper, `lj_profile_interpreter`, `lj_dispatch_profile`, `lj_vm_profhook`); do not suspend.

## Verification

- `misc.sysprof.start{mode="C", interval=1, path=...}` then stop; compare `misc.sysprof.report().samples` with the number of parsed events (`tools/utils/evread.lua` + `tools/sysprof/parse.lua`, `LUA_PATH="tools/?.lua;tools/?/init.lua;src/?.lua;;"`). They must match exactly.
- Resolve captured addresses with `nm -n luajit.exe` + base subtraction (MinGW debug builds carry COFF function symbols; release builds do not).
- Stress: repeat start/stop 100-200 times with a `table.sort` + Lua-comparator workload and a `string.find` workload; any crash is a sampling-safety bug.
