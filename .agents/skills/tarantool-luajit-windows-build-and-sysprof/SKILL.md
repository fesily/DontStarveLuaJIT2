---
name: tarantool-luajit-windows-build-and-sysprof
description: "Build tarantool's LuaJIT fork on Windows with MinGW and port/enable sysprof (SuspendThread sampler, CONTEXT unwinding, PE/COFF symtab); use when tarantool luajit must run or be profiled on Windows."
---

# Tarantool LuaJIT on Windows: build + sysprof

## 1. Why you must bootstrap a build system
- Root `CMakeLists.txt` aborts on Windows: `FATAL_ERROR "Please use the old build system"`.
- `src/Makefile` does not exist in the fork (CMake only).
- Workaround: worktree of `tarantool/master`, copy upstream LuaJIT v2.1 `src/Makefile` + `src/Makefile.dep`, then:
  - `LJLIB_O`: replace `lib_buffer.o` with `lib_misc.o`.
  - `LJCORE_O`: drop `lj_prng.o`, `lj_serialize.o`; add `lj_wbuf.o lj_utils_leb128.o lj_memprof.o lj_profile_timer.o lj_symtab.o lj_sysprof.o lj_mapi.o`.
  - Delete the `luajit.h:` rule (fork checks in `luajit.h`, has no `host/genversion.lua`/`.relver`) and drop `luajit.h` from `ALL_HDRGEN` so `make clean` does not delete it.
  - Strip `lj_prng.h`/`lj_serialize.h`/`lib_buffer.h` from `Makefile.dep`.
- Build commands (MinGW gcc):
  - release/dynamic: `mingw32-make XCFLAGS=-DLUAJIT_ENABLE_GC64` (GC64 is required; without it `LJ_FR2=0` and dynasm picks `vm_x86.dasc`).
  - symbolized: `mingw32-make clean && git checkout -- src/luajit.h && mingw32-make BUILDMODE=static CCDEBUG=-g XCFLAGS=-DLUAJIT_ENABLE_GC64` (`CCOPT=-O1 -g` does NOT add debug info; use `CCDEBUG=-g`).
  - Run serially: `-j` races on generated `lj_libdef.h` (lib_misc.o has no dep).
- Windows shell quirks: invoke `luajit.exe` by absolute path; `./luajit` is not found.

## 2. Enabling sysprof (LJ_HASSYSPROF)
1. `lj_arch.h`: allow `LJ_TARGET_WINDOWS && LJ_TARGET_X64` in the `LJ_HASSYSPROF` gate.
2. **dynasm flag**: the build must pass `-D LJ_HASSYSPROF` (tarantool's `cmake/SetDynASMFlags.cmake` greps `LJ_HASSYSPROF 1` out of the arch probe). With the make build add:
   ```make
   ifneq (,$(findstring LJ_HASSYSPROF 1,$(TARGET_TESTARCH)))
     DASM_AFLAGS+= -D LJ_HASSYSPROF
   endif
   ```
   Symptom if missing: `g->top_frame_info.top_frame == NULL`, segfault in `stream_backtrace_lua` on the first guest sample.
3. `lib_misc.c`: the whole profile section is under `#if !LJ_TARGET_WINDOWS`; widen it to `#if !LJ_TARGET_WINDOWS || LJ_HASSYSPROF` and gate `misc.sysprof` registration on `LJ_HASSYSPROF` (keep `misc.memprof` Windows-hidden; `LJ_HASMEMPROF` is 0 there).
4. Open the profile file with `O_BINARY`: text mode rewrites `0x0a` as `0x0d 0x0a` and corrupts the `ljs`/`ljp` stream.

## 3. Sampler implementation
- `sj_jysprof`: timer thread stops the profiled thread:
  ```c
  DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                  &sp->thread_handle, 0, FALSE, DUPLICATE_SAME_ACCESS);
  /* stack bounds: ((PNT_TIB)NtCurrentTeb())->StackBase / StackLimit */
  ```
- Per tick: `SuspendThread` -> `GetThreadContext(CONTEXT_CONTROL|CONTEXT_INTEGER)` -> record counters/Lua stack -> `ResumeThread`.
- Lua stack: unchanged upstream code reading `g->top_frame_info` (VM stashes `BASE` on every vmstate transition).
- Host stack from the saved CONTEXT:
  ```c
  RtlPcToFileHeader(rip, &base)            /* NULL => JIT mcode/foreign: stop */
  func = RtlLookupFunctionEntry(rip, &base, &hist);
  func ? RtlVirtualUnwind(UNW_FLAG_NHANDLER, ...)
       : (leaf: rip = *(void**)rsp, rsp += 8);   /* bounds-check rsp */
  ```
- No handler frames are on the target stack: set `SYSPROF_HANDLER_STACK_DEPTH 0` on Windows.

## 4. Symbols (`lj_symtab.c`)
Order: COFF symbol table in the image file (MinGW; `PointerToSymbolTable`, 18-byte entries, filter StorageClass 2/3 and Type & 0x20, address = base + section.VirtualAddress + Value) -> PE export directory parsed from the loaded image -> single module-base entry with `me.szExePath`. Return -1 when zero entries so the fallback still runs. MSVC/PDB is not covered: add DbgHelp `SymInitialize`/`SymLoadModuleEx`/`SymEnumSymbols`.

## 5. Verify
- `misc.sysprof.start{mode="D"}` = counters only; `"L"`/`"C"` stream to `path` (default `sysprof.bin`).
- Parse: `LUA_PATH="tools/?.lua;tools/?/init.lua;src/?.lua;;" luajit tools/sysprof.lua out.bin`; sum of parsed events must equal `misc.sysprof.report().samples`.
- Symbol quality check: nearest-symbol lookup via `nm -n --defined-only luajit.exe | awk '$2 ~ /[TtWw]/'` plus RVA arithmetic against the module base recorded in the symtab.
- Expected Windows behaviour: `Sleep(1)` ≈ 1.5-1.9 ms, so `interval=1` under-samples; 10 ms is accurate. `tools/sysprof/parse.lua` shows no Lua frames because `insert_lua_callchain` breaks on the outermost CFUNC (`pmain`) - platform-independent.

## 6. Pitfalls checklist
- Missing `-D LJ_HASSYSPROF` to dynasm -> crash, not a compile error.
- Text-mode output file -> stream desync.
- `SuspendThread` pairs must match; close the duplicated handle in both `lj_sysprof_stop` and the start-error path.
- Never allocate/lock in the sampler while the target is suspended.
- `LJ_TARGET_X86` Windows is not supported by this port (RtlVirtualUnwind path is x64/ARM64 only).
