---
name: luajit-windows-sysprof-and-jit-unwind
description: "Build tarantool LuaJIT on Windows with MinGW, port/test sysprof sampling, name JIT mcode frames and unwind through them, and symbolize profiles from PDB/map/embedded tables."
---

# LuaJIT Windows sysprof + JIT mcode unwinding

Use when working on tarantool/luajit `lj_sysprof` on Windows, mixed Lua/host stack merging, or profile symbolization without symbols.

## Build (tarantool tree, MinGW)

1. Root `CMakeLists.txt` refuses Windows (`FATAL_ERROR`); there is no `src/Makefile` and no `msvcbuild.bat`.
2. Copy upstream v2.1 `src/Makefile` + `src/Makefile.dep` into the tree. Adjust:
   - drop `lj_prng.o`, `lj_serialize.o`, `lib_buffer.o`; add `lj_sysprof.o lj_symtab.o lj_wbuf.o lj_utils_leb128.o lj_profile_timer.o lj_memprof.o lj_mapi.o lib_misc.o` (and `lib_misc.o` instead of `lib_buffer.o` in LJLIB_O).
   - sed the new deps out of `Makefile.dep` (`lj_prng.h`, `lj_serialize.h`, `lib_buffer.h`).
   - delete the `luajit.h: ... genversion.lua` rule (tarantool checks the header in) and remove `luajit.h` from `ALL_HDRGEN` so `make clean` keeps it.
3. Add the dynasm macro or the VM will never record `top_frame_info` (immediate SIGSEGV in the first guest sample):
   ```make
   ifneq (,$(findstring LJ_HASSYSPROF 1,$(TARGET_TESTARCH)))
     DASM_AFLAGS+= -D LJ_HASSYSPROF
   endif
   ```
4. Build: `mingw32-make BUILDMODE=static CCDEBUG=-g XCFLAGS=-DLUAJIT_ENABLE_GC64` (serial; `-j` races lib_misc.o against the generated lj_libdef.h). GC64 is required for tarantool parity; without it dynasm picks vm_x86.dasc.

## Sampling (Windows)

- Timer thread (LJ_PROFILE_WTHREAD) samples: SuspendThread (real handle from DuplicateHandle) -> GetThreadContext -> read `g->vmstate`, walk `g->cur_L` + `g->top_frame_info` -> RtlLookupFunctionEntry/RtlVirtualUnwind -> ResumeThread.
- Re-check the profiler state after suspending (the profiled thread writes the stream itself while extending the symtab).
- Under `WIN` the dasc skips save/restore_vmstate around C calls, so `top_frame_info` is stale there: for CFUNC samples walk from `L->base` and validate `bot <= frame < L->top < stack_end` or the target crashes.
- Keep IO out of the frozen window: swap in a spare buffer and write after ResumeThread.

## JIT mcode

- Machine code has no unwind info. Detect it by range: snapshot `T->mcode/szmcode/traceno` (VISIBLE under `#if LJ_HASJIT`) on the profiled thread at start and in `lj_sysprof_add_trace()`; never walk `J->trace[]` from the sampler (realloc race -> crash). Capacity bound = `JIT_P_maxtrace + 1` (`lj_trace.c:75`).
- Remove ranges when traces die: hook BOTH `lj_trace_free()` and `lj_trace_flushall()` (flush does not go through free), clearing `size` before `traceno`.
- Unwind through a trace with the SEH entry frame, not `spadjust`: `caller_rsp = L->cframe + CFRAME_SIZE`, `return_address = *(cframe + CFRAME_SIZE - 8)`. `CFRAME_SIZE_JIT + spadjust` only holds in the trace body, not at call sites.
- VM asm frames: `buildvm_peobj.c` emits exactly two `.pdata` entries for the whole blob, so compare the containing function's begin with the entries for `lj_vm_asm_begin` and `lj_vm_profhook`.

## Symbolizing (tools)

- `tools/utils/symresolver.lua`: debug (PDB via dbghelp FFI; else `addr2line` in batches of 128) -> linker map (GNU ld `0xADDR name`, MSVC `/MAP` RVA) -> the profile's embedded ljs table. Emit a module base+path entry for every image: the resolver needs it for load->link address translation.
- DbgHelp pitfalls: pass `SizeOfImage` as `DllSize` to `SymLoadModuleEx` (0 makes every lookup return `__ImageBase`); load at the profile's runtime base; unwrap `ILT+1234(name)`; parse hex with ffi `uint64_t` (`tonumber(s,16)` overflows above 32 bits on Windows).

## Verifying

- `luajit -ts <profile>` runs the bundled parser; `-ts --debug=<exe>` / `--map=<file>` exercise the resolver.
- Sanity: parsed event count == `misc.sysprof.report().samples`; trace frames appear as `TRACE [N]`; `jit.flush()` mid-profile must not crash.
- Workloads that actually reach mcode: hot loop (`jit.opt.start("hotloop=1")`) with an FFI call such as `ffi.C.Sleep(n)`; expect chains like `lua_pcall; TRACE [1]; Sleep`.
