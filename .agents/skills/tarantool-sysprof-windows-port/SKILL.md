---
name: tarantool-sysprof-windows-port
description: "Build tarantool/luajit on Windows with MinGW and port/verify sysprof (suspend+CONTEXT sampling, PE symtab, deferred flush); use for Windows sysprof work, not generic LuaJIT builds."
---

# Tarantool sysprof on Windows (MinGW x64)

Goal: build tarantool/luajit on Windows and make `misc.sysprof` work, or debug an existing port.

## 1. Bootstrap the Windows build

tarantool/master has no Windows build: `CMakeLists.txt` aborts (`FATAL_ERROR` unless Linux/Darwin/FreeBSD) and there is no `src/Makefile`.

```sh
# in a worktree of tarantool/master
cp <luaJIT-v2.1>/src/Makefile        src/Makefile
cp <luaJIT-v2.1>/src/Makefile.dep    src/Makefile.dep
```

Then in `src/Makefile`:
- `LJLIB_O`: replace `lib_buffer.o` with `lib_misc.o`.
- `LJCORE_O`: drop `lj_prng.o`, `lj_serialize.o`; add `lj_wbuf.o lj_utils_leb128.o lj_memprof.o lj_profile_timer.o lj_symtab.o lj_sysprof.o lj_mapi.o`.
- Delete the `luajit.h: ... luajit_rolling.h` rule (tarantool checks `luajit.h` in) and remove `luajit.h` from `ALL_HDRGEN` so `make clean` does not delete it.
- In `Makefile.dep`, remove ` lj_prng.h`, ` lj_serialize.h`, ` lib_buffer.h`.
- Add `ifneq (,$(findstring LJ_HASSYSPROF 1,$(TARGET_TESTARCH)))` / `DASM_AFLAGS+= -D LJ_HASSYSPROF` next to the NO_UNWIND block.

Build (GC64 is mandatory; without `-DLUAJIT_ENABLE_GC64` the arch probe yields LJ_FR2=0 and dynasm uses `vm_x86.dasc`):

```sh
mingw32-make clean; git checkout -- src/luajit.h
mingw32-make XCFLAGS=-DLUAJIT_ENABLE_GC64            # serial: -j races on lj_libdef.h
mingw32-make BUILDMODE=static CCDEBUG=-g XCFLAGS=-DLUAJIT_ENABLE_GC64   # symbolized debug binary
```

`CCDEBUG=-g` is what adds `-g` and disables strip; `CCOPT` alone does not.

## 2. Checklist for the port itself

- `lj_arch.h`: allow `LJ_HASSYSPROF` for `LJ_TARGET_WINDOWS && LJ_TARGET_X64`.
- `lj_sysprof.c`: `DWORD thread; HANDLE thread_handle` (DuplicateHandle of GetCurrentThread, THREAD_SUSPEND_RESUME|GET_CONTEXT); stack bounds from `NtCurrentTeb()->StackLimit/StackBase`; handler signature `void(void)` (timer thread, not a signal).
- Sampling: `SuspendThread` -> `GetThreadContext(CONTEXT_CONTROL|CONTEXT_INTEGER)` -> `sysprof_record_sample` -> `ResumeThread`; host stack unwound from the saved CONTEXT with `RtlPcToFileHeader` + `RtlLookupFunctionEntry`/`RtlVirtualUnwind`, leaf fallback = return address at `[Rsp]`, stop at non-PE addresses (JIT mcode).
- `lib_misc.c`: the whole profiler section is inside `#if !LJ_TARGET_WINDOWS`; widen it and register `misc.sysprof` under `LJ_HASSYSPROF` (keep memprof Windows-hidden). Open profile files with `O_BINARY`.
- `lj_symtab.c`: toolhelp snapshot + COFF symbol table (`ty & 0x20`, scl 2/3) -> exports -> module-base fallback entry.
- Debug `freeze` cost with QueryPerformanceCounter around Suspend/Resume before optimizing.

## 3. Symptom table

| symptom | cause |
|---|---|
| SIGSEGV in `stream_backtrace_lua` on first guest sample | dynasm never got `-D LJ_HASSYSPROF`, `top_frame_info.top_frame` is NULL |
| symtab parse ends mid-entry, `ljp` magic not found | profile fd opened in text mode (`0x0a` -> `0x0d 0x0a`) |
| `misc.sysprof` is nil | `lib_misc.c` guard `#if !LJ_TARGET_WINDOWS` |
| merged output has no Lua frames | `insert_lua_callchain` breaks on the first CFUNC (outermost frame is `pmain`) - tool quirk, not a stream bug |
| max freeze ~200 us spikes | `write()` inside the frozen window; swap buffers and flush after Resume |

## 4. Verify

```lua
-- run under the built luajit
local misc = require("misc"); assert(misc.sysprof.start{mode="C", interval=2, path=out})
-- workload: fib + collectgarbage + table churn
assert(misc.sysprof.stop()); print(misc.sysprof.report().samples)
```

```sh
LUA_PATH="tools/?.lua;tools/?/init.lua;src/?.lua;;" luajit.exe tools/sysprof.lua <file>
```

Acceptance: parsed event count == `samples` (exact), host chains resolve to `lua_pcall`/`lj_BC_*` in a debug build, idle test (`os.execute('ping -n 3 127.0.0.1 > nul')`) yields single-frame `ZwWaitForSingleObject` samples, 100 start/stop cycles without crash.
