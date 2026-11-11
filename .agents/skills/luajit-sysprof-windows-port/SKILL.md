---
name: luajit-sysprof-windows-port
description: "Port Tarantool LuaJIT sysprof to Windows x64 (MinGW build, suspend sampling, unwinding, symbolization, deterministic merge) or extend jit.profile with host stacks."
---

# Tarantool LuaJIT: Windows sysprof / host-stack work

Worktree used: `%TEMP%\lj-sysprof-win` (branch `sysprof-win`, based on `tarantool/master`).
Source refs from a plain `C:/Users/fesil/LuaJIT` checkout: `git show tarantool/master:src/...`.

## 1. Build tarantool/luajit on Windows (MinGW) — it has no Windows build

`CMakeLists.txt` hard-fails off POSIX; there is no `msvcbuild.bat` and no `src/Makefile`.
Bootstrap with the upstream v2.1 `src/Makefile`:

1. `cp <LuaJIT>/src/Makefile` and `Makefile.dep` into the tarantool tree.
2. Object lists: drop `lib_buffer.o`, `lj_prng.o`, `lj_serialize.o`; add
   `lib_misc.o lj_wbuf.o lj_utils_leb128.o lj_memprof.o lj_profile_timer.o
   lj_symtab.o lj_sysprof.o lj_mapi.o`.
3. `sed 's/ lj_prng\.h//g; s/ lj_serialize\.h//g; s/ lib_buffer\.h//g' Makefile.dep`
   (it has no deps for the added files, so build **serially**: `-j` races `lj_libdef.h`).
4. Remove the `luajit.h:` rule (tarantool checks that header in) and drop
   `luajit.h` from `ALL_HDRGEN` so `make clean` keeps it.
5. Add the dynasm flag (CMake does this via `cmake/SetDynASMFlags.cmake`):
   ```make
   ifneq (,$(findstring LJ_HASSYSPROF 1,$(TARGET_TESTARCH)))
     DASM_AFLAGS+= -D LJ_HASSYSPROF
   endif
   ```
   Missing it = `vm_x64.dasc` never writes `top_frame_info`, `top_frame` stays
   NULL, the first guest sample segfaults.
6. Build GC64 (tarantool default): `mingw32-make BUILDMODE=static CCDEBUG=-g XCFLAGS=-DLUAJIT_ENABLE_GC64`.
   `BUILDMODE=static` lets symbols resolve in gdb; `CCDEBUG=-g` disables `--strip-unneeded`.
   Never `make clean` without re-checking `src/luajit.h` is present.
7. Run Lua tools with `LUA_PATH="tools/?.lua;tools/?/init.lua;src/?.lua;;"`.
   The profile CLI is `luajit -ts <profile>` (`-t<cmd>` in `luajit.c`), not `luajit tools/sysprof.lua`.

## 2. Port pieces (all in `src/lj_sysprof.c` unless noted)

- `lj_arch.h`: `LJ_HASSYSPROF` on `(LJ_TARGET_WINDOWS && LJ_TARGET_X64)`; memprof stays off.
- `lib_misc.c`: `misc.sysprof` registration was inside `#if !LJ_TARGET_WINDOWS` — gate the
  common section on `!LJ_TARGET_WINDOWS || LJ_HASSYSPROF`, register the module on `LJ_HASSYSPROF`.
  **Open the profile stream with `O_BINARY`** — text mode turns `0x0a` into `0x0d 0x0a` and
  silently corrupts the stream (symptom: symtab parse drifts, tool reports bad magic).
- Sampling: `DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), ...)` at start;
  per tick `SuspendThread` → `GetThreadContext` → record → `ResumeThread`.
  `PNT_TIB`/`NtCurrentTeb()` gives the profiled thread's stack bounds at start.
- Host unwinder: `RtlPcToFileHeader` (must be a PE image) + `RtlLookupFunctionEntry` /
  `RtlVirtualUnwind`; leaf frames take the return address at `[Rsp]`; stop at JIT mcode.
- Counters-only mode (`LUAM_SYSPROF_DEFAULT`, the default) needs no freeze: `vmstate` is one
  aligned word — read it without suspending.
- Idle fast path: resolve `NtWaitForSingleObject/NtWaitForMultipleObjects/NtDelayExecution/
  NtRemoveIoCompletion*/NtWaitForWorkViaWorkerFactory` + `WaitForSingleObject*/Sleep*` at start;
  a sample inside one (0x20 window) is streamed as a single frame.
- Deferred flush: swap `lj_wbuf`'s buffer with a spare (`opt.len`, memset at start) inside the
  frozen window and `write()` after `ResumeThread`; otherwise a flush keeps the target stopped
  for ~200 us.
- Lua stack walk must be defensive: when `vmstate == LJ_VMST_CFUNC` start from `L->base`
  (on Windows `save_vmstate`/`restore_vmstate` are `#if not WIN` no-ops, so the stashed
  `top_frame_info.top_frame` goes stale and walked frames crash), and require
  `bot <= frame < min(L->top, stack_end)`.

## 3. jit.profile host stacks (`lj_profile.c`)

- `'h'` mode; capture with `RtlCaptureStackBackTrace(LJ_PROFILE_HOSTSTACK_SKIP=4, ...)` in
  `lj_profile_interpreter` right before the callback (no suspend: the callback already runs on
  the profiled thread). Skip profiler frames: capture fn, interpreter, dispatch_profile, profhook.
- VM frames are identified structurally: `buildvm_peobj.c` emits only two `.pdata` entries for
  the whole VM blob, so the function containing `lj_vm_asm_begin` and the one containing
  `lj_vm_profhook` cover it — no symbols, no `lj_vm_asm_end` needed.
- Deterministic merge (`mixedstack`): walk the Lua chain (via `lj_debug_frame`) and splice host
  frames at each C-function boundary by matching `func->c.f` against the host frame's containing
  function (`RtlLookupFunctionEntry → base + BeginAddress`). Fast functions: host frames until a
  VM frame, then the `[builtin#N]` marker (the marker is the *outer* boundary).
- Cost: `RtlCaptureStackBackTrace` ~0.6 us for 16 frames; no measurable throughput impact.

## 4. Symbolization / offline tools

- `lj_symtab_cfuncs(cb, ctx)` is the reusable collector (no lj_wbuf, no Lua allocator, any thread).
  Windows: COFF symtab (`ty 0x20`) → export dir → **always** emit the image base + path
  (the resolver needs module load addresses).
- Stream format (`lj_sysprof.h`): host frame = `exec-addr` + `func-off` (+1, 0=unknown) since
  v3. ljs v4 added `SYMTAB_VM` (VM function start addresses). `tools/utils/symtab.lua` accepts
  3..4, `tools/sysprof/parse.lua` accepts 2..3.
- `parse.lua` merges deterministically (no name matching); the old `insert_lua_callchain`
  heuristic never merged anything because it breaks on the outermost CFUNC (`pmain`).
- `tools/utils/symresolver.lua`: C names from (1) debug info, (2) map file, (3) embedded ljs.
  DbgHelp via FFI (`SymInitialize`, `SymLoadModuleEx` at the *profile* base, `SymFromAddr`);
  fall back to batched `addr2line` (128 addresses/invocation, two-pass CLI) or GNU/MSVC map.
  Pass PDB-free `addr2line` only when `--addr2line=` is given; DbgHelp otherwise (no subprocess).

## 5. Verification recipes

- `misc.sysprof.start{mode="C", interval=1, path=...}` + a mixed workload; compare
  `misc.sysprof.report().samples` with the parsed event count (must be equal).
- Resolve captured frames with `nm -n luajit.exe` (RVA = pc - module base, add 0x140000000),
  or `jit.profile.symtab()` + binary search inside Lua.
- Freeze window: wrap `SuspendThread..ResumeThread` with `QueryPerformanceCounter`; expect
  ~10-25 us, max < 60 us (peaks = I/O in the frozen window).
- Crash triage: gdb batch script `run -joff script.lua` + `thread apply all bt`; build with
  `CCDEBUG=-g CCOPT=-O0` when locals are optimized out.
