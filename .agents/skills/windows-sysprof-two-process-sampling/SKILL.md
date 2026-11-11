---
name: windows-sysprof-two-process-sampling
description: "Build tarantool LuaJIT on Windows with MinGW and implement/verify sysprof suspend-based sampling, mcode naming, DbgHelp symbolization"
---

# Build + verify tarantool LuaJIT sysprof on Windows

## Build (the tarantool tree has no Windows build)
1. `git worktree add <dir> tarantool/master --detach`
2. Copy upstream LuaJIT v2.1 `src/Makefile` + `src/Makefile.dep` into it.
3. In Makefile: object lists must drop `lj_prng.o lj_serialize.o lib_buffer.o` and add `lib_misc.o lj_mapi.o lj_memprof.o lj_profile_timer.o lj_symtab.o lj_sysprof.o lj_utils_leb128.o lj_wbuf.o`; delete the `luajit.h` generation rule (tarantool ships it) and remove `luajit.h` from ALL_HDRGEN so clean keeps it.
4. Add dynasm flag: `ifneq (,$(findstring LJ_HASSYSPROF 1,$(TARGET_TESTARCH))) DASM_AFLAGS+= -D LJ_HASSYSPROF endif` — without it the VM never writes `top_frame_info` and the sampler crashes immediately.
5. Build serial (parallel races on generated headers): `mingw32-make XCFLAGS=-DLUAJIT_ENABLE_GC64`; add `BUILDMODE=static CCDEBUG=-g` for debugging, always `mingw32-make clean` first when switching BUILDMODE (otherwise stale dll/static objects fail to link).
6. `make clean` deletes `src/luajit.h`; `git checkout -- src/luajit.h` to restore.

## Run the tooling
- Profiles: `misc.sysprof.start{mode="C", interval=1, path=...}`, workload, `stop()`, `report()`.
- Parser CLI is the `-ts` option: `LUA_PATH="tools/?.lua;tools/?/init.lua;src/?.lua;;" luajit -ts profile.bin` (running `tools/sysprof.lua` directly does nothing — it returns a function).
- `--map=file`, `--debug=binary`, `--addr2line=tool` for C names.

## Sampling implementation notes (see memory for numbers)
- Freeze window = SuspendThread -> GetThreadContext -> record -> ResumeThread; never allocate or do blocking I/O while frozen (swap the wbuf into a spare and write after resume).
- mcode: snapshot trace ranges on the profiled thread (`JIT_P_maxtrace + 1` entries), never walk `J->trace[]` from the sampler; invalidate on `lj_trace_free` AND `lj_trace_flushall`.
- Unwind past a trace via the SEH entry frame: RA at `[L->cframe + CFRAME_SIZE - 8]`, caller RSP = `cframe + CFRAME_SIZE`.
- C-state samples: walk from `L->base`, not the stashed `top_frame_info` (Windows never restores it), and bound-check frames against the live stack.

## Debugging sampler crashes
- `gdb -batch -x cmd --args luajit.exe ...` with `thread apply all bt`: the crash is usually in the sampler thread inside `stream_backtrace_lua` (stale base) or `RtlVirtualUnwind` (missing `EstablisherFrame`/`HandlerData` pointers — pass real locals, NULL crashes).
- Temporarily gate prints with `getenv("...DEBUG")` in the sampler; remember to strip them and the stdio/stdlib includes before committing.
