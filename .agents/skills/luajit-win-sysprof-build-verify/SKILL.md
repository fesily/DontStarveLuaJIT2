---
name: luajit-win-sysprof-build-verify
description: "Build and verify the LuaJIT v2.1 sysprof/mixprof worktree on Windows (MSVC + MinGW), run profiles, parse the ljp/ljs stream with -ts, and check timestamps/formats."
---

# LuaJIT sysprof/mixprof on Windows: build and verify

Use for the sysprof Windows-port worktree (`%LOCALAPPDATA%\Temp\lj-sysprof-v21`): rebuilding after C changes, collecting profiles, and verifying the tool output (frames, symbolization, timestamps, JSON).

## Build (both toolchains, one tree — MSVC last)

MSVC moved: `C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat`. The old `\2022\` path is an empty shell; `vcvars64` there fails with "The system cannot find the path specified".

MSVC: write a `.bat` (CRLF) and run it with `subprocess.run([bat], cwd=src)` — `cmd /c "call .. && nmake"` gets its quotes mangled by the MSYS layer:

```
@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 2
call msvcbuild.bat
exit /b %errorlevel%
```

Do **not** use `nmake -f Makefile`: that Makefile is GNU-make only (dies at `Makefile(157) U1000`). MinGW:

```
cd src && export PATH=/c/ProgramData/mingw64/mingw64/bin:$PATH
mingw32-make luajit.h     # after a clean, -j4 races and lj_mixprof.c fails on missing luajit.h
mingw32-make -j4
```

Never leave a mixed tree: `.o` from MinGW plus `.obj` from MSVC in one directory crash `luajit.exe` at startup (0xC0000005), and `jit/vmdef.lua` embeds a build-version stamp that then mismatches the other toolchain ("LuaJIT core/library version mismatch"). Verify MinGW first, then rerun the MSVC build so the tree is consistent (MSVC also gives the `.pdb` needed to test `--pdb=`).

## Running the worktree binary

The bash tool resolves `./src/luajit.exe` against the **workspace root**, not the `cd` directory, so it silently runs the main repo's binary (no `-t`, no sysprof). Always call the absolute path through `eval`/Python `subprocess`, with:

```
LUA_PATH=<worktree>/?.lua;<worktree>/tools/?.lua;<worktree>/tools/?/init.lua;<worktree>/src/?.lua;<worktree>/src/?/init.lua;;
```

(`jit.vmdef` lives in `src/jit`). Tool form: `luajit -ts [options] profile.bin`; options go **before** the path.

## Collect a profile

```lua
local sp = require("misc").sysprof
assert(sp.start{ mode = "C", path = "p.bin", interval = 1 })  -- modes: C, L, D
...workload...
assert(sp.stop()); print(sp.report().samples, sp.report().vmstate.TRACE)
```

`mode="D"` is counters-only: it ignores `path` (stream_is_needed() is false), so no file is written. A JIT-compiled tight loop finishes in <1 ms and yields 0 samples at interval 1 — put `ffi.cdef[[void Sleep(int ms);]]` + `ffi.C.Sleep(3)` in the loop (100 iterations ≈ 300 ms, ~200 samples).

`jit.mixprof`: `mix.start(depth, interval)`, `mix.stop()`, `mix.report()` → `chains, spans, ticks` (`spans` in collection order `{chain, tick, count}`), `mix.info()` → `{start_us, interval_us, ticks}`; record time = `start_us + tick*interval_us`.

## Verify the tool output

* frames: `-ts p.bin` prints `module!function`, `module+offset`, `@chunk:line`, `[TRACE n]` — a bare hex address only outside every image. Text must stay byte-identical when only internal structures change (save a baseline first).
* `--format=json`: one object per aggregated chain, `count` must match the text report line by line; addresses are hex strings; aggregated chains carry `first_us`/`last_us` once the stream is v5.
* `--format=samples`: JSONL per sample with `time_us`; check monotonicity, 1–2 ms deltas at interval 1, first sample ≈ file mtime − profile duration. Format 2..4 profiles parse without times (warning "no sample times").
* symbolization: without symbol files the profile's own ljs table names exported/COFF symbols; `--pdb=src/luajit.pdb` (explicit only — the tools do not pick a `.pdb` sitting next to the image, it may be another build) adds internal names; `--map=` accepts MSVC `seg:off name rva` lines.
* counters sanity: `mode="C"` with JIT on → all samples TRACE; `jit.off()` → cfunc > 0, trace = 0.

## Traps seen while verifying

* `local _, name = resolver and resolver:resolve(...)` — a conjunction yields **one** value, so `name` is always nil. Call the resolver first, take its 2nd return.
* Resolver caches keyed by address hide answers for the same function queried later with a proper `entry`: key by function start (entry), fall back to `addr`.
* DbgHelp keys symbols to the module list of the analysing process: read a PDB standalone first (`llvm-pdbutil dump -section-headers` + `dump -symbols`; `addr = SSSS:OOOO` is hex, `code size` decimal), use DbgHelp only as a fallback with a function-extent check.
* ljs v7 appends a symbol size (ULEB) after every CFUNC record — a parser that skips it desyncs on inline `LJP_SYMTAB_*` events; pass `symbols.version` to `parse_sym_cfunc`.
