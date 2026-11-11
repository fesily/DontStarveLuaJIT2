---
name: luajit-sysprof-baseline-rebase
description: "Rebase the sysprof-v2.1 LuaJIT branch onto a newer v2.1 baseline, then verify behaviour on MSVC and MinGW including upstream test-suite parity against a stock build."
---

# Rebase the sysprof branch onto a new LuaJIT baseline and verify it

Scope: the `sysprof-v2.1` branch (temp worktree `%LOCALAPPDATA%\Temp\lj-sysprof-v21`)
being moved onto a newer `v2.1` baseline. Windows x64 host only.

## 1. Measure the move before touching anything

```bash
cd /c/Users/fesil/AppData/Local/Temp/lj-sysprof-v21
git fetch --all --prune
git log --oneline -1 v2.1; git log --oneline -1 origin/v2.1
git log --oneline <old-base>..origin/v2.1            # how many baseline commits
git diff --name-only <old-base>..HEAD | sort > /tmp/ours.txt
git log --oneline <old-base>..origin/v2.1 -- $(cat /tmp/ours.txt | tr '\n' ' ')
```

That last command names the only baseline commits that can conflict. Expect
`src/lj_parse.c` and `src/lj_errmsg.h` (the profiler hook sits in `fs_finish()`).

## 2. Rebase and prove nothing was lost

```bash
git rebase origin/v2.1
git range-diff <old-base>..<old-head> origin/v2.1..HEAD
```

`range-diff` prints `=` for every commit reapplied byte-identically. Anything else
must be inspected: the expected case is the port commit, whose hunk in
`fs_finish()` follows the baseline's signature change. Verify the hook is still
right after the `lj_vmevent_send(G(L), BC, ...)` block:

```bash
sed -n '/^static GCproto \*fs_finish/,/^}/p' src/lj_parse.c | tail -20
```

## 3. Rebuild both toolchains (never skip one)

MinGW first (it rebuilds everything, so do it before the MSVC run that leaves
PDBs behind):

```bash
cd src && export PATH=/c/ProgramData/mingw64/mingw64/bin:$PATH
mingw32-make clean >/dev/null; mingw32-make luajit.h; mingw32-make -j4
```

`luajit.h` must be built before the parallel build after a clean, otherwise
`lj_mixprof.o` fails with `luajit.h: No such file`. Build MSVC from Python (cmd
quoting through bash is unreliable):

```python
vs = r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
open("src/msvc-build.bat", "w", newline="\r\n").write(
    '@echo off\r\n' f'call "{vs}" >nul\r\n' 'if errorlevel 1 exit /b 2\r\n'
    'call msvcbuild.bat\r\n' 'exit /b %errorlevel%\r\n')
subprocess.run([bat], cwd=src)
```

Expected end state: `=== Successfully built LuaJIT for Windows/x64 ===`, no
warning from `lj_sysprof.c` / `lj_profile.c` / `lj_mixprof.c` / `lj_symtab.c` /
`lib_misc.c` / `lib_mixprof.c`, and `src/luajit.pdb` fresh.

## 4. Functional battery (drive the binary by absolute path)

The bash tool resolves `./src/luajit.exe` against the workspace root, so run the
worktree build through Python:

```python
env["LUA_PATH"] = ";".join([root+"?/?.lua", root+"/tools/?.lua",
    root+"/tools/?/init.lua", src+"/?.lua", src+"/?/init.lua"]) + ";;"
```

| check | expected |
|---|---|
| `misc.sysprof` modes C/L/D + `jit.off()` | samples > 0, per-vmstate counters sane (trace for JIT runs, cfunc for FFI) |
| `jit.mixprof` | `sum(chains) == sum(spans.count) == ticks == info().ticks`, `#spans > 0` |
| `--format=samples` | `time_us` strictly non-decreasing; span ≈ profile wall time |
| `text` / `json` / `folded` | `sorted(count)` of all three identical; **no `\r` in any output** |
| `--pdb=src/luajit.pdb` | `luajit.exe!__scrt_common_main_seh`, `!main`, `!pmain`, `!handle_script` |
| `--format=folded` piped to `flamegraph.pl` | exit 0, SVG contains `RtlUserThreadStart` and `lua_pcall` |
| line directive `# 500 "v.lua"` | profiled frames read `@v.lua:<500+n>`, no crash |
| 60-round soak (C/L/D + `jit.flush` + pcall/GC + mixprof sessions) | non-zero samples, exit 0 |

Give the soak workload `ffi.C.Sleep(1)` per iteration; a JIT-compiled loop is
faster than the 1 ms sampling interval and yields 0 samples.

## 5. Upstream suite, compared against a stock build

The worktree has no test directories. Use the main repo's suite and build a
stock worktree of the same baseline:

```bash
git worktree add ../lj-stock origin/v2.1
cd ../lj-stock/src && export PATH=/c/ProgramData/mingw64/mingw64/bin:$PATH
mingw32-make clean >/dev/null; mingw32-make luajit.h; mingw32-make -j4
```

```python
subprocess.run([exe, "test.lua"], cwd=r"C:\Users\fesil\LuaJIT\LuaJIT-test-cleanup\test")
```

Expected on Windows: `532 passed, 4 failed` for **both** builds, and outputs
identical after masking `0x7ff[0-9a-f]+` (ASLR). The 4 are
`lib/contents.lua` (x2), `trace/exit_pargc.lua`, `opt/loop/unroll.lua`.
A difference between the two runs is the regression to chase.

## 6. Clean up and publish

```bash
rm -f fin.lua f_*.bin fin.folded flamegraph.pl src/msvc-build.bat
git worktree remove ../lj-stock --force
git add -A && git commit            # warning fixes / doc notes, if any
git push --force-with-lease origin sysprof-v2.1
git ls-remote --heads origin sysprof-v2.1   # must equal local HEAD
```

Update `doc/sysprof-windows-design.md` §11: the base commit in the header and a
row in §11.2 for the rebase + suite parity.
