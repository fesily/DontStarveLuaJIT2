---
name: dst-luajit-fork-build-ctest-verify
description: "Verify/debug a luajit fork (dontstarve branch) change in DontStarveLuaJIT2: CMake rebuild + luajit CTest, cdb localization of assert/AV crashes, non-fatal CMake probes that warn when the build's macro switches differ from what the tests assume, stale-object/fold-token pitfalls, and the commit split (submodule vs main repo)."
---

# When
Any source edit in the LuaJIT fork submodule `luajit` (branch `dontstarve`) of `C:/Users/fesil/DontStarveLuaJIT2` that needs build + test proof (e.g. hotpath-review items), **or** any LuaJIT assert/AV crash that must be localized with a debugger instead of guessed, **or** work on the CMake/ctest side (test registration, build-switch diagnostics).

User preference: apply known fixes by editing the file directly — don't dig git history to "restore" values.

# 1. Build
- Edit files under `luajit/src/...` in the main checkout (submodule gitdir `.git/modules/luajit`).
- Toolchain is NOT on PATH. VS 18 bundle paths:
  - `C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\{cmake.exe,ctest.exe}`
  - `...\CMake\Ninja\ninja.exe`, `...\VC\Auxiliary\Build\vcvars64.bat`
- Write a temp .bat: `call vcvars64.bat`, `set NoDefaultCurrentDirectoryInExePath=`, then
  `cmake --build builds\ninja-multi-vcpkg --config RelWithDebInfo --target luajit luajit-arenagc`
  (targets `luajit` / `luajit-arenagc` exist; both must rebuild for a public-code change).
- Run the .bat via Python subprocess: `subprocess.run([COMSPEC, '/c', bat])` (eval). Bash `cmd /c` / `cmd //c` quoting is unreliable in this shell — don't fight it. Long cmd runs inside the `eval` kernel can kill it: drive them from the `bash` tool instead, writing the .bat with Python (`newline="\r\n"`). Also: the bash tool refuses to exec relative paths like `./x.exe` / `run_on\cost.exe` ("command not found") — go through a .bat.
- Incremental rebuild after an `lj_*.h` edit ≈ 20–40 s (amalgamation TUs). C4819/C5287 warnings are pre-existing noise.
- Verify a rebuild is real: compare `builds/ninja-multi-vcpkg/luajit/CMakeFiles/luajit-5.1.dir/RelWithDebInfo/src/ljamalg.c.obj` mtime against `luajit/src/lj_debug.c`. This machine's Ninja dep prefix was corrupted once (zero recorded includes for `ljamalg.c.obj`) — if the object is older than the source, delete it and rebuild.
- **Same corruption on `buildvm.c.obj` is worse**: with no recorded includes, a new IR opcode in `lj_ir.h` (e.g. RETM's `RETFV`) does not recompile buildvm, only relinks it, and the build dies with `Error: bad fold definition token "RETFV" at line 2493` — looks like broken source, is a stale object. Fix: delete `builds/<tree>/luajit/CMakeFiles/buildvm-{default,arenagc}.dir/*/src/host/buildvm.c.obj` and rebuild.
- After any `edit`, eyeball the diff/compiler warnings: fuzzy matching once rewrote an identifier (`lj_mem_newagco` → `lj_mem_newagcoL`); MSVC only warned (implicit declaration) and the link failed later.

# 2. Tests
- Run ctest from the subdir to isolate luajit tests:
  `cd builds\ninja-multi-vcpkg\luajit && ctest.exe -C RelWithDebInfo --output-on-failure`
- `ctest -R luajit` at the top-level build dir selects the whole LuaJIT lane (compat51 + ds + parity + variant-registry tests). Expect 20/20 after `cbaddf73`+`9f457b6d`+`c04ae378`; it grew to 28 with the ETW lane (`-L luajit_etw`), which needs an elevated/PLU-capable shell (exit 77 = SKIP).
- Config preference: `tools/pre_push.py` picks Debug first, so keep `--config Debug` binaries fresh too — stale Debug binaries produce 5 unrelated failures.
- Exes: `builds/ninja-multi-vcpkg/luajit/<Config>/{luajit.exe,luajit-arenagc.exe}` (small launchers; the code lives in `lua51DS.dll` / `lua51DS_gengc.dll`).

# 3. Differential probe (mutation-style evidence)
- Run the same probe script on old and new builds; Python `subprocess` with timeout, kill on hang. Flush progress (`io.stdout:flush()`) or output is lost when the target hangs and is killed.
- Build a per-variant tree (`rcopy luajit/src` + `dynasm` + `.relver` into `v_x/`, `call msvcbuild.bat amalg` with `CL=<macros>`) so variants coexist and each build is a full recompile; **verify the copy with md5 + a grep for the new symbol** — `xcopy /e /i` and `rmdir /s /q` silently fail here, and a stale variant tree produces false failures.
- Example (item C): pre-fix `v_prefix` vs fixed `v_rel` printed byte-identical 71-line traceback dumps (shallow / deep20 with compression marker / pcall / metamethod / error(msg,2) / getinfo level walk) → the fix is output-neutral.
- Cheap standalone configure probe for build switches: a wrapper project (`project(x C ASM)` + `enable_testing()` + `add_subdirectory(<repo>/luajit luajit)`) builds the two VMs in seconds without vcpkg; per config run `/D<switch>=ON`. A preprocessor probe (`cl /EP` on a file that prints `LJ_HASETW`) is the cheapest way to prove a switch's effect.

# 4. cdb localization of assert/AV crashes
Goal: never guess where a fork assertion or access violation fires — build with PDB, break, read the actual Lua state.

- msvcbuild already passes `/Zi` + `link /DEBUG` → `luajit.pdb` + `lua51DS.pdb` (private symbols, locals enumerable).
- cdb (path `C:\Program Files\WindowsApps\Microsoft.WinDbg_*\amd64\cdb.exe`):
  `cdb -G -lines -y <variant>\src -logo <log.txt> -cf <cmds.txt> <variant>\src\luajit.exe <script.lua>`
- Breakpoints: symbols ok (`bp lua51DS!luaL_traceback`), offsets ok (`bp lua51DS!luaL_traceback+0x2d4`). Source-line bps (``bp `mod!path\file.c:874` ``) fail with "Ambiguous symbol error" here — use function+offset, then map back via the stack frame.
- `-g` runs straight past the loader breakpoint to the first exception (fine for AV/abort, useless for arming bps); omit `-g` when you need to set breakpoints first.
- Assert builds: break on the assert call site, then `dv /v /t`, `?? *(lua51DS!lj_Debug*)&ar`, `?? ((lua51DS!lua_State*)@r14)->top`, `?? *(...->top - 1)`.
- `dv` only works in frames of modules with private symbols; frame 0 (ucrtbase) always fails with dbgerr005 — select the LuaJIT frame first.
- GC64 nil TValue = u64 `0xFFFFFFFFFFFFFFFF`; `gcval()` masks with `LJ_GCVMASK` = `0x7FFFFFFFFFFF`, so dereferencing a nil function reads `0x8000000000000009` → non-canonical AV.
- Reference (item C): assert build aborts at `lj_debug.c:874` `tvisfunc(L1->top-1)`; `ar` = tail level (`what="tail"`, `source="=(tail call)"`, `i_ci=0`, `istailcall=1`); `L1->top-1` is nil. `LUA_COMPAT_TAILCALL_COUNT`'s virtual tail level pushes nil for the `f` option (5.1 parity: `src/lua51original/src/ldebug.c` `if (f == NULL) setnilvalue(L->top);`); `luaL_traceback`'s only escape is `if (ar.i_ci == 0 && !LJ_DS_TRACEBACK_PATCH)`, off in the DST default. Release survived only because `LUA_COMPAT_DISABLE_FUNCTION_BUILTIN_INFO=1` compiled the `isffunc(fn)` read out; forcing it to 0 makes a release build AV at `lj_debug.c:877`. Fix (`9f457b6d`): ask for `"Snl"` on `i_ci == 0`, leave `fn == NULL`, guard with `fn && isffunc(fn)`.
- When no cdb is installed: bisect with a `--only=<name>` scenario switch in the test binary plus `stderr` prints, and remember that an unprotected Lua error escaping to the top exits with `0xE24C4A00 + errcode` (e.g. `0xE24C4A02` = `LUA_ERRRUN`).

# 5. Build-switch preflight in the test framework (user's chosen mechanism)
The user rejected a second "assertion VM" build + pre_push/CI gate as too heavy. **Do not reintroduce a build lane**; instead the test framework detects the effective macro switches and prints a `message(WARNING)` (never fatal).

In `luajit/CMakeLists.txt`:
- probe macro **without** `#undef` (unlike the existing `LJ_TEST_ARCH_VALUE`) so `-D` overrides via `CMAKE_C_FLAGS`/`CL` win over the `lj_arch.h` default:
  ```cmake
  MACRO(LJ_TEST_SWITCH_VALUE stuff value)
    CHECK_C_SOURCE_COMPILES("
  #include \"lj_arch.h\"
  #if ${stuff} == ${value}
  int main() { return 0; }
  #else
  #error \"not ${stuff}=${value}\"
  #endif
  " ${stuff}_IS_${value})
  ENDMACRO()
  ```
  (undefined identifiers are 0 in `#if`, so "defined and 1" == "`${stuff}_IS_1`" is TRUE).
- `add_definitions()` sets a **directory property** that `try_compile` cannot see, so record CMake-level switches explicitly (e.g. `SET(LJ_TEST_ASSERT_SWITCHES_ADDED TRUE)` inside the `LUAJIT_ENABLE_FSANITIZE` block) and OR them into the probe result.
- Collect one note per deviation (`LUA_COMPAT_TAILCALL_COUNT` off, `LJ_DS_TRACEBACK_PATCH` off, `LUA_USE_ASSERT`/`LUA_USE_APICHECK` unset, plus the "probe compiled out ⇒ tailcall_lines/tailcall_debug pass vacuously" combination) and emit one `MESSAGE(WARNING ...)`; never `FATAL_ERROR`.
- Verify cheaply with a standalone wrapper project (no vcpkg): `project(ljswitch C ASM)`, `enable_testing()`, `add_subdirectory(<repo>/luajit luajit)`, configured once per case (`/DLJ_DS_TRACEBACK_PATCH=0`, `/DLUA_COMPAT_TAILCALL_COUNT=0`, `/DLUA_USE_ASSERT /DLUA_USE_APICHECK`, `-DLUAJIT_ENABLE_FSANITIZE=ON`), then `grep "test switches differ"` the configure logs. `LUAJIT_DIR` is set inside `luajit/CMakeLists.txt`, so the wrapper works; `xxcopy`/scratch dirs under `builds/` are gitignored.

# 6. Commit conventions (pushes deferred; doc §3.9 tracks the stack)
- luajit submodule, branch `dontstarve`: `git -C luajit add <files>` then `feat(scope): subject` (or `fix(...)`) + evidence paragraphs + `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Main repo: stage ONLY the gitlink (`git add luajit` — path-limited; the repo has unrelated dirty files), commit mirroring the subject on the current branch. Files under `tests/performance/` are **untracked as a whole** in this repo: adding one of them adds only that path, and the user's other files there (run.py, analyze.py, baselines/, their new startup_* scripts) must stay untouched — check `git status --short` after staging.
- The user owns commit scope: after a rollback (`git reset --soft HEAD~` keeps changes staged), **leave changes uncommitted and ask** which range to commit.
- Never push. The doc worktree branch `docs/hotpath-review` (`.claude/worktrees/luajit-hotpath-doc`) stays at its old commit unless the user moves it; don't edit the review doc yourself.

# 7. Throwaway probes: keep them out of the repo
- Scratch goes to `builds/` (gitignored) with a `_` prefix; the user asks for cleanup periodically — expect to delete your own `builds/_*` later, and never touch their `_apk_probe`/`_crashmap`/`_install_*`/`_ns_live_cmp*`/`_pkg_mod`/`_reconfigure.bat`.
- The user's perf harness trees (`builds/game-performance*`, `builds/ninja-multi-vcpkg`, `builds/game-performance-vm-release`) are theirs: rebuilding inside them is fine (e.g. `python tests/performance/build_release.py` refreshes the Release VM + hash evidence), deleting them is not.
