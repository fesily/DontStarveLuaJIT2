---
name: luajit-fork-rebase-and-verify
description: "Rebase uncommitted/own commits of the C:/Users/fesil/LuaJIT fork onto the sysprof-v2.1 baseline, resolve conflicts, and re-verify with the int3-smoke harness matrix on Windows/MinGW."
---

# Rebase a fork-work branch onto the current LuaJIT baseline and verify

Use when work was cut from an older base and must move onto the fork's rolling
line (e.g. before continuing INT3 / sysprof / ETW work in `C:/Users/fesil/LuaJIT`
or a worktree like `C:/Users/fesil/.omp/wt/<name>`).

## 1. Pick the right baseline

```bash
git for-each-ref --sort=-committerdate --format='%(committerdate:short) %(refname:short) %(objectname:short) %(subject)' refs/heads refs/remotes | head -15
```
- The fork's active line is **`sysprof-v2.1`** (Windows sysprof/mixprof/mapi/symtab/wbuf/profile_timer + tools). Bare `upstream/v2.1` moves much slower; ask/state the choice if the delta sizes are close.
- `git merge-base --is-ancestor <old-base> <new-base>` then `git rev-list --count <old-base>..<new-base>` to size the delta; `git diff --stat` to see which of *your* files the baseline touched (conflicts are predictable from that list).

## 2. Make the replay cheap

- Squash your own commits into one *first* (`git reset --soft <old-base>` + commit) when the intermediate state is not reviewable/needed: otherwise the same conflicts must be resolved once per commit.
- Keep a safety ref: `git branch <branch>-pre-rebase <tip>`.
- Untracked files that the baseline tracks abort the rebase ("would be overwritten"). Move them aside, then compare afterwards:
  `diff -q <file> <(git show <base>:<file>)`.

## 3. Resolve

Typical conflict trio for this fork: `src/lj_profile.c` (sysprof restructured it), `src/Makefile` (`LJCORE_O`: keep `lj_mixprof.o lj_profile_timer.o lj_sysprof.o …` *and* your new object), `src/luajit_rolling.h` (baseline added `luaJIT_profile_hoststack/mixedstack/symtab`; keep both API blocks). The 7 `vm_*.dasc` files usually auto-merge.

## 4. Fix the dependency file — this is mandatory

The fork's committed `src/Makefile.dep` is **stale**: the new modules
(`lj_mixprof/lj_sysprof/lj_mapi/lj_symtab/lj_wbuf/lj_utils_leb128/lj_profile_timer`,
`lib_misc/lib_mixprof`) have no stanzas, so `make -j` races and compiles them
before `luajit.h` exists (`fatal error: luajit.h: No such file or directory`).

```bash
cd src
mingw32-make luajit.h          # generate it first: `make depend` would touch an empty one
mingw32-make depend            # regenerates with the host gcc
```
Then restore the **target-specific** stanzas from the baseline, because the
host generates them empty (their includes are guarded by `LUA_USE_ASSERT` or
`LJ_32 && LJ_HASFFI`):

```python
# for name in ('lj_assert.o:', 'lj_opt_split.o:'): copy that stanza verbatim
# from `git show <base>:src/Makefile.dep` into the regenerated file
```
Verify semantically, not by text:
parse both files into `{obj: set(headers)}` and print only the diffs; the
result should be exactly "your new object + your header additions".

## 5. Known baseline gaps (as of sysprof-v2.1 @ f9aa64ae)

- sysprof split `LJ_VMST_C` into `LJ_VMST_LFUNC/FFUNC/CFUNC` but **only updated
  `vm_x64.dasc`**. `vm_x86.dasc`, `vm_arm64.dasc`, `vm_mips64.dasc` still emit
  `LJ_VMST_C` via their own `mv_vmstate …, C` macros.
  For *verification only* (never commit) build with
  `XCFLAGS="-DLUAJIT_DISABLE_GC64 -DLJ_VMST_C=LJ_VMST_CFUNC"`, and for
  cross-assembly add `-DLJ_VMST_C=LJ_VMST_CFUNC` to the scratch buildvm gcc line.
- `LJ_HASSYSPROF` originally ignored `LJ_HASPROFILE`/`LJ_HASJIT`: reduced
  builds failed on `lj_profile_timer_stop()` and on the trace IR views.
  Guard it as `… || !LJ_HASPROFILE || !LJ_HASJIT`.
- `ljamalg.c` lacked the new modules → `make amalg` could not link. Add
  `lj_mixprof, lj_sysprof, lj_profile_timer, lj_symtab, lj_mapi, lj_wbuf,
  lj_utils_leb128, lib_misc, lib_mixprof` in `LJCORE_O`/`LJLIB_O` order.

## 6. Verify

```bash
cd src
run_cfg() { name=$1; xc=$2; hf=$3; mk=$4;
  mingw32-make clean >/dev/null 2>&1
  mingw32-make -j8 $mk XCFLAGS="$xc" 2>&1 | grep -E "error|OK" | tail -1
  gcc -O1 $hf -I . ../int3-smoke.c libluajit-5.1.dll.a -o int3-smoke.exe
  cmd.exe /c "int3-smoke.exe" > /tmp/$name.txt 2>&1
  echo "$name rc=$? $(grep -E 'PASSED|FAILED' /tmp/$name.txt)"; }
run_cfg default  ""                                   ""        ""
run_cfg noprofil "-DLUAJIT_DISABLE_PROFILE"            "-Wno-unused-function -DSMOKE_NO_PROFILE" ""
run_cfg nojit    "-DLUAJIT_DISABLE_JIT"                "-Wno-unused-function -DSMOKE_NO_JIT"     ""
run_cfg both     "-DLUAJIT_DISABLE_JIT -DLUAJIT_DISABLE_PROFILE" "-Wno-unused-function -DSMOKE_NO_JIT -DSMOKE_NO_PROFILE" ""
run_cfg amalg    ""                                   ""        amalg
run_cfg gc64off  "-DLUAJIT_DISABLE_GC64 -DLJ_VMST_C=LJ_VMST_CFUNC" "" ""
```
Also: `dynasm` preprocessing for all 7 dascs, `buildvm -m elfasm` for
arm64/mips64, and a standalone `gcc -c … lj_int3.c` under each `-D` combination.
Always finish with `make clean && make` so the tree ships in the default config.

## 7. Sandbox/tooling quirks on this machine

- Native tools (gcc, minilua, python, newly built .exe) cannot see MSYS paths:
  `/tmp/x` and `/c/...` are invisible to them. Use repo-relative paths or `C:/...`.
- Bash refuses to exec arbitrary binaries (`error: command not found`); run them
  through `cmd.exe /c "cd /d C:\path && prog.exe …"`.
- After editing **any** header that changes struct layout/enums (`lj_dispatch.h`
  `GG_LEN_*`, `lj_bc.h`), `mingw32-make clean` first: incremental builds keep
  stale objects and crash in the exit stub / dispatch table.
- `mingw32-make amalg` on Windows needs the alias `-Wno-unused-function`
  tolerance if a helper is static-only in the amalgamation.
