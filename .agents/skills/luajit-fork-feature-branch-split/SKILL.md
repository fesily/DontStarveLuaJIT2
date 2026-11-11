---
name: luajit-fork-feature-branch-split
description: "Split the LuaJIT fork's combined BC_INT3 + sysprof branch into per-feature branches on v2.1: decoupling table, cherry-pick resolution, verification matrix."
---

Split a combined feature branch of the LuaJIT fork (BC_INT3 vs sysprof/mixprof) into one branch per feature, both rebased on the current `v2.1`.

## 1. Establish the real base
- `git fetch upstream v2.1`; a local `v2.1` is often one fetch stale. Compare `git rev-parse v2.1 upstream/v2.1`.
- Fast-forward it **from the worktree that has it checked out** (`git -C C:/Users/fesil/LuaJIT merge --ff-only upstream/v2.1`); `git branch -f` fails for a checked-out branch.
- Check overlap before rebasing: `git diff --name-only v2.1 upstream/v2.1` vs the branch's own files. Recent upstream v2.1 commits touch only `src/lj_asm_x86.h`, `src/lj_asm.c`, `src/lj_opt_fold.c`, `dynasm/dasm_arm64.h`, so a sysprof/int3 branch replays cleanly.

## 2. Create the feature branch and cherry-pick
- `git switch -c int3 <v2.1>` then cherry-pick the feature commits in order (`git cherry-pick --continue` after each resolution).
- Worktrees: a branch checked out elsewhere can only be rebased from that worktree. If that worktree lives under `%TEMP%`, verify it is not emptied (a temp cleanup deletes tracked files → `git status` shows N×`D`); recover with `git worktree remove --force <path>` + `git worktree add C:/Users/fesil/.omp/wt/<name> <branch>`.

## 3. Decoupling points (sysprof → int3 branch)
Because the BC_INT3 commit was authored on the sysprof branch, its diff assumes sysprof symbols. Resolve each:

| File | int3 branch keeps | sysprof branch keeps |
|---|---|---|
| `src/luajit_rolling.h` | only the `luaJIT_int3_*` API | `hoststack`/`mixedstack`/`symtab` decls |
| `src/lj_profile.c` | `lj_profile_active()` + `if (lj_int3_active()) return;` guard | `lj_profile_timer.h`/`lj_mixprof.h`/`lj_symtab.h` includes |
| `src/lj_int3.c` | `setvmstate(g, C)` — v2.1 has a single C state, no `LJ_VMST_CFUNC` | `CFUNC` |
| `src/lj_arch.h` | no `LJ_HASSYSPROF` block | `LJ_HASSYSPROF` derived from `LJ_HASPROFILE && LJ_HASJIT` |
| `src/ljamalg.c` | `lj_int3.c` only | `lj_mixprof.c`, `lj_sysprof.c`, `lj_profile_timer.c`, `lj_symtab.c`, `lj_mapi.c`, `lj_wbuf.c`, `lj_utils_leb128.c`, `lib_misc.c`, `lib_mixprof.c` |
| `src/Makefile` | `lj_api.o lj_profile.o lj_int3.o` | `... lj_mixprof.o` |
| `src/Makefile.dep` | regenerate | regenerate |
| `int3-smoke.c` | delete the `[10]` sysprof-coexistence test + its dispatch line (tests 1–9 use the stock `luaJIT_profile_*` API and compile on pure v2.1) | — |

- A commit that was authored on the combined branch may be *mostly* the other feature (`0824a68e "Core: Fix reduced configurations..."`): cherry-pick it where its real content lives (sysprof: lj_arch.h + ljamalg.c) and drop the irrelevant hunks; do not drag it into the other branch.
- After touching `ljamalg.c`, run `mingw32-make depend` in `src/` and grep `src/Makefile.dep` for the removed objects (a stale `#include "lj_mixprof.c"` in `ljamalg.c` makes `make depend` abort with a missing-file error — that error is the diagnostic).
- Fix stale API comments found while splitting (e.g. the header claimed "JIT off and flushed" while the implementation keeps the JIT enabled and only flushes the traces that can reach the armed instruction).

## 4. Verify each branch
Environment: git-bash `mingw32-make` (cmd.exe quoting of `XCFLAGS` breaks; pass `"XCFLAGS=-D... -D..."` from git-bash).

- dynasm all backends, no failures:
  `host/minilua.exe ../dynasm/dynasm.lua -D ENDIAN_LE -D JIT -D FFI -D DUALNUM -D FPU [-D P64] -o out.h vm_<a>.dasc` for x64, x86, arm, arm64, mips, mips64 (`-D P64`), ppc (`-D ENDIAN_BE`).
- x64-GC64 and x86-nonGC64: `gcc -O1 -Wall -Wextra -I src int3-smoke.c src/libluajit-5.1.dll.a -o src/int3-smoke.exe` then `int3-smoke.exe` → `PASSED: 0 failure(s)`.
- int3 branch also with the reduced libs: `-DSMOKE_NO_JIT` (built with `XCFLAGS="-DLUAJIT_ENABLE_GC64 -DLUAJIT_DISABLE_JIT"`) and `-DSMOKE_NO_PROFILE` (`[9] no-profile: calls=0` = API returns `LUAJIT_INT3_UNAVAILABLE`).
- Build matrix: `-DLUAJIT_DISABLE_JIT`, `-DLUAJIT_DISABLE_PROFILE`, both, and `amalg`.
- sysprof branch has no harness: run a Lua check instead — `require('misc').sysprof.start{mode='D',interval=1}`, a `string.sub(BIG,1,1e6)` loop (FFUNC), a `string.find(BIG,'zz')` loop (CFUNC), an interpreter loop (LFUNC), then assert `report().vmstate.FFUNC/CFUNC/LFUNC > 0`; run it on both x64-GC64 and x86-nonGC64 (the latter is what exercises the ported `set_vmstate_*` macros).
