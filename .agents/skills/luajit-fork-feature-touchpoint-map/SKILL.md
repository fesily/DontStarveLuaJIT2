---
name: luajit-fork-feature-touchpoint-map
description: "Map which engine files a feature touched in a LuaJIT fork (tarantool/openresty) using git grep + git log -S, before reading code."
---

# Map a feature's engine touchpoints in a LuaJIT fork

Use when asked "what did branch X change in the engine for feature Y" — never read files one by one, never diff the whole fork against upstream (it contains hundreds of unrelated Tarantool/OpenResty patches).

## Procedure

1. Locate the reference and the feature branch.
   ```bash
   git remote -v                 # tarantool -> github.com/tarantool/luajit, upstream -> LuaJIT/LuaJIT
   git branch -r
   git worktree list             # local sysprof-win etc. are OUR changes, ignore unless asked
   ```

2. Enumerate call sites / references with `git grep` on the remote-tracking tree, excluding the feature's own modules:
   ```bash
   git grep -n -i "sysprof" tarantool/master -- src/ ':!src/lj_sysprof.c' ':!src/lj_sysprof.h'
   ```
   This directly yields the "engine built-in" file list (vm_*.dasc, lj_obj.h, lj_parse.c, lj_bcread.c, lj_trace.c, lj_state.c, lj_arch.h, lj_errmsg.h, lib_misc.c, lmisclib.h, lj_mapi.c).

3. Attribute each touchpoint to a commit with `-S` (pickaxe) restricted to `--first-parent` so merge noise disappears:
   ```bash
   git log --oneline -S"LJ_HASSYSPROF" --first-parent tarantool/master -- src/
   git log --oneline -S"top_frame_info"  --first-parent tarantool/master -- src/
   ```

4. Get per-commit file lists and intent:
   ```bash
   git show --stat --format= <sha>     # files + line counts
   git log -1 --format=%s <sha>; git show <sha>   # commit message explains WHY (design rationale)
   ```

5. For new modules, find creation:
   ```bash
   git log --oneline --diff-filter=A tarantool/master -- src/lj_sysprof.c src/lj_wbuf.c ...
   ```

6. Read the actual hook hunks from the branch tip, not from a diff:
   ```bash
   git show tarantool/master:src/vm_x64.dasc | sed -n '350,405p'
   git show tarantool/master:src/lj_obj.h    | sed -n '596,700p'
   ```

## Reporting shape

Table: file → what changed → commit sha. Then a short list of new modules (with their originating commit), then verified-untouched files (`git diff --name-only <base> HEAD -- <paths>` returning empty). Keep design rationale from commit messages — it is the only place the constraints (e.g. "cannot run both profilers, they share SIGPROF") are written down.

## Pitfalls

- Do not diff the fork against `upstream/v2.1`: the fork carries unrelated patches, so the diff is not the feature.
- Do not confuse the user's working branch with the upstream feature branch; check `git worktree list` and say which tree you read.
- `git grep` on `src/` alone is enough: hooks always sit next to the VM/GC/parser/dispatch code.
- Build-system changes (`Makefile.original`, `CMakeLists.txt`, `ljamalg.c`, `DASM_AFLAGS`) are real touchpoints: a missing `-D LJ_HASSYSPROF` in dynasm silently disables VM hooks.
