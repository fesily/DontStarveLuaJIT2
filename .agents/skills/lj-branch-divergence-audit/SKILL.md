---
name: lj-branch-divergence-audit
description: "Answer \"what differs between branch A and B / are the baselines different?\" for the LuaJIT fork: ancestry+merge-base check, per-side unique commit counts, baseline identification, feature/format/line-count diff, and a merge-vs-rebase recommendation."
---

# LuaJIT branch divergence audit

Use when the question is "两个分支差什么 / 基线是否一样" for `C:/Users/fesil/LuaJIT` (or any long-lived fork with parallel ports). Answer with facts from git, never from memory of the branches.

## 1. Topology first, features second

```bash
git branch -vv --list '<pat>*'
git worktree list
git merge-base A B && git describe --tags --always <base>
git rev-list --left-right --count A...B      # unique counts each side
```

Then settle **baseline identity** explicitly — the merge-base alone lies when both sides descend from an old tag but along different lineages:

```bash
for b in A B tarantool/master v2.1; do printf '%-16s ' $b; git rev-parse --short $b; done
git merge-base --is-ancestor tarantool/master B && echo base-is-tarantool
git merge-base --is-ancestor v2.1 A && echo base-is-upstream-v21
```

An old merge-base (e.g. `v2.1.0-beta3`, 2017) plus a huge left/right count means *different lineages*, not "same baseline, a few commits apart".

## 2. Detect re-port vs cherry-pick

```bash
git log --oneline --no-merges <base-of-each>..<branch>
git log --oneline <branch> --grep='<subject of other side>'   # expect 0 on the other side
```

No shared commit IDs + each side's port commit re-creating files (`5afad6b3` style) ⇒ **re-port**: fixes never propagate; state that consequence.

## 3. Feature diff that is actually verifiable

```bash
# file presence / absence (A added-only vs D removed-only means real layout split)
git diff --name-status A B -- src/ tools/ doc/ test/ | grep -E '^(A|D)'
# sizes of the contested modules
for b in A B; do for f in src/lj_sysprof.c src/lj_symtab.c src/lj_profile.c tools/sysprof/parse.lua; do
  printf '%-8s %-24s %s\n' $b $f "$(git show $b:$f 2>/dev/null | wc -l)"; done; done
# implementation markers (cost model, build system, formats)
git grep -c -F 'RtlCaptureStackBackTrace' $b -- src/
git show $b:tools/sysprof.lua | grep -nE 'format|json|folded|pdb'
git show $b:doc/<design>.md | grep -E '^#{2,3} '
```

Stream-format versions (`ljp vN`, `ljs vN`) and doc section lists are the cheapest feature-parity evidence. `grep` of the tool's `opt_map` keys gives CLI parity.

## 4. Recommendation shape

- Two heavily diverged (1400+ line net) implementations: **do not merge**; name the branch that is the live line and the one that is archival, plus what the archival branch is uniquely worth (e.g. a probe test, tarantool-tree validation).
- Flag volatile worktrees: anything under `%TEMP%` needs `git worktree move` to survive.

## Cheap traps

- `git diff --stat A B` is directional: `A` items are only-in-B, `D` items are only-in-A.
- `git grep -c -F` against a branch fails silently for absent files; distinguish "file missing" from "marker missing" with `git ls-tree`. Occasionally also a branch name quoting problem: pass `$b -- paths`.
