---
name: luajit-squash-rebase-to-updated-v21
description: "Squash a LuaJIT fork branch into one commit and rebase onto an updated origin/v2.1: backup branch, soft-reset to old base, single rebase round, equivalence check via git diff old-tip, then rerun the full 6-config build/test matrix."
---

# 适用

LuaJIT fork（`C:/Users/fesil/.omp/wt/int3-da63e8e`，分支 `int3`）需要把一条功能分支压成单提交、并改基到**已前进的** `origin/v2.1` 上时。不适用于需要保留分步历史的评审分支。

## 0. 先量分歧，别信口头数字

```bash
git log --oneline v2.1..int3 | wc -l      # 实际提交数（本仓库常与用户所说数字不符）
git rev-list --left-right --count int3...origin/v2.1   # 领先/落后
git merge-base int3 origin/v2.1 | cat     # 记下 old-base
git fetch origin && git log --oneline -3 origin/v2.1 | cat
git log --oneline <old-base>..origin/v2.1 | cat
git diff --stat <old-base> origin/v2.1 | tail   # 与功能文件集比对是否重叠
```

## 1. 留备份分支（必须）

```bash
git branch int3-squash-backup <old-tip>
```

## 2. 软重置 + 单提交

```bash
git reset --soft <old-base>   # index 保留 old-tip 的树，工作区不动
git diff --cached --stat | tail -5   # 确认只有功能文件集，且新文件是 A
git commit -F msg.txt
```

消息按仓库风格：`<Prefix>: <Capitalized imperative>.`，正文写最终设计（不写已删除的中间态）+ 逐文件清单 + `Verified:` 数字。

## 3. 改基（冲突只解一轮）

```bash
git rebase --onto origin/v2.1 <old-base> int3
```

先压缩再 rebase，而不是先 rebase 再压缩：14 个提交改基要解 14 轮潜在冲突，单提交只解 1 轮。

## 4. 等价性与验证（必须）

```bash
git diff --stat <old-tip> HEAD   # 应只剩上游动过的文件 -> 功能内容零变化
git rev-list --count origin/v2.1..int3    # 应为 1
```

上游 bump 后**重跑全矩阵**（本仓库标准 6 项）：

```bash
cd src
for cfg in "A:-DLUAJIT_ENABLE_GC64 -DLUA_USE_ASSERT:-DSMOKE_NONE" \
           "B:-DLUA_USE_ASSERT:-DSMOKE_NONE" \
           "C:-DLUAJIT_DISABLE_JIT -DLUA_USE_ASSERT:-DSMOKE_NO_JIT" \
           "D:-DLUAJIT_DISABLE_PROFILE -DLUA_USE_ASSERT:-DSMOKE_NO_PROFILE" \
           "E:-DLUAJIT_DISABLE_JIT -DLUAJIT_DISABLE_PROFILE -DLUA_USE_ASSERT:-DSMOKE_NO_JIT -DSMOKE_NO_PROFILE"; do
  n=${cfg%%:*}; r=${cfg#*:}; xc=${r%%:*}; sm=${r#*:}
  mingw32-make clean >/dev/null 2>&1
  mingw32-make -j8 XCFLAGS="$xc" >/dev/null 2>&1 && \
    gcc -I . $sm ../int3-smoke.c libluajit-5.1.dll.a -o smoke_$n.exe && \
    echo "cfg $n: $(./smoke_$n.exe 2>&1 | tail -1)"
  rm -f smoke_$n.exe
done
mingw32-make clean >/dev/null 2>&1
mingw32-make -j8 amalg XCFLAGS="-DLUAJIT_ENABLE_GC64 -DLUA_USE_ASSERT"   # 编译即可
```

最后恢复主配置（GC64+assert）并重建 `int3-smoke.exe`，保证留在工作区的构建与已提交内容一致。

## 陷阱

- 该 worktree 常年挂着他人未跟踪文件（`doc/*-design.md`、`doc/tarantool-*`）；`git add` 只写具体路径，绝不 `git add -A`。
- `mingw32-make clean` 只删 `ALL_RM`（`*.o`、`host/*.o`、exe/dll、生成头），不会删 `src/buildvm-arch.h` 之类散落副本——若它消失，是别的步骤干的，别声称是 clean 造成的。
- 重写分支后 `origin/<branch>` 仍指向旧历史，需 `git push --force-with-lease`；未获授权不要推。
- 压缩前若用户给的提交数与实测不符，以 `git log <base>..` 实测为准并明确说明。
