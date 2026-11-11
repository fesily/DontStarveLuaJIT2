---
name: rebase-dirty-worktree-with-submodules
description: DontStarveLuaJIT2 脏工作区 + 子模块场景下 rebase 到最新 origin/master、解决 CHANGELOG 冲突、清子模块残留锁、A/B 定位上游 bump 弄坏的构建并重测（不擅自动子仓库历史）
---

# 适用

DontStarveLuaJIT2（本仓库）在 **worktree 有他人未提交改动** + **带子模块**的情况下，把本地提交 rebase 到更新后的 `origin/master`，然后重新构建/测试并定位“上游 bump 弄坏构建”。

# 1. rebase：用 autostash

```bash
git status --porcelain          # 记下哪些是别人的（.vscode/*、3rd/dst/...、tests/performance/*）
git fetch origin --prune
git log --oneline -5 origin/master
git diff --stat HEAD origin/master   # 看上游动了哪些文件，是否撞上别人的脏文件
git rebase --autostash origin/master
```

- 不要 `git stash push` 手工搬别人的改动；`--autostash` 在本仓库已验证可用（脏文件与上游改动不重叠时 pop 无冲突）。
- 普通 `git rebase` 会直接因脏工作区拒绝。

# 2. 冲突：只在中英 CHANGELOG

两条 CHANGELOG（`CHANGELOG.md` / `CHANGELOG_EN.md`）都在 `## 未发布` 下追加条目，必然冲突。规则：**上游新条目在前，自己的条目随后**，后面接原有条目。用 Python 按 `<<<<<<< HEAD` / `=======` / `>>>>>>>` 切块合并（终端是 CP936，直接 `sed`/`cat` 看会乱码，但文件本身是 UTF-8，必须用 Python 以 UTF-8 读写）。

```bash
git add CHANGELOG.md CHANGELOG_EN.md
GIT_EDITOR=true git rebase --continue   # 非交互环境必须给 GIT_EDITOR
git diff --stat origin/master HEAD      # 应只剩自己那一个提交的范围
```

# 3. 子模块同步：残留锁

`git submodule update --init --recursive` 可能报：

```
fatal: Unable to checkout '<sha>' in submodule path '3rd/frida-gum-src'
... an editor opened by 'git commit' ... remove the file manually
```

这不是编辑器问题，是子模块 gitdir 的残留锁：

```bash
find .git/modules -name '*.lock'
rm -f .git/modules/<sub>/index.lock .git/modules/<sub>/modules/<nested>/index.lock
git submodule update --init --recursive
git submodule status    # 无 '+' 前缀 = 已对齐记录提交
```

# 4. 上游 bump 弄坏构建：A/B 定位

现象：全量构建在某个子模块源文件报错（例：`luajit/src/lib_debug.c(210): error C2159`），改动与本次提交无关。

```bash
git -C <sub> checkout <old-sha>   # rebase 前的指针
cmake --build builds/ninja-multi-vcpkg --config Release   # 绿 → 证明是 bump 引起
git -C <sub> checkout <new-sha>
git -C <sub> log --oneline <old>..<new>   # 找上游修没修
```

若上游分支已修（`git -C <sub> fetch --all --prune` 后看 `origin/<branch>`），直接 `git -C <sub> checkout -- <patched-file>` 丢弃本地临时补丁，再 `git -C <sub> checkout origin/<branch>`。

**边界**：子仓库里的修复/提交/推送、以及 superproject 的子模块指针 bump，必须问用户；未经同意不要动子仓库历史，也不要自行提交 bump。

# 5. 重测与判读

```bash
cmake --build builds/ninja-multi-vcpkg --config Release
builds/ninja-multi-vcpkg/src/DontStarveInjector/util/tests/Release/test_util.exe
cd builds/ninja-multi-vcpkg && ctest -C Release --output-on-failure
```

- 构建用绝对路径 `C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe`（PATH 里没有 cmake）。
- 已知长期失败：`game_performance_unit`，根因是工作区里未提交的 `tests/performance/server_load.py`（断言 `len(stopped)==1` 得到 0），与本轮改动无关——判读时直接说明，不要试图“修”它。
- 基线：`test_util` 10 cases / 34 assertions；`ctest` 92/93。
- 构建输出里刷屏的 `warning C4819`（该文件包含不能在当前代码页(936)中表示的字符）是既有文件的中文注释，不是错误；新增文件建议写纯 ASCII 避免它。
