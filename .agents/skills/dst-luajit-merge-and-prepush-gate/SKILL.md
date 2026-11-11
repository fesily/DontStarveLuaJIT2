---
name: dst-luajit-merge-and-prepush-gate
description: DontStarveLuaJIT2：合并远端分支（含 CHANGELOG 未发布段冲突）并跑 pre-push 门禁测试集；含 MSVC 构建与工具定位
---

# 合并分支 + 跑 pre-push 门禁（DontStarveLuaJIT2）

`git pull/fetch` 后合并远端 fix 分支到本地分支，并要求“跑 push hook 测试集”时用。

## 1. 侦察
```bash
git status --short --branch
git fetch origin <branch>
git rev-list --left-right --count HEAD...origin/<branch>
git diff --name-status $(git merge-base HEAD origin/<branch>) origin/<branch>
```
对比 `git status` 里未提交/未跟踪文件与分支改动文件的重叠：重叠文件会让 merge 冲突或被覆盖（本仓库常见 `Mod/deps/liblua51.so`）。

## 2. 合并
```bash
git merge --no-commit --no-ff origin/<branch>
```
- 本仓库 `CHANGELOG.md` / `CHANGELOG_EN.md` 的「未发布」段几乎必冲突：两侧都在段首加条目。解决原则 = 保留 master(ours) 已有条目 + 只追加分支真正新增、且 master 尚无的条目；分支旧措辞/重复条目丢弃。用 `conflict://<N>` 写回，或直接 `edit`。
- `git diff --name-only --diff-filter=U` 确认无残留 unmerged，`grep '^<<<<<<<'` 复查。
- `git add` 冲突文件后 `git commit -F -`。

## 3. 必须重新构建（否则门禁跑的是旧二进制）
`cmake`/`ctest` 通常不在 PATH。用 VS 自带：
`C:/Program Files/Microsoft Visual Studio/*/*/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/{cmake,ctest}.exe`
（ctest 的路径 `tools/pre_push.py` 会自己 glob 兜底，cmake 不会）

构建目录由 `pre_push.py` 自动选最新的有 `CTestTestfile.cmake` 的：常见 `builds/ninja-multi-vcpkg`（Ninja Multi-Config，Debug）。
```bash
"<vs>/cmake.exe" --build builds/ninja-multi-vcpkg --config Debug
```

### 已知 MSVC-only 编译雷区
分支常自 Linux 开发、Windows 才暴露：`error C2589` / `std::min(` / `std::max(` 被 `windows.h` 宏展开。修复 = 加括号写成 `(std::min)(...)`（本仓库既有约定）。见 memory 中同类记录。

## 4. 跑门禁
```bash
python tools/pre_push.py            # 全量（会新开 ctest -j <cpu>），耗时可达 ~6min
python tools/pre_push.py --dry-run  # 先看选中的 build dir/config
python tools/pre_push.py -R <regex> # 单测快验
```
游戏类 ctest（plugin_client_inject_smoke / dedicated_sim_pause / game_mod_throw_abort）共享 `RESOURCE_LOCK(dst_game_server)`，需本机装有 DST 才能过；通过即 80/80。
用 `wait` 等后台任务，不要轮询。

## 5. 收尾
修复构建/集成的改动单独 commit（不要 amend 已定的 merge commit），信息用仓库的 conventional 风格。
