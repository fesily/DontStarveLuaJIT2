---
name: partial-commit-own-hunks
description: 只提交自己这一轮 hunk：worktree 混有他人未提交改动时的逐 hunk 拆分（git show HEAD + hash-object + update-index --cacheinfo），含 Windows /tmp 路径陷阱
---

# 适用

在一个**已经堆积了他人/历史未提交改动**的仓库里，只提交自己这一轮的 hunk（本仓库 DontStarveLuaJIT2 的常态：签名库 v2、`types_android.hpp`、`.vscode/*` 常年挂在 worktree 里）。

# 步骤

## 1. 先划清归属

```bash
git status --porcelain            # 第 1 列空 = 未暂存；此时 index == HEAD
git diff --stat
git diff -U3 -- <file>            # 逐 hunk 人工辨认：这一行是我写的吗？
```

- **全是我的** → 直接 `git add <file>`。
- **完全不是我的** → 不碰。
- **混合同一文件** → 走第 2 步。

不要用 `git add -p`（非交互环境不可用），也不要用 `git stash push <file>` + `git stash pop`（会把别人的改动挪来挪去）。

## 2. 混合文件：基线 + 只写回我的插入

```bash
git show HEAD:src/.../Foo.cpp > "$W/Foo.cpp"     # 基线（index 内容）
# 在 $W/Foo.cpp 上只施加我的改动（锚点必须唯一：count==1 才 replace）
H=$(git hash-object -w --path=src/.../Foo.cpp "$W/Foo.staged.cpp")
git update-index --cacheinfo 100644,$H,src/.../Foo.cpp
```

关键点：

- `hash-object -w --path=<repo 相对路径>` 才会套用 `.gitattributes` 的换行规格，和 `git add` 结果一致。
- 写临时文件时保持 `\n`（`newline="\n"`，并 `replace("\r\n","\n")`），否则行尾混杂会在提交里炸出整文件 diff。
- 锚点断言 `text.count(old) == 1`，避免误替换到同名代码。

## 3. 复核（必须）

```bash
git diff --cached --stat
git diff --cached -- <path> | grep -E "^[-+]" | grep -v "^[-+][-+]"
```

插入/删除行数应当等于“我这一轮真的改了几行”；逐行读一遍，确认没有别人的 `format_version` / `platforms` / 重构 hunk 混进来。

## 4. 提交

```bash
git commit -F - <<'MSG'
<type>(<scope>): <subject>

<根因 + 机制 + 改动清单 + 验证数字>
MSG
git log --oneline -2
git status --porcelain | head   # 确认别人的改动仍在、且仍是未暂存
```

# Windows 陷阱

- git-bash 的 `/tmp/idx` 与 Python 的 `/tmp` 不是同一个路径（Python 会解析成 `\tmp`，报 FileNotFoundError）。先 `cygpath -w /tmp/idx` 拿真实路径，交给 `eval` / 脚本时用 Windows 绝对路径。
- `git hash-object`、`git add` 也要传 Windows 绝对路径或仓库相对路径，别传 msys 的 `/tmp/...`。

# 已验证的判定信号

`git status --porcelain` 里 `MM` = 该文件既有已暂存（我的）又有未暂存（别人的）改动——这正是拆分成功的样子；若出现单个 `M ` 夹带整文件 diff，说明拆分失败，回退 `git reset <path>` 重来。
