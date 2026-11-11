---
name: fork-branch-foreign-commit-audit
description: 审阅别人推到你 squash 提交之上的分支提交：判定是否严格超集、逐点核对既有修复、链接与测试是否真的执行、teeth 验证，再决定 take/rebase/drop。含 LuaJIT 专属陷阱（内部符号不导出、table __gc 不执行）。
---

# 适用

`origin/<my-branch>` 在你自己的 squash 提交**之上**多出了不是你写的提交（本次：`383f5472` 落在 `63c8934c` 之上）。要决定 take（fast-forward）/ rebase 重做 / 丢弃 / 挑拣。核心判据不是读提交信息，而是**跑出来的证据**。

# 步骤

## 1. 先定位三方向关系

```bash
git fetch --all --prune
git log --oneline -4 origin/<branch>            # 多了什么
git rev-list --left-right --count <branch>...origin/<branch>
git log --oneline -1 origin/v2.1; git log --oneline -1 upstream/v2.1   # 基线是否也动过
```

## 2. 超集判据：harness 是纯增量吗

```bash
git show <my-tip>:int3-smoke.c > /t/local.c
git show origin/<branch>:int3-smoke.c > /t/remote.c
diff /t/local.c /t/remote.c | grep -c '^<'      # 我的断言被删/改的行数
diff /t/local.c /t/remote.c | grep -c '^>'
```

`删除行数 == 0` ⇒ 我的回归全部保留。再用标记串确认关键子测试仍在（`grep -c` 每个 marker）：
`line events`、`CALLM+call hook`、`close with finalizer`、`rec.depth == 4 + fr2`、`wback`、`arm from cb`。
同时看 `git diff --stat <my-tip> origin/<branch>`：**没动 `.dasc` / `lj_state.c` / `lj_debug.c` / `lj_obj.h`** 就说明我前几轮的后端、teardown、名称回溯、per-VM 会话改动没被回退。

## 3. 逐点核对既有修复（读远端文件，不读 diff）

```bash
git show origin/<branch>:src/lj_int3.c > /t/remote_int3.c
grep -nE '^(static |LJ_FUNC|LUA_API|LJ_FUNCA)' /t/remote_int3.c   # 函数清单
```

对每个修复找锚点：hit 里的 `oldpc` 保存/还原、`int3_paired_jump`、`disp_ins(`、`slot[]`/`nmax`、`g->int3`、`int3_sessions`、`luaJIT_int3_rearm` 是否仍不存在。函数清单里出现**新名字**（`int3_commit`、`int3_mount_owner`、`lj_int3_nojit_release`）就是新增能力，单独评估。

## 4. 构建 + 链接（最容易被忽略的一步）

```bash
gcc -I src int3-smoke.c src/libluajit-5.1.dll.a -o src/int3-smoke.exe
```

- 用 DLL 导入库时**只有 `LUA_API` 符号可用**；`LJ_FUNC` 内部符号（如 `lj_int3_active`）会 `undefined reference`。
- 远端若在 harness 里 `extern` 了内部符号，就是它自己没按本仓库方式链接 → 改用公开 API 可观测量（"新 VM 能 start"证明进程级槽已释放；`arm()` 返回 `DISABLED` 证明本 VM 无会话）。

## 5. 测试是否真的执行

新测试"通过"不等于执行过：

- LuaJIT 遵循 Lua 5.1 语义，`setmetatable(t,{__gc=...})` 对 **table 永不跑 finalizer** → 必须 `newproxy(true)` 或 FFI cdata；否则测试只断言自己的 `-1` 哨兵。
- 检查哨兵式断言（`CHECK(x == -1)` 紧跟 `x = -1`）是 tautology。
- 给新测试加可读输出（`printf`），确认路径真的走到。

## 6. Teeth：每条新修复都要能反向失败

临时把修复改回旧行为，跑 harness，必须 FAIL/崩，再撤销：

| 修复 | 反向操作 | 期望 |
|---|---|---|
| close 前释放会话 | 把 `lj_int3_close` 挪回 `close_state`（finalizer 之后） | `[19] finalizer-arm=1`(BUSY) + `[5] close-hits=1` |
| owner 释放 NOJIT | 去掉 `setptmode` 里的 `lj_int3_nojit_release` | 先 arm 再 `jit.off` 再 cancel → trace 又开始了 |
| 回调栈视图 | `disp_ins` 无条件 `*pc` | `rec.depth` 从 `4+LJ_FR2` 掉到 `pt->framesize` |

## 7. 决定与提交

- 超集 + 逐点保留 + 构建通过 + teeth 命中 ⇒ `git merge --ff-only origin/<branch>`，然后**不要 amend 别人的提交**；自己补的（如 harness 修复）单独一条 `Test:` 提交。
- 再跑 5 配置矩阵（GC64+assert / 非 GC64 / `DISABLE_JIT` / `DISABLE_PROFILE` / 两者皆禁）+ 行为探针（跨 VM 继承、关闭后 profiler、finalizer、jit.off 所有权）。

# 判据信号

- `diff` 删除行数为 0 且 `grep -c` 关键 marker 全 ≥1 ⇒ 我的断言还在。
- `git diff --stat` 不含我改过的文件 ⇒ 我的修复没被回退。
- 链接报 `undefined reference to lj_...` ⇒ harness 越过了公开 API 边界。
- 新测试"通过"但无输出/只有哨兵断言 ⇒ 先怀疑它没执行。

# 陷阱

- 不要用提交信息判断语义；本次提交信息描述的方向（pending/mount）看似与我"立即挂载 + `lj_int3_ins`"冲突，实际是**并存**：mounted 槽仍靠 `lj_int3_ins`，pending 只覆盖 arm 窗口。
- Windows/MinGW：临时文件用 `C:/...` 绝对路径（`/tmp`、`/c/...` 在本工具链里不可靠）；`bash script.sh` 的 `cd C:/...` 可能失败，直接用工具 shell 的 `cwd`/`cd`。
- `make clean` 会删 `src/*.exe`，矩阵跑完要重建一次 `int3-smoke.exe` 再报结论。
