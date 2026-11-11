---
name: dsj-install-freeze-and-installer-semantics
description: DST LuaJIT 安装后游戏加载卡住（怀疑特征码生成器）的定位流程，以及 install.ps1/install.bat 覆盖、清理、marker 解析语义
---

# DST LuaJIT：装完卡加载 / 安装器语义

用于两类问题：
1. 用户报「跑了 install.ps1 后游戏加载进度条卡住不动，是不是特征码生成器卡住了」；
2. 需要说清 install.ps1 / Mod/install.bat 对已存在文件、marker、`.pkg` 镜像的处理。

## 先判定：是「慢」还是「真死」

| 检查 | 位置 | 结论 |
|---|---|---|
| `signatures_client.json` 是否存在、mtime 是否更新 | `<游戏>/mods/<名>/` 或 `…\workshop\content\322330\3444078585\` | 不存在/没更新 ⇒ 生成完没落盘（`SignatureJson::update_signatures` 的 `ofstream` 没有错误检查），每次启动都重生成 |
| 是否有标题 `patch process...` 的窗口及其百分比 | 屏幕 | 有窗口 + 0.0% ⇒ 正常生成中；没窗口 ⇒ 没走到签名阶段 |
| `bin64/DontStarveInjector_client.log` | release 只有 err 级 | 出现 `unresolved Lua functions` / `cannot generate signatures unique from Lua base` ⇒ 生成失败，随后 `MessageBoxA(NULL,…)`（无 owner、非 TOPMOST）藏在游戏窗口后面 → 永久冻结 |
| `data/unsafedata/ds_luajit_boot.log` | 游戏根 | 只到 `shell(winmm): installed injector startup hook` ⇒ 卡在注入之后 |

要 phase 耗时：带调试器启动（`gum_process_is_detected_debugger` → debug 级）或 `log_level=info`。

## 为什么 0% 会「卡」这么久（结构原因）

- 发行包**不带** `signatures_*.json`（release zip 全是 `.pkg`；`Mod/.gitignore` 忽略 DB，CI 不生成）→ 首次启动必走 `create_signature`。
- `update_signatures` 是协程，但 phase1 `init_module_signature`、phase2 `nucleus_analyze_file`（lua51.dll + 20MB 主 exe）、phase3 `scan_module_function_features`、pdata 校验都在**第一个 `co_yield` 之前**，进度窗整段停在 0.0%。
- 该工作跑在游戏主线程（注入点是 `SetCurrentDirectoryW` 钩子），所以游戏加载一起被阻塞。

有界性测量（repo 的 RelWithDebInfo 工具，勿覆盖仓库 DB）：

```bash
SIGNATURE_TOOL_OUTPUT_DIR=<临时目录> signature_updater.exe create   # 无 DB
SIGNATURE_TOOL_OUTPUT_DIR=<临时目录> signature_updater.exe update   # 把 DB 的 version 改错，模拟游戏更新
```
759671 实测两者都是 12.3 s（client+server 两目标）→ 生成器不是死循环；机器慢/杀软扫描会放大到分钟级。

## 安装器语义

- **mod 目录**：存在但无 `modinfo.lua` → `target.foreign` 中止（磁盘零改动）；是自己 → 整目录 `Remove-Item -Recurse -Force` 后重建，**不合并、无回滚**；用户手放文件、运行时生成的 `signatures_*.json`、`update_pending/` 全部消失。PS 5.1 对该路径上的 junction 只删链接、不穿透删目标。
- **bin64**：只处理 `Winmm.dll`（`fc /b` 相同则跳过，否则 `copy /Y`）；不动其它文件；`install.ps1` 调 `cmd /c install.bat` **不检查 `$LASTEXITCODE`**。
- **`data/unsafedata`**：ps1 与 bat 都会整目录删，失败只 WARN；ps1 **先删再自检**，所以自检里任何 marker 内容比较都是死代码 —— marker 仍在只说明清理失败。
- **marker 解析优先级**：`DS_LUAJIT_INJECTOR`(文件) → `DS_LUAJIT_INJECTOR_DIR` → `ds_luajit_injector.path` → `<game>/mods` / UGC 别名扫描；前三者成功都会重写 marker。**marker 内容可能与刚装的目录不同**（环境变量可长期钉住另一棵树；测试 harness 就这么干），ps1 无法感知。marker 是只读一次就关句柄的局部 `ifstream`，不会长期占用。
- **`.pkg` 镜像**：`<名>.dll.pkg` 是耐久副本，规范名 `.dll` 是加载前按 PE 戳生成的派生物。`install.bat` 的清理只删「有孪生」的规范名 `.dll`，`bin64\` 整棵跳过；**没有孪生的 `.dll` 绝不能删**（源树/构建树布局里它是真身）。

## 修复方向（按「能删就删」排序）

1. 发行包直接带 `signatures_*.json`（根治首次启动生成）；
2. 把 phase 1–3 挪到进度窗之前，或先显示「分析模块…」；
3. 失败走日志 + 可见提示，别用隐形模态框；
4. `SignatureJson::update_signatures` 检查流状态并记 error。
