---
name: dst-firstboot-signature-stall-triage
description: DST 首次启动/安装后进度条卡住或静默退出：先开 log_level 取证据，再判定特征码生成器（无 DB、0% 卡点、峰值内存、隐形 MessageBox、退出码）
---

# 首次启动“加载进度条卡住”归因：特征码生成器

## 适用
用户反馈“跑完 install.ps1 后游戏加载进度条卡住不动”“是不是特征码生成器卡住了”。已符号化的 DST mod（DontStarveLuaJIT2）安装/启动阶段，不是 mod Lua 逻辑 bug。

## 先开日志再说别的（2026-10-27 起）
发行包 release 默认只写 `err`，所以任何“日志什么都没有”的反馈先要给用户开级别：

| 开关 | 位置 | 说明 |
|---|---|---|
| `log_level=<level>` | env 或启动参数 `-log_level=info` / `--log_level info` | `InjectorConfig::log_level`；trace/debug/info/warn/err/critical/off（+`warning`/`error` 别名）；显式值优先于默认(err)/Debug(trace)/挂调试器(debug)；`spdlog::set_level` 会同时放开 `FunctionRelocation.log` |
| `disable_progress=1` | env 或 `-disable_progress` | 跳过进度窗，生成内联跑 |

- 日志文件：`<游戏>/bin64/DontStarveInjector_client.log`（default logger，注入器+所有插件共用 `deps/spdlog.dll` 的 registry）；`<游戏>/bin64/FunctionRelocation.log`（signature 扫描明细，rotating）；`<游戏>/data/unsafedata/ds_luajit_boot.log`（壳引导，每次覆盖）。
- **必须当次运行后立刻看、别再启动一次**：sink 在 2026-10-27 之前是 truncate，每次启动清空文件；现在已改为追加。
- 想看失败原因：`log_level=debug` 复现一次，然后 `findstr /C:"fatal:" <日志>`；退出码 `1`=我们 `exit(1)`，`0xC0000409`=abort/terminate，`0xC00000FD`=栈溢出，`0xC0000005`=AV。

## 结论模板（先给，再给证据）
发行包不带 `signatures_*.json` ⇒ **首次启动必须全量生成一遍**，生成在游戏主线程同步跑，且全部分析阶段在第一次 `co_yield` 之前 ⇒ 进度条长时间 0% 不动。生成器本身有界（本机 11-12 s / 目标，峰值工作集 ≈954 MB），不是死循环。

## 归因链条（逐一可验证）
1. 发行包是否带 DB：下载对应 release 的 `windows_Mod.zip` 列出条目；`CMakeLists.txt` 只在源树存在时 install，`Mod/.gitignore` 忽略它们，`release.yaml` 不生成 → 干净安装必然无 DB。
2. 无 DB 走哪条路：`SignatureUpdater::create_or_update` → `create_signature` → `update_signatures_from_disasm`；client 侧按 `disable_progress` 决定是否开进度窗。
3. 为什么停在 0%：协程体 phase1 `init_module_signature`、phase2 `nucleus_analyze_file(lua51.dll / 20MB 主 exe)`、phase3 `scan_module_function_features`、pdata 交叉校验都在第一次 `set_progress` 之前执行，窗口收不到重绘。
4. 谁被阻塞：注入由 `SetCurrentDirectoryW` 钩子触发 → 游戏自己的加载条一起冻结。

## 变种症状：进度窗消失 + 进程退出 + 无 dump
旧版（2026-10-27 前）两条静默路径：`update_signatures_exception` → `showError`（Windows 分支只 `MessageBoxA(NULL,…,0)` 藏在游戏窗口后 + `std::exit(1)`，**不写日志**）；非该类型异常穿过进度窗 `WM_TIMER` → `std::terminate`/`abort`。所以“无 dump”≠崩溃。现在（`7ed926b9`）showError 先落 `fatal:` 再 TOPMOST 弹框，`update_signatures_from_disasm` 也 catch `std::exception`/`...`。

## 测时长（关键证据，勿覆盖仓库 DB）
```bash
SIGNATURE_TOOL_OUTPUT_DIR=<临时目录> \
  builds/ninja-multi-vcpkg/tools/Creater/RelWithDebInfo/signature_updater.exe create
python tests/signatures/run.py <tool.exe> [--check-cache]   # 正式闸门
```
- 用 RelWithDebInfo/Debug 目录（Release 目录缺 fmt/spdlog/pe-parse 运行库 → 0xC0000135）。
- 本机基线：client+server 各 104 条、~11-12 s、峰值 ≈954 MB、rc=0。

## 现场判定（按序）
1. `<mod>/signatures_client.json` 是否存在、mtime 是否本次启动 → 不存在/未更新 = 生在内存没落盘。
2. `bin64/DontStarveInjector_client.log`：新版看 `fatal: …`；旧版只有 `unresolved Lua functions` / `cannot generate signatures unique from Lua base` ⇒ 生成失败 → 隐形 MessageBox。
3. `data/unsafedata/ds_luajit_boot.log` 停在 `shell(winmm): installed injector startup hook`、屏幕上有无 `patch process...` 窗口。
4. 进程退出码（见上）。

## 真·永久卡死来源
- `MessageBoxA(NULL, …, 0)` 失败路径（已改 TOPMOST + 先写日志）。
- `SignatureJson.cpp` 的 `std::ofstream` 无错误检查 → 目录不可写则每次启动重生成（已加流状态检查 + error 日志）。
- `Progress.cpp` 的 `PostMessage(progress_ctx.hwnd, WM_CLOSE, …)` 的 `hwnd` 从未赋值，收窗靠 20 ms 定时器兜底 —— **不要顺手赋值**，否则 100% 时会提前关窗、跳过最后一次 co_yield 之后的校验，产生静默半成品 DB。
- 用户手点 X 关进度窗仍会被当作“成功”返回空串（既有风险，未修）。

## 修复取向（须由用户裁决）
1. 发行包直接带 `signatures_*.json`（根治首次生成）。
2. phase1-3 前先显示“分析模块…”（已做：set_progress + UpdateWindow）。
3. 失败改 boot log + 带 owner/TOPMOST 提示，不阻塞主线程（已做）。
4. `update_signatures` 检查流状态并记 error（已做）。
