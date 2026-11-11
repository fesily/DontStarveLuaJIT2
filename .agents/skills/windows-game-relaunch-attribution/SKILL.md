---
name: windows-game-relaunch-attribution
description: 当 DST/Steam 游戏“反复启动/自己重启”需要找出是谁拉起时用：Steam gameprocess_log 命令行+时间线、父进程链、omp 会话记录回溯；不用于游戏内崩溃分析。
---

# 谁拉起了游戏（Windows / Steam）

目标：把“游戏在反复启动”变成可证伪的事实——是崩溃循环、自动更新器，还是某个测试脚本反复 `Popen`。

## 1. 先取权威启动记录（不要从进程快照猜）

`C:\Program Files (x86)\Steam\logs\gameprocess_log.txt` 按行记录每次被跟踪进程的**完整命令行**，只要有 `steam_appid.txt` / steam_api 初始化，直接 `CreateProcess` 也会被记进来：

```bash
grep -an "dontstarve" "/c/Program Files (x86)/Steam/logs/gameprocess_log.txt" | tail -30
```

- 命令行里带 `-persistent_storage_root <Temp>\...`、`-force_enable_mods=...`、`-offline -debug_random_data` → 测试夹具启动，不是玩家点 Play。
- 交叉验证会话区间：`logs/content_log.txt` 的 `AppID 322330 state changed : ... App Running` / 无，给出存活时长；`no longer tracking PID x, exit code N` 给退出码（exit 1 常见于夹具断言失败而非崩溃）。
- 8 小时 Application 日志无 `dontstarve` 事件 ≈ 不是崩溃。

## 2. 定位启动者

```powershell
Get-CimInstance Win32_Process | ? { $_.Name -like '*dontstarve*' } |
  % { $p=$_; $par=Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)"; "$($p.ProcessId) <- $($par.Name) $($par.CommandLine)" }
```

- `$_` 在 bash → powershell 里会被吞：把脚本写到临时 `.ps1`（`-ExecutionPolicy Bypass -File`）而不是内联 `-Command`。
- 无 Security 4688 审计、非管理员时拿不到进程创建历史 → 上面的日志+会话记录是唯一可行路径。

## 3. 回溯到具体 agent/工具

本机 `omp` 会话记录是取证金矿：

```bash
cd ~/.omp/agent/sessions/-DontStarveLuaJIT2 && ls -lt --time-style=+%m-%d_%H:%M *.jsonl | head
grep -c "ds_client_ws_\|ds_client_disc_" <candidate>.jsonl
```

含大量 `ds_client_*` 的会话即启动者；读它尾部 `thinking` 往往直接列出它创建的丢弃脚本（`build/tmp_client_*.py`）与清理计划。首行 `type:title` 标明会话主题。

## 4. 排除“自启动”假说（按证据，不按源码直觉）

- 部署产物查字符串：`grep -a "Wait-Process\|rungameid\|start dontstarve" Mod/Injector.dll Mod/plugins/... Mod/bin64/windows/Winmm.dll`
- 源码要知道宏边界：`grep -n "#if\|#endif" util/updater.cpp` —— 自动重启体常整块在 `#if 0` 内且**无调用点**，别看到 `installer()` 就断言。
- `Mod/install.bat` 只 `taskkill`，不 `start` 游戏。
- `%Winmm.dll` 双方 md5 相同 ⇒ 更新器 `need_updater()` 不会触发重启。

## 5. 收尾

结论要能复述为时间线表格（时刻 / 命令行特征 / 存活 / 退出码），并确认当前无残留进程、无残留脚本、无计划任务。
