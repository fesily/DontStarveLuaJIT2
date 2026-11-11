---
name: wpa-etw-capture-with-custom-wprp
description: 用 WPA/WPRUI 加载自定义 .wprp 做 ETW 采集并在 UI 看报表：先录后启动(capture-from-launch)与 attach 的区别、如何从事件集合判定顺序、以及对应的自动化等价命令。
---

# 何时用

需要"实时抓取 + UI 看报表"(CPU 采样/栈/JIT 符号),或者要区分"录制先启动进程"与"attach 到已运行进程"两种采集顺序时。

WPA/WPRUI 的录制是**全系统、按 profile**的,不存在"必须先有目标进程"的限制;报表(WPA 的 CPU Usage (Sampled) 等表)只能在**停止录制之后**对文件分析 —— ETW 没有官方 UI 边录边出报表。

# 1. UI 采集（管理员；非管理员 `wpr -start` 会失败 `0xc5585011`）

WPT 路径一般 `C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\`(`wpa.exe` / `WPRUI.exe` / `wpr.exe` / `xperf.exe`)。

- **WPA 自录**：管理员启动 `wpa.exe` → 录制区 **Add profile…** 选目标 `.wprp` → 在 profile 列表里选它（注意是 profile 的 `Name`，CLI 用的是 `Id`，形如 `<Id>!<Name>`）→ **Start Recording** →（需要"从启动抓"就在此时才拉起目标进程；否则可先跑负载）→ 跑够（1 ms 采样，≥10 s 才有上万样本）→ **Stop Recording** → 报表自动出现。
- **WPRUI**：管理员 `WPRUI.exe` → More options → **Add Profiles…** → 选 `.wprp` → 勾 profile → **Start** → 拉目标 → **Stop**（存 ETL，或点 Analyze 直接进 WPA）。
- 想"一个动作采+拉"：PerfView Collect → **Run**，`Additional Providers` 填 `<providerGUID>:<keywords>:<level>`。
- 抓完后想离线复算/写进 CI：`wpa.exe <etl>` 看报表；命令行用 `xperf -i <etl> -a tracestats`（丢事件必须为 0）、`xperf -i <etl> -o out.csv -a dumper -stacktimeshifting`（CSV 里 manifest provider 已按字段名展开）、`tracerpt <etl> -of XML`（核对 payload 字段/顺序）。

# 2. 抓取顺序：先从事件集合判定，再下结论

若 provider 同时订阅了 runtime 与 start rundown 关键字（例如 `0x3` = `0x1|0x2`），两种顺序都不丢数据，但事件集合不同：

| 顺序 | 事件特征 |
|---|---|
| **capture-from-launch**（先录后启动） | 注册时一次空 cache 快照（init/complete+context，如 1/7/2/+11），启动期每个 trace 都是**运行时** load；**没有** rundown 段（如 5 MethodDCStart / 39 SourceDCStart） |
| **attach**（先启动后录） | 多一段 rundown 回放（MethodDCStart / SourceDCStart）覆盖录制前已存在的符号 |

在 WPA 的 `Generic Events` 里看有没有 `MethodDCStart` 段即可判定；自动化脚本应把该判定写成断言（attach 要求有 rundown，start-first 要求没有），否则 PASS 判据会误报。

# 3. 自动化等价（可重复、不需要点 UI）

- 只抓不判：管理员终端 `python tests/performance/etw_control.py start --session DsPerf-<32位hex> --etl <abs> --receipt <abs>` → 拉目标 → `… stop …`（会话名必须任务唯一；只 stop 自己那个会话，别用裸 `wpr -cancel`）。
- 抓+判：目标仓库若已有类似 `verify_jit_symbols.py` 的脚本，用它的模式：默认 attach（先起负载、预热后打印 READY 再开始录）、`--start-first --launch "<cmdline>" --launch-seconds N` 先录后启动、`--etl … --pid …` 只做离线复算（不弹 UAC）。判据 = 目标 PID 的 CPU 样本 PC 落在 `[MethodStartAddress, +MethodSize)` 的比例 + 丢事件为 0 + 顺序断言。

# 4. 本仓库相关取值（示例，换项目要替换）

- profile：`tests/performance/cpu.wprp`，profile `Name=DsPerfCPU`（Id `DsPerfCPU.Verbose.File`）；provider `LuaJITJScript`=`57277741-3638-4a4b-bdba-0ac6e45da56c`，keyword `0x3`，`Level=4`。
- 脚本：`tests/performance/verify_jit_symbols.py`；先录后启动示例 `--start-first --launch "builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/luajit.exe builds/_ui_work.lua 8"`。
- 该 GUID 与全机 Chakra 宿主共用：视图里按 `Process` 过滤；不加 PID 过滤的会话实测能丢上万条事件。

# 本机坑

- 该 provider GUID 共享、WPR 需管理员、残留会话要按名字 stop —— 细节见 skill `windows-etw-nonadmin-authorize`。
- 脚本里所有 `subprocess` 捕获必须显式 `encoding="utf-8", errors="replace"`，并 `sys.stdout.reconfigure(...)`，否则中文 Windows(GBK) 上解码/打印会抛 `UnicodeDecodeError`/`UnicodeEncodeError`。
- `--launch` 这类命令行参数在 bash 里含 `\` 会被当转义符（`builds\_jitcap\x` → `builds/_jitcapx`）；在 Windows 侧用 `\` 路径时要么加引号，要么统一用 `/`。
