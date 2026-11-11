---
name: windows-etw-nonadmin-authorize
description: Windows 上让非提权 agent/工具跑 ETW（含内核/系统采样）而不每次弹 UAC：分类工具档位、一次性授权、高权限端点包装、共享 provider GUID 的 PID 过滤、会话残留清理，以及包装脚本的编码坑。
---

# 目的

非提权进程要跑 ETW（尤其"采样工具"）时，判定真需要什么权限并一次性铺好，之后不再弹 UAC；附写入/包装这类工具脚本时的本机编码坑。

## 1. 先分类，别急着提权

- 用户态 provider（TCPIP / DNS-Client / CLR …）：`Performance Log Users` 组即足够，无需提权，也无需改 UAC。
- **自建 real-time session 不需要提权**：进程自己 `StartTraceW`(`LogFileMode=EVENT_TRACE_REAL_TIME_MODE`) + `EnableTraceEx2` + `OpenTraceW`/`ProcessTrace` 实测在非提权 shell 可用（事件能收到）。要采样 CPU 才需要下面的内核档权限。
- 内核/系统档：`Microsoft-Windows-Kernel-*`、`SystemTraceControlGuid {9E814AAD-3204-11D2-9A82-006008A86939}`、`LogFileMode` 含 `EVENT_TRACE_SYSTEM_LOGGER_MODE (0x1000)`、PROFILE/CSWITCH/STACKWALK 关键字 → 需要 ACL + `SeSystemProfilePrivilege`。
- NT Kernel Logger、`EVENT_TRACE_PRIVATE_LOGGER_MODE`、autologger → 只有 Administrators/SYSTEM，无法用组/ACL 授权。

判别实测（不要只读代码）：

```powershell
cmd /c "set __COMPAT_LAYER=RunAsInvoker && <tool> ..."   # 若只是 manifest 无脑要 admin，这一步就够了
logman start probe -p Microsoft-Windows-TCPIP   -o t.etl -ets ; $LASTEXITCODE   # 用户态基线，应 0
logman start probe -p Microsoft-Windows-Kernel-Process -o t.etl -ets ; $LASTEXITCODE   # 内核档，未授权应 0x80070005
```

`logman start` 可能"报拒绝访问但会话已建"（会话建了、启用 provider 失败）→ 一定要 `logman query <name> -ets` 复核，别只看 rc。

**WPR 是另一档**：`wpr -start <profile>!<ProfileName> -filemode` 走 System 档策略，非提权必失败，签名固定为 rc `3310899217`（`0xC5585011`）+ stderr `Failed to enable the policy to profile system performance`。看到这个就不要再试参数，直接走第 3 节。

## 2. 一次性授权（需提权的 PowerShell，跑一次）

三件事缺一不可：

1. 组：`Add-LocalGroupMember -SID S-1-5-32-559 -Member <acct>`（用 SID，避免本地化组名）。用户态档到此为止。
2. ETW 对象 ACE：`EventAccessControl(Guid, op=2/*EventSecurityAddDACL*/, Sid, Rights, byte allow)`（advapi32）。
   - 权限位来自 `wmistr.h`：WMIGUID_QUERY 0x1、TRACELOG_CREATE_REALTIME 0x20、TRACELOG_CREATE_ONDISK 0x40、TRACELOG_GUID_ENABLE 0x80、**TRACELOG_ACCESS_KERNEL_LOGGER 0x100**、TRACELOG_LOG_EVENT 0x200、TRACELOG_ACCESS_REALTIME 0x400、TRACELOG_REGISTER_GUIDS 0x800。
   - session GUID 给 0x1|0x20|0x40|0x400|0x100；provider GUID（含 SystemTraceProvider）给 0x80|0x100。
   - `BOOLEAN` 形参是 **1 字节**，用 `[byte]1`，用 `bool` 会当 4 字节 BOOL 传错。
   - 立即生效，无需重新登录。
3. 特权：`SeSystemProfilePrivilege`（单进程采样再加 `SeProfileSingleProcessPrivilege`），用 `LsaOpenPolicy(0x800 /*POLICY_LOOKUP_NAMES*/)` + `LsaAddAccountRights`。
   - **LSA 返回 NTSTATUS，不是 Win32**：必须 `LsaNtStatusToWinError` 再显示，否则 `0xC0000022` 会让 `[int]` 转型崩。
   - 必须授给**标准（非管理员）账号**：管理员登录后的过滤令牌把行政特权整个剥掉（`whoami /priv` 只剩 SeShutdown/SeChangeNotify/SeUndock/SeIncreaseWorkingSet/SeTimeZone），授了也拿不到。
   - 组/特权要**重新登录**才进令牌；仅重启进程不够。

参考：MS Learn `EventAccessControl`、`Configuring and Starting a SystemTraceProvider Session`（明确写 "grant the user profile privilege and then add this user to both the session GUID and the system trace provider GUID"）、geoffchappell ETW Security 的默认 ACE 表。

## 3. 工具自身提权门禁时（ACL 授权无效）

- 短期：一次性提权注册 `schtasks /Create /TN X /TR "..." /SC ONCE /ST 00:00 /RL HIGHEST /RU %USERNAME% /F`，agent 侧 `schtasks /Run /TN X`（无需提权）。参数固定，动态参数走参数文件/管道；这是"计划任务提权"模式，EDR 可能告警。
- 长期：采样器做成 LocalSystem 常驻服务 + 命名管道 IPC，agent 保持非提权。
- 整体提权：子进程继承父令牌 → agent 以 `/RL HIGHEST` 任务或服务启动即可。
- Windows 11 自带 `sudo.exe`（1.0.x）也可用：`sudo --new-window --chdir <dir> <exe> <args...>`。新窗口不能回传 stdout，所以让被调工具自己写 receipt/结果文件（例如仓库的 `etw_control.py --receipt`），agent 侧有限轮询该文件拿 returncode——比解析窗口输出可靠。
- 脚本侧建议：默认“非管理员就自动走 sudo”，开头打印 `[info] admin=… sudo=…` 让人一眼看出走了哪条路；`--no-elevate` 之类开关保留 opt-out，避免在管理员终端里重复弹 UAC。
- 不要用关 UAC（`EnableLUA=0`）来"解决"。

## 4. 共享 provider GUID：会被别的进程灌爆，必须按 PID 过滤

有些 GUID 是所有宿主共用的，例如 **Microsoft-JScript `57277741-3638-4a4b-bdba-0ac6e45da56c`**（Windows/Chakra JIT 符号协议，Edge/WebView2 等 Chakra 宿主都用）。session 一按 GUID 启用，别的进程的事件也全进来：实测一次 16 s 录制里某 Chakra 进程刷出 4800+ MethodLoad，自己的 ~10 条事件被挤掉、consumer 收不到（`EventsLost` 上万）。

解法：启用时给 session 加 PID 过滤。`EnableTraceEx2` 最后一个参数是 **`PENABLE_TRACE_PARAMETERS`**，不是 `PEVENT_FILTER_DESCRIPTOR`：

```c
EVENT_FILTER_DESCRIPTOR fd = { (ULONGLONG)(ULONG_PTR)&pid, (ULONG)sizeof(pid), EVENT_FILTER_TYPE_PID };
ENABLE_TRACE_PARAMETERS p = {0};
p.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
p.EnableFilterDesc = &fd;
p.FilterDescCount = 1;
EnableTraceEx2(session, &providerGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, keywords, 0, 0, &p);
```

WPR profile 不能表达 PID 过滤，只能把 `<EventCollector>` 的 `BufferSize`/`Buffers` 调大（实测 64KB×32 → 256KB×128 足够），并提醒使用者按进程过滤视图。

## 5. 会话残留与诊断

- 进程异常/崩溃退出（atexit 没跑）会留下**启用中的会话**，其 consumer 已死 → 缓冲堆积、后续 run 丢事件、行为诡异。自建会话的工具必须在所有退出路径清理（`atexit`），且只按自己的会话名/handle stop，**不要**用裸 `wpr -cancel`（会停掉别人的录制）。
- 排查顺序：
  - `logman query -ets | findstr /i <prefix>` 找残留会话，`logman stop <name> -ets` 逐个停（别人在用的别动）。
  - `xperf -i f.etl -a tracestats` 看丢事件/缓冲（"Lost":0 才是好结果）。
  - `xperf -i f.etl -o out.csv -a dumper -stacktimeshifting`：CSV 里 manifest provider 已被按**字段名**展开（一行一个事件 + 表头行），比 `tracerpt -of XML` 便宜得多（后者在系统档录制上能到 850MB）。
  - `tracerpt f.etl -o f.xml -of XML -y`：用 OS 里已注册的 manifest 解码，适合核对 payload 字段名/顺序/长度；注意 `<Provider Guid="{...}">` **带花括号**，比较 GUID 时要 strip。

## 本机坑 A：写 .ps1 必须 ASCII 或带 BOM

Windows PowerShell 5.1 在 zh-CN 上按 ANSI(GBK) 解码 .ps1；UTF-8 无 BOM 的中文注释会错位吞掉引号，报 `表达式或语句中包含意外的标记`。一次性管理脚本写成纯 ASCII，或加 BOM。

## 本机坑 B：Python 包装 Windows CLI 必须显式指定编码

zh-CN 上 `subprocess.run(cmd, capture_output=True, text=True)` 不写 `encoding` 会用 locale（cp936/GBK）解子进程输出：

- 子进程吐非 GBK 字节 → `UnicodeDecodeError: 'gbk' codec can't decode byte 0x…`；
- 捕获后又 `print`（尤其经 `errors="replace"` 得到 U+FFFD，或工具的中文输出）→ `UnicodeEncodeError: 'gbk' codec can't encode character '\ufffd'`。

三件套修掉：

```python
TEXT_IO = {"text": True, "encoding": "utf-8", "errors": "replace"}
for s in (sys.stdout, sys.stderr):
    try: s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError): pass
# 失败路径只打印 ascii(一行摘要)，不要 dump 子进程原始输出
```

先排除“文件本身编码”这个伪因：`python -c "d=open(p,'rb').read(); print(sum(1 for b in d if b>127))"`，为 0 就是纯 ASCII，问题必然在上面这段 IO 上。注意这类报错常与“未提权导致 WPR 失败”同时出现（失败路径正好是打印 tool 输出的地方），修编码的同时把失败原因说清楚。
