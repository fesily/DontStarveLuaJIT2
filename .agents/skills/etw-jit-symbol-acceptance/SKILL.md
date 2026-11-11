---
name: etw-jit-symbol-acceptance
description: "Accept LuaJIT JIT symbols in WPA/PerfView/ETL on Windows: this repo's opt-in build switch (LUAJIT_ENABLE_ETW), runtime switch (jit.profile.etw), the real-ETW test lane, capture/verify tooling, and the lock/consumer traps."
---

# When

DontStarveLuaJIT2 的 ETW JIT 符号功能：构建/验证、在 WPA/PerfView 里看到 `LuaJIT::TRACE_*`、或在游戏/测试进程实抓 ETL 做符号归因。非本仓库的通用 ETW 权限问题见 `windows-etw-nonadmin-authorize`。

# 1. 两个开关（都要开，缺一不可）

| 层 | 开关 | 默认 | 说明 |
|---|---|---|---|
构建 | `-DLUAJIT_ENABLE_ETW=ON`（CMake）/ `XCFLAGS+=-DLUAJIT_ENABLE_ETW`（Makefile）/ `set CL=/DLUAJIT_ENABLE_ETW`（msvcbuild.bat） | **关** | `LJ_HASETW` 需要 `LJ_TARGET_WINDOWS && LJ_HASJIT && defined(LUAJIT_ENABLE_ETW)`；旧宏 `LUAJIT_DISABLE_ETW` 已删除。开时 CMake 才会链 `advapi32`，amalgamation 才把 `WINVER` 抬到 0x0600 |
运行时 | Lua `require("jit.profile").etw(true)` | **关** | 进程级单例；`etw(true)` 顺带对该 VM 做等价 `jit.flush`（traces 全删，重新编译后才符号化）；`etw(false)` 立即上报 unload 并停发；`etw()` 查询。未编译时恒 `false` |

测试入口：`-DLUAJIT_TEST_ETW=ON` **且** `-DLUAJIT_ENABLE_ETW=ON` 才生成 `etw-symbols-{default,arenagc}` 与 ctest `luajit_{default,arenagc}_etw_symbols`（label `luajit_etw`，无采样权限返回 77 = SKIP）。

# 2. 构建/跑测试的坑

- CMake 缓存会被重置成 `LUAJIT_TEST_ETW=OFF` → 症状是 `ninja: error: unknown target 'etw-symbols-default'`。重新 `cmake --preset ninja-multi-vcpkg -ULUAJIT_DISABLE_ETW -DLUAJIT_ENABLE_ETW=ON -DLUAJIT_TEST_ETW=ON`。
- `LNK1168/LNK1201`（无法写 `lua51DS.dll`/`.pdb`）：有测试进程或 `mspdbsrv.exe` 占着。`taskkill /F /IM etw-symbols-default.exe`、`taskkill /F /IM mspdbsrv.exe`，必要时删 `lua51DS.pdb/.ilk` 再链接。
- 后台任务被 cancel **不会杀死它派生的 `cmd /c` 循环**：会不断复活测试进程继续占 DLL。用 PowerShell 按命令行匹配杀：
  `Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" | ? { $_.CommandLine -match 'etw-symbols' } | % { Stop-Process -Id $_.ProcessId -Force }`
- 被 `taskkill` 的测试进程跑不到 atexit → 留下 `LuaJIT-ETW-<pid>-…-<tag>` 会话：`logman query -ets | findstr LuaJIT-ETW` → `logman stop <name> -ets`。只停自己的名字，别用裸 `wpr -cancel`。
- 单场景：`etw-symbols-default.exe --only=<name>`（runtime-switch / collector-first / empty-cache / trace-first-idle / trace-first-running / keyword-matrix / two-sessions / capture-repeat / flush-reprewarm / single-flush-gc / two-vms-coroutine / concurrent-close / names-and-lines）。正常全套约 75 s/变体；某场景突然多 40 s ⇒ 查 `STOPPING` 自等待（见第 4 节）。

# 3. 实抓 ETL 与验收

- 一键：`python tests/performance/verify_jit_symbols.py --exe <etw-symbols exe> --out <dir>`（非管理员会自动经 `sudo --new-window` 起 WPR；`--no-elevate` 关掉）。输出 `capture order: attach (rundown=yes)` 或 `start-first (rundown=no)` + `JIT SYMBOL ACCEPTANCE: PASS/FAIL`；`summary.json` 里有 `event_counts / jit_ranges / samples_in_trace_range / resolved_trace_names / verdict`。
- 从启动抓：`--start-first --launch "<exe> <args>" --launch-seconds N`。
- 复算已有 ETL（不需要管理员）：`--etl <etl> --pid <pid>`。
- 游戏一轮：`python tests/performance/run.py --profile worldgen --worldgen-jit on --sample-native --warmup 0 --repeat 1 --vm luajit=builds/game-performance-vm-release/luajit/lua51DS.dll --injector builds/game-performance-runtime-release/src/DontStarveInjector/Release/Injector.dll --output <dir>`，**先** `python tests/performance/build_release.py` 重建 Release VM（否则那份 DLL 里没有 provider）。产物 `<dir>/round-0-<vm>-native.etl` + `-native-samples.json`（含 pid）。
- 消费端判据：ETL 的 `CPU Usage (Sampled)`（WPA，按 PID 过滤）符号列出现 `LuaJIT::TRACE_<n>::<chunk>:<line>`；只看到 Generic Events 不算过。chunk 是裸路径时（DST 引擎传 `scripts/xxx.lua`，无 `@`）会原样保留；源码文本/超长名折叠成 `(string)`。
- 诊断工具顺序：`xperf -i f.etl -a tracestats`（丢事件）→ `xperf -i f.etl -o out.csv -a dumper -stacktimeshifting`（CSV 里 manifest provider 已按字段名展开，比 `tracerpt` 的 850MB XML 便宜；注意 image 行叫 `ImageId`/`I-Start`，base 在 row[3]、size 在 row[4]）。
- 共享 GUID 陷阱：`Microsoft-JScript` 与机器上所有 Chakra 宿主共用；自发会话务必带 PID 过滤（`ENABLE_TRACE_PARAMETERS` + `EVENT_FILTER_DESCRIPTOR{Type=EVENT_FILTER_TYPE_PID}`），WPR profile 不能过滤 → 加大 EventCollector 缓冲（256KB×128）。

# 4. 锁纪律（改 lj_etw.c 时必须守住）

- `etw_cache_lock` **只**覆盖链表/标志更新；**所有 `EventWrite` 必须在锁外**。做法：记录/上下文引用计数（record = `T->etw_entry` 所有权 + 链表成员 + 写者；context = 链表成员 + 写者）+ `EtwBatch`（锁内借/交接引用，锁外写，`etw_batch_release` 统一 drop/释放）。
- 静态自检：扫描 `AcquireSRWLockExclusive(&etw_cache_lock)` 与对应 `Release` 之间不得出现 `etw_write_*`。
- worker 停止分两阶段：`stop_begin`（置 STOPPING + 请求 + 交回句柄）→ **锁外** `stop_join`（5 s 超时诊断后继续等，`EventUnregister` 要求线程已退）→ 锁内 `stop_finish`。
- 陷阱：join 之后**不要**用"等别人停完"的 `etw_lifecycle_acquire()`——此时 STOPPING 是自己设的，会等自己未触发的 `stop_done`（8×5 s = 40 s/次）。自己拥有的 stop 直接普通加锁。
- `etw(false)`/`etw(true)` 的批量写仍在 lifecycle 锁内（只影响 VM 创建/关闭延迟，不在 cache 热路径）；`etw_provider` 无锁读在 x64 上是原子的且 unregister 一定在 join 之后。

# 5. 语义速查

- 默认关：不开 `etw(true)` 就**一条事件都不发**；先跑后 attach 也只能拿到开启之后编译的 trace。
- `etw(true)` 是"转换时 flush"：已经开着再调用不 flush，但会补发此后新出现的 VM context。
- `etw(false)` 立即上报卸载；记录进 retired 链，由属主 VM 释放（别在别的线程 free/解引用外 VM 的 `GCtrace`）。
