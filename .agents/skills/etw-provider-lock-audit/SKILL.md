---
name: etw-provider-lock-audit
description: 量化 ETW provider 内部锁竞争(EventWrite 是否在锁内、批量持锁时长)并据此选分片/引用计数修法;含 logman 会话与计时配方。
---

# 目的

审查/量化一个 Windows ETW provider（自身代码里 `EventRegister` + `EventWrite` 的实现）的**锁竞争与锁持有时间**，判断“全局锁 × ETW 写入”是否会把宿主进程的其它线程卡住。

# 1. 先画锁范围（不要靠猜）

用脚本或肉眼逐个函数确认：

- 哪把锁保护哪些状态（通常：生命周期锁 = 注册/注销/发布切换；缓存锁 = 记录链表/代际）。
- **每次 `EventWrite` 是在锁内还是锁外**——这是核心；`EventWrite` 是用户态拷贝但**会话缓冲满时会被反压**，在锁内就等于不可控停顿。
- 批量操作（rundown / 批量卸载 / 批量发布）是否一次持锁写完整个集合（持锁 ∝ 记录数）。
- 有没有在锁内 `WaitForSingleObject(thread, INFINITE)` 之类的**无界等待**。
- 锁顺序是否固定（拿到 `A→B` 就别出现 `B→A`）；enable callback 最好完全不取锁，只置位 + `SetEvent`。

快速摸底（正则扫函数体，看锁调用与 `EventWrite` 是否同函数/同作用域）：把每个函数体切出来，统计 `SRWLock/Mutex` 与 `EventWrite*/EventWriteTransfer` 出现位置即可列出嫌疑表。

# 2. 用真实会话量化“锁持有时间”

关键：**必须有至少一个会话订阅该 provider**，否则 `EventEnabled` 为假、写入被跳过，测出来的是纯链表成本（会低估一个数量级）。

非提权也能建**文件模式**会话（provider 是用户态的）：

```cmd
logman create trace LJC -p "{GUID}" 0x3 4 -nb 64 256 -o C:\abs\out.etl -ets
:: ...被测进程...
logman stop LJC -ets
xperf -i out.etl -a tracestats      :: Lost 应为 0
```

坑：本机 `logman` 的 `-b <KB>` 会报“参数错误”，只用 `-nb <min> <max>` 指定缓冲数量即可；`-o` 要给绝对路径。

测量套路（宿主进程内，Lua/C 均可）：

1. **每记录/每事件的写入成本** = 同一批量操作在“有会话”与“无会话”下的时间差 ÷ 事件数。
2. **每次提交的锁持有时长** = 编译器/业务循环里每个提交点的 `(有会话 - 无会话)` 差值。
3. **单次批量锁持有** = 直接对 `disable/rundown` 之类的公开入口计时；它等于“其它线程最坏被卡多久”。
4. 放大到可测规模：把记录数拉到 1e4–6e5（trace 类实现要同时抬高上限，如 LuaJIT `maxtrace`），并让 `os.clock()`（1 ms 分辨率，足够测 ≥1 ms 的批量）或 QPC 计时。
5. 重复 3 次取最小值；先跑一遍预热（首次含惰性加载）。

经验数量级（2026-10，8 核桌面，文件会话）：`EventWrite` ≈100 ns/事件；一次“链表 + 2 次写”的提交 ≈2 µs；30k 记录的批量卸载 ≈6 ms（每记录 2 事件）/ 完整 rundown ≈12 ms（每记录 4 事件）；**无会话**时锁内只有链表+`EventEnabled` ≈15–20 ns/记录。

# 3. 判读与修法

| 现象 | 结论/修法 |
|---|---|
| 默认关闭或没人订阅 | 基本无竞争（锁内纳秒级），不必改 |
| 每次提交在锁内写 1–2 事件 | 正常路径 ≈2 µs/条；只有缓冲反压时才会放大 → 先分片再考虑移出锁 |
| 批量操作一次持锁写完 | **按固定条数分片**（如 256 条/片，片间 `SwitchToThread()`），单次持锁上界可算 |
| 想彻底移出锁 | 记录加**引用计数**：锁内入链/摘链 + refs++，锁外 `EventWrite`，回锁 refs--/释放；注意并发 disable 与 publish 会让同一记录的 load/unload 次序颠倒，需要 per-record pending 标志或接受偶发乱序 |
| 锁内无限等待线程退出 | 改成两阶段：置 stop+SetEvent → **释放锁** → join → 重取锁注销；至少加超时+诊断 |
| 关闭状态下也取生命周期锁 | 只在真正启停时取；把 `EventEnabled` 结果在锁外算好传入 |
| 无锁读取注册句柄 | x64 对齐 8 字节读原子，但形式上是 data race：加注释/原子读 |

# 4. 常见误判

- `os.clock()` 在 Windows 是 1 ms 分辨率：< 1 ms 的操作会显示 `0.0`，别据此断言“零成本”，先放大规模。
- 会话没建成功（`logman` 参数错、GUID 拼错、provider 未注册）时，两次测量会几乎相同，看起来像“写入免费” —— 先 `logman query -ets | findstr <name>` 确认，并在结束后用 `tracestats` 看 ETL 是否真有事件。
- 实时会话（`EVENT_TRACE_REAL_TIME_MODE`）比文件会话更容易反压；压测锁竞争时用文件会话，验证消费者时用实时会话。
