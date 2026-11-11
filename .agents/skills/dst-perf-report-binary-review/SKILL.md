---
name: dst-perf-report-binary-review
description: "Use when reviewing a third-party DST performance/lag report (addresses, percentages, call chains) against the symbolful Android libDontStarve.so via Ghidra MCP; not for running new profiles."
---

# 用符号二进制复核 DST“性能瓶颈报告”

## 何时用
第三方（Steam 讨论区、模组作者）给出 DST 性能报告，含函数地址、占比、调用链结论，需要判断可信度。
不适用于：自己跑 profiling、性能复现实验。

## 0. 先判地址属于哪个构建
- 汇编出现 `r*` / `xmm` / `_memcmp` → x86-64；报告若说 Linux，则是 Linux dedi。
- Windows client/dedi 镜像仅 ~7.9MB，`0x80xxxx` 级地址必然超出；Android `.so` base 0x100000、AArch64 布局也不同。
- 结论：**地址不可逐条复核**；改为核对“机制 + 调用结构”，并在输出里明确这一局限。

## 1. 工具路径（Ghidra MCP）
```
switch_program libDontStarve.so
list_class_members class_name=cSimulation|cEntityManager|cNetworkReplicaManager|cNetworkComponent|cEntity
decompile_function address=...
search_functions name_pattern=CheckSleepers|Dirty|ThreadPhysics
list_globals name_substring=gUseThreadedPhysics
search_strings search_term=LuaJIT|mspt
get_xrefs_to / get_function_callers
```
注意：`search_functions` 用普通子串（`.*x.*` 常匹配不到）；`list_globals` 的过滤参数是 `name_substring`；`search_instructions` 的 operand 过滤不可靠。

## 2. 必须核对的锚点（Android 1.1.28）
| 报告常见说法 | 真实锚点 |
|---|---|
| Simulation::Update | `cSimulation::Update` 0x889604：Lua Update→WallUpdate→DoUpdate/EntityManager::Update/PostUpdate 或 SimUpdate→IncrementalGarbageCollect→物理线程 |
| Lua 总入口 | `CallLuaFunction`，引擎用 Timer 计时；区间含 Lua 调用的 C++ API |
| CheckSleepers“扫全图” | 0x86a6c0，`cSpatialHash::ApplyPred<sNetworkSleepCheckPred>` 玩家附近查询（64/76.8/4.01） |
| 物理更新循环 | `cEntityManager::Update` 0x86baa4 是组件虚函数循环；物理本体 `cBPWorld::Update` |
| ReplicaManager O(玩家×实体) | `Update`→`Tick` 0x97e2c0：连接×每连接 replica 数组，lastSerialized 去重 + AutoSerializePerTicks |
| 脏位 memcmp | `cEntity::SerializeLuaState` 0x865a14 用显式脏位；未变通道不写。非 memcmp 快照 |
| GC <0.5% | 每帧一次 `lua_gc(L,5)`；`DoGarbageCollection` ≤1ms（elapsed<0.001）；应急全量 ≈420MiB |
| 无多线程 | 有 `PhysicsUpdateThread` JobThread，开关 `gUseThreadedPhysics`（Android 构建只读不写） |

## 3. 输出格式
表格：`报告说法 | 二进制核对 | 判定(✅/⚠️/❌/❓)`，然后“对结论的影响”。
判定纪律：
- 占比、CPU% 一律 ❓（采样无法证伪）；
- inclusive 区间不得当“Lua vs C++”分账证据；
- 地址在函数中间、名字缺 `c` 前缀、`Update` 是跳板 → 精度不足。

## 4. 常见误判
- 把 mspt(10ms) 与 top(80%) 当矛盾：33.3ms 周期内 10+17ms 恰好 ~80% 单核，不矛盾。
- 把“远处休眠实体清理无效”当反例：休眠实体本就不在 awake 更新向量、网络也被 sleeping flag 挡掉——方向正确。
- LuaJIT mcode 归因：JIT 打开时热 Lua 在匿名 mcode，采不到就不会出现在“Lua 区间”。
