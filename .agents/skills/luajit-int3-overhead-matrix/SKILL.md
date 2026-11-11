---
name: luajit-int3-overhead-matrix
description: LuaJIT int3 开销全矩阵基准（无会话/门控/绕过门控/已编译/每次命中/FORL 槽）：相位设计、死槽隔离、best-of-N 稳定性与 MinGW 陷阱
---

# 适用

量 LuaJIT int3 断点机制在不同组合下的开销：无会话、会话 arm 但不命中、hook 每指令、已编译热循环、每次迭代命中、以及放开后的循环/返回槽。用于回归对比或回答“这层查表/门控/挂载花了多少”。

# 前提

- **release 构建**：`XCFLAGS="-DLUAJIT_ENABLE_GC64"`（**不要** `LUA_USE_ASSERT`，断言会污染测量，尤其 `trace_start`/`commit` 路径上的 `lj_int3_pending` 断言）。
- 单独写一个 bench 程序，通过 DLL 链接 `libluajit-5.1.dll.a`；只调公开 API（harness/bench 都拿不到内部符号）。
- 计时用 `clock_gettime(CLOCK_MONOTONIC)`，每档跑 N 次取**最小值**：同一二进制在 MinGW 上会有 ±60% 的抖动，单次结果不可信。
- `make clean` 后重建：混配置（前一次 `DISABLE_PROFILE`）留下的 `lua51.dll` 会让链接报 `undefined reference to luaJIT_profile_start`。

# 相位设计（每档都要有对照）

| 相位 | 目的 | 做法 |
|---|---|---|
| A 无会话 / 会话 arm 32 个死槽 | 无 hook 的解释器路径是否被污染 | 期望两者相同（该路径根本不调 `lj_dispatch_topslot`） |
| B hook 每指令（`lua_sethook(count=1)`）+ 32 死槽 | 门控是否生效 | 与“门控绕过 + 0 槽”对照；门控生效应 ≤ 0 槽 |
| B' 门控绕过 | 隔离查表本身的成本 | `jit.off(hot)` 让运行原型带 `PROTO_NOJIT`，`disp_ins` 只能查表；1 槽 vs 32 槽给出 per-slot 成本 |
| C 已编译热循环（JIT on，无 hook）/ 会话 arm 死槽 | mcode 与选择性 flush | 吞吐应不变，且 `trace` 的 `start` 事件仍为 0（arm 别的原型不该丢它的 trace） |
| D 每次迭代命中 | 单次命中成本 | 在循环体槽（如 `ADDVV`）arm 1 个；再 +31 个死槽测“命中路径里的查表” |
| E 循环/返回槽 | 放开后是否变贵 | arm `FORL`（或 `RET1`）与 `ADDVV` 对比；预期几乎相同 |

关键手法：**死槽**（一个从不被调用的函数里 arm 一批槽）用来只测扫描、不测回调；`jit.off(f)` 用来故意让门控失效；`arm` 之后检查 `funcbc` 确认槽里是原始 opcode（挂载会先 flush，把 `JFORL`/`JLOOP` 还原）。

# 参考数值（2daacff6，2M 迭代×4 bytecode，5 次最优）

- A：1.1–1.2 ns/bytecode，会话不加价。
- B：门控生效 17.5 ns/指令（32 槽）≤ 0 槽绕过 19.1；绕过时 1 槽 20.6、32 槽 27.0（≈0.25 ns/槽/指令）。
- C：0.30 ns/迭代，会话无关。
- D：1 次命中/迭代 8.9 ns/命中（≈112M/s），+31 死槽 13.3 ns/命中。
- E：`FORL` 9.0 ns/命中 vs `ADDVV` 8.9，差别在噪声内。

# 陷阱

- `lua_getglobal(L, "G.f")` 不会按点路径查找 → 拿到 nil → `funcinfo` 报 “function expected, got nil”；先 `getglobal("G")` 再 `getfield("f")`。
- bench 里用 Lua 找 bcpos 时把**完整路径**传给 `funcinfo/funcbc`（`G.tl`，不是 `tl`）。
- `best()` 若重复执行同一 chunk，命中计数要按 reps 折算（`hits/reps`），否则 ns/hit 会差 reps 倍。
- 不要把 bench 放进仓库，除非明确要求；临时程序放 TEMP。
