---
name: luajit-int3-refusal-set-relaxation
description: "放开/收紧 LuaJIT int3 断点的\"不可 arm 字节码\"集合：写点清点、断言化不变量、翻面测试与 teeth"
---

# 适用

要放开 `luaJIT_int3_arm()` 对某类字节码槽的拒绝（例如循环槽、返回槽、函数头），或要把现有拒绝集缩小/扩大时。前提：这个分支的 int3 已经是"挂载时 flush + PROTO_NOJIT"模型（`lj_int3_commit()` 在 `lj_dispatch_ins()` 尾 / `lj_dispatch_call()` 头挂载）。

不适用：纯粹的 int3 性能调优（见 `luajit-int3-lookup-cost-audit`）；配对 JMP / 伪 line hook 的诊断（见 `luajit-comparison-paired-jump-detection`）。

# 判定：这个槽该不该拒绝

把理由分成两类，只有第一类还在：

- **解释器自己改写**（无法用 guard 解决）→ 必须拒绝：
  - `BC_ISNEXT`：执行时把**自己**写成 `BC_JMP`，并把**邻居** `ITERN` 写成 `BC_ITERC`（或把 JLOOP 槽还原成 `BC_ITERC`）。
  - `BC_ITERN`：上面那个邻居。
  - 函数头全形态（`FUNCF/FUNCV/IFUNCF/JFUNCF/IFUNCV/JFUNCV`）：命中时帧与 vararg 布局都没建立，`lj_int3_hit()` 给不了回调一致视图。用 opcode 判，不要只判 `bcpos == 0`（补丁形态会变）。
- **JIT 改写**（已由不变量兜住）→ 可以放开：`FORI/FORL/ITERL/LOOP/RET/RET0/RET1` 及 `J*`/`I*` 形态。
- **从不派发** → 单独规则，不进 opcode 表：比较/测试（`BC_ISLT..BC_ISF`）紧随的 `JMP` 槽（`int3_paired_jump()`）。`RETM` 一直可 arm。

# 放开前的 writer 清点（逐个写点核对）

```bash
grep -rn "setbc_op(\|setbc_d(\|\*pc = \|BCINS_AD(BC_JLOOP" src/lj_trace.c src/lj_record.c
grep -n "mov PC_OP\|mov byte \[PC\]\|mov dword \[PC\]" src/vm_*.dasc
```

对每个写点回答"能不能碰到已挂载的槽"，并把答案变成断言（`lj_assertJ(!lj_int3_pending(J2G(J), pc), "…")`）：

| 写点 | 可达性 | 处理 |
|---|---|---|
| `trace_start` 懒 I-patch | NOJIT 原型的 hot 槽；外层已有 `!lj_int3_pending` | 保留 guard（断言保留） |
| `lj_trace_hot` | 进录制状态机前 | 已有 `lj_int3_jit_on_blocked` 早退，必须保留 |
| `trace_stop`（start patch / `JFORL` 连带的 `FORI`） | 需该原型的 trace | 断言两处 |
| `trace_unpatch` | 需 trace | 断言 |
| `trace_ins` 临时写 `startins` 到 JLOOP 槽 | 需 recording | 断言 |
| `blacklist_pc`（两个分支） | 需 penalty（真在录） | 断言，签名加 `jit_State *J` |
| `lj_record.c` `rec_idx_bump` 的 TNEW 回写 D | 需 recording | 断言 + `#include "lj_int3.h"` |
| `BC_ISNEXT` handler（自写 + 邻居） | 每次执行 | 无解 → 保持拒绝 |

arm-accept 时读到 `JFORL/JLOOP/IFORL` 不要紧：挂载先 flush 再捕获 `ins`，落盘的是原始形态。测试里可以直接断言这点（`funcbc` 前后 opcode 变化）。

# 落地步骤

1. `lj_int3.c: int3_mutable_op()` 只留上面第一类；同步改写它的注释（把"为什么现在安全 + 谁在保证 + 断言在哪"写清楚，否则下一个人会把 case 加回去）。
2. 按上表加断言；`lj_assertJ` 需要 `J`，必要时改函数签名（如 `blacklist_pc(jit_State *J, ...)`）。
3. `int3-smoke.c`：原来钉住"拒绝"的断言要**翻面**（并在需要精确计数的组里先 `cancel()` 隔离）；新增按槽位逐次计数的组，计数用构造法推导而不是观测值：
   - `FORI` 每次进入循环 1；`FORL` n 次迭代 n 次；`LOOP` 每迭代 1；
   - `ITERL`/`ITERC` 每次迭代器调用 1（n 个值 + 末尾 nil = n+1）；
   - `RET1` 每次返回 1，并配 `LUA_MASKRET` 断言 ret hook 仍看到影子指令；
   - 热循环槽：`JFORL` → arm → 槽内变 `FORL`，`hits == 迭代数`，`starts == 0`，cancel 后又能起 trace。
4. 文档：`src/luajit_rolling.h` + `doc/ext_c_api.html` 的不可 arm 列表、`LUAJIT_INT3_UNARMABLE` 的返回说明同步；改完用 regex 统计 `p/pre/tt/b/i` 开闭标签配平。
5. 验证：5 配置矩阵（`LUAJIT_ENABLE_GC64 -DLUA_USE_ASSERT` / 非 GC64 / `DISABLE_JIT`+`SMOKE_NO_JIT` / `DISABLE_PROFILE`+`SMOKE_NO_PROFILE` / 两者皆禁），每次 `mingw32-make clean` 后重建（矩阵循环最后留下的 DLL 配置会污染下一次增量构建，症状是 `undefined reference to luaJIT_profile_start`）。

# teeth（必须做，否则不知道测试有没有区分力）

- **断言 teeth**：同时删掉 `lj_trace_hot` 的 `lj_int3_jit_on_blocked` 早退 **和** `trace_start` 懒补丁的 `!lj_int3_pending` 判定 → assert 构建应报 `trace_start: patching a trapped slot`。只删一个不会触发（两层 guard + 断言是串联的，这点很容易误判成"没有 teeth"）。
- **行为 teeth**：同上但用非 `LUA_USE_ASSERT` 构建 → 陷阱在一个 hotloop 窗口后被 `IFORL` 覆盖，计数变成 `hotloop` 值（例如 56 而不是 5000）。
- 放开自身的 teeth：把 `int3_mutable_op` 加回被放开的那几项 → 新组应全红。
