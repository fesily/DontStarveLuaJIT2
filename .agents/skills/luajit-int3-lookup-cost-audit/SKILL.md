---
name: luajit-int3-lookup-cost-audit
description: LuaJIT int3 断点会话 arm 后的 per-instruction 查表成本：查表点归类、dead-slot 基准测量法、PROTO_NOJIT 门控修复与重验；非 int3 性能问题勿用
---

# 适用

在 LuaJIT fork（尤其是带 int3/BC_INT3 断点模块的分支）里，需要回答或消除「断点会话 arm 之后，hook/record 派发是否每条指令都多一次查表」这类问题时用。也适用于审阅别人提出「为什么不在指令里内嵌索引」的疑问。不适用于普通性能调优或非 int3 场景。

## 1. 先确定「查表在哪里」

`lj_int3.c` 的 `int3_find()` 是全模块唯一的 slot→原指令 映射（32 条线性表，早退条件 `st->g != g || st->count == 0`）。逐个 grep 调用点并归类：

```bash
grep -rn "lj_int3_bcins\|lj_int3_ins\|lj_int3_pending" src/*.c src/*.dasc
```

判定标准：只有「拿不到 trap 语义就错」的路径才允许查表；能改成删物理 opcode 依赖的（如 x64/x86 `vmeta_tgets/tsets` 的 `PC_OP` 比较、ARM `vmeta_unm` 的重读）优先删而不是包一层。

已知结论（int3 分支）：

| 路径 | 频率 |
|---|---|
| `lj_int3_hit` | 每次执行已 arm 槽（被回调成本淹没） |
| 命中后重派发 → `lj_dispatch_topslot` | 每次命中且 hook/record 开 |
| `4:`/`5:` 续执行 → `lj_int3_ins` | 每次穿 hook 的命中 |
| `lj_meta.c meta_opcode`/`equal_cd` | 已 arm 指令走 C 慢路径 |
| **`lj_dispatch_topslot` + `LUA_MASKRET` 判定** | **hook/record 开启时每条指令** ← 唯一 per-instruction |
| `funcbc`/dump/debug 自省 | 每次调用 |

「指令码内嵌索引」不可行的三条硬理由：A/B/C/D 必须保留原操作数（操作数直读点极多）；opcode 空间被 `BC_FUNCF..` 紧随（`bc_isret`、`bc_op(*pc) < BC_FUNCF` 依赖顺序）；派发表按 opcode 索引，没有 per-slot entry。

## 2. 测量（关键：隔离「扫描」而不要测「命中」）

在**从不被调用**的原型里 arm N 个槽，运行时每条指令都会扫表但永不命中，delta 就是纯查表成本。

- 用 `lua_sethook(L, cb, LUA_MASKCOUNT, 1)` + `jit.off()`，循环体 `for i=1,N do s=s+i local a=i*2 s=s+a end`；
- 迭代 ≥2M（8M 指令），否则 `clock()` 1ms 粒度噪声压不住；
- **每个配置跑 3 次取稳定值**：单次首跑可能偏高 50%+（观察到的假象）；
- 配置序列 0/1/4/8/16/32 槽（每段先 `luaJIT_int3_cancel` 再 arm）；
- 先确认 `luaJIT_int3_start` 返回 `LUAJIT_INT3_OK`（`=4` 表示 UNAVAILABLE，说明当前 DLL 是 `LUAJIT_DISABLE_PROFILE` 构建，先重建 GC64 主配置）。

参考基线（MinGW/GC64，`LUA_USE_ASSERT`）：0/1/4/8/16/32 → 92-99 / 140 / 137 / 141 / 149 / 174-191 ns/指令。注意 1 槽就 +51%：主导项是进循环后的依赖链与条目数组 cache line，不是 32 次比较。

## 3. 修复：按原型门控（首选）

不变量：**armed ⇒ `PROTO_NOJIT`**。依据：`int3_arm_request` 无条件置位；`luaJIT_setmode(ON)` 对已 arm 或含 arm 子原型被 `lj_int3_jit_on_blocked` 拒绝；`int3_cancel_entry` 只在条目释放后清除。

```c
static LJ_AINLINE BCIns disp_ins(global_State *g, GCproto *pt, const BCIns *pc)
{
  /* Only an armed prototype carries a trap, and arming sets PROTO_NOJIT
  ** (never cleared while one of its entries exists). */
  return LJ_UNLIKELY(pt->flags & PROTO_NOJIT) ? lj_int3_bcins(g, pc) : *pc;
}
```

替换 `lj_dispatch_topslot()` 与 `lj_dispatch_ins()` 里 `bc_isret(...)` 两处。实测 armed=32 从 +84…101% 降到 0…+4%。副作用：`jit.off` 过但无断点的原型会白查一次（语义正确）。

可选第二层：`Int3State` 增加平行 `BCIns *slot[LJ_INT3_MAX]`，`int3_find` 变纯指针比较（少一次 `proto_bc(pt)+bcpos*4` 依赖计算），hit/`lj_int3_ins`/meta 三条路径同时受益。

## 4. 改完必须重验

1. `make clean` + 5 个配置矩阵（GC64+assert / 非 GC64 / `DISABLE_JIT`+`SMOKE_NO_JIT` / `DISABLE_PROFILE`+`SMOKE_NO_PROFILE` / 两者皆禁）；
2. 针对性 teeth：临时删掉门控 → 用 count=1 hook 重测 armed=32 应回到 +80% 以上；同时确认 arm 后**同一**原型的断点仍命中（门控不能漏掉真陷阱）；
3. 非宿主后端：DynASM 预处理 + 生成 arch 头 `gcc -fsyntax-only`（`buildvm -m elfasm` 在 Windows 宿主上对 pristine dasc 也会 `DASM error`，不是有效判据）；
4. 只动 C 时无需动 `.dasc`；若动了 `.dasc`，按 `luajit-nonhost-asm-edit-verify` 走。
