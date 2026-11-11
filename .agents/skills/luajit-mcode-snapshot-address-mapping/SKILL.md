---
name: luajit-mcode-snapshot-address-mapping
description: "LuaJIT x64: map mcode address ↔ trace snapshot/bytecode PC/line, understand exit stubs, mcofs, guard branch sites; use when reverse-locating trace code or reading -jdump/mcode."
---

# LuaJIT mcode ↔ snapshot ↔ line 映射

用途：把 mcode 地址归属到 trace/快照/行号，或反向找某 PC/行在 mcode 的精确守卫地址。基于 LuaJIT 2.1 x64/GC64（`LJ_FR2=1`、`EXITTRACE_VMSTATE=1`）。

## 1. 地址 → 快照/行（现成路径）

```c
/* lj_trace.c: lj_trace_unwind(J, addr, &exitno) */
T = traceref(J, vmstate);                 /* vmstate 在 trace 内恒为 traceno */
if (T->mcode <= addr < T->mcode + T->szmcode) {
  ofs = addr - T->mcode;
  /* 二分 snap[i].mcofs，得最大 i 使 snap[i].mcofs <= ofs → exitno = i */
}
pc = snap_pc(&T->snapmap[T->snap[exitno].mapofs + T->snap[exitno].nent]);
line = lj_debug_line(pt, proto_bcpos(pt, pc));
```

- `snap[i].mcofs` = 快照 i 守护代码区的**起点偏移**（相对 `T->mcode`），不是分支指令地址；`snap[0].mcofs == 0`。
- 归属是**区间级**近似：head/tail/loop 不变段会被就近算进相邻快照。
- 快照不记 proto：PC 可能属于内联的被调函数，需自行找包含该 pc 的 proto 才能算行号。

## 2. 快照/行 → 精确 mcode 地址（必须自己扫）

官方没有 PC→地址表。做法同 `lj_asm_patchexit`（`lj_asm_x86.h:3132`）：

1. `exit = exitstub_addr(J, exitno)`（共享 stub：`group[exitno/32] + 4*(exitno%32)`）。
2. 在 `T->mcode .. +T->szmcode` 线性扫描 `0F 8x rel32`，判定目标：`site + 6 + rel == exit`（C 里 `lj_asm_patchexit` 用 `px = exit-6` 与 `site + rel` 比较，因为其比较式用指令起始地址）。
3. 跳过 vmstate 更新（`mov [DISPATCH+vmstate], imm32`）之前的部分（stack check），跳过目标为 `lj_gc_step_jit` 的 GC check。
4. 一个快照可有 0..N 个分支点（快照合并），一条字节码也可有多个快照（循环展开/分支两侧）。

Lua 侧 API：

```lua
local mcode, addr, loop = jit.util.tracemc(tr)   -- 字节串 + T->mcode + T->mcloop
local stub  = jit.util.traceexitstub(exitno)     -- x86: 公共 stub 地址
local snapinfo = jit.util.tracesnap(tr, sn, true) -- [0]=ref-REF_BIAS, [1]=nslots, [n+2]=entries; getpos 返回 bcpos
local line = jit.util.funcinfo(proto, bcpos).currentline
```
注意 `snap->mcofs` **未**在 `jit.util` 暴露；需要时改 `lib_jit.c` 的 `tracesnap` 加一行。

## 3. 必知不变量

| 事实 | 依据 |
|---|---|
| stub 按 exitno 全局共享，不含 traceno；traceno 来自 `g->vmstate` | `lj_target_x86.h:167`、`vm_x64.dasc:2459` |
| `exitno == snapno`（当前实现） | `lj_snap.c:943` |
| mcode 地址升序 = IR 顺序；`T->mcode` 是最低地址入口 | `lj_asm.c:2471-2640` 逆序生成 |
| `T->szmcode` 不含 exit stub（stub 在区底、由 `lj_mcode_commitbot` 永久占用） | `lj_asm_x86.h:9-63` |
| `mcofs` 是 uint16，超 64 KB → `LJ_TRERR_MCODEOV` | `lj_asm.c:1079` |
| GC64 快照 PC 打包 `(pc<<8)|(baseslot-2)`，低 8 位用于还原 `L->base` | `lj_snap.c:113`、`:1013` |
| 快照只在 `J->needsnap` 后产生，且可合并（无 IR 间隔 / 无 guard） | `lj_record.c:2287`、`lj_snap.c:184` |

## 4. 常见误判

- 别把 `snap[i].mcofs` 当成守卫指令地址；它是区间下界。
- 别假设「一条字节码一个快照」或「一条快照一个退出点」。
- 退出后 `L->top` 由 `bc_op(snap_pc)` 决定（`BC_CALLM/RETM/TSETM` 特例），不是 `snapslot` 简单上界。
