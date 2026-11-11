---
name: luajit-line-slot-fixture-inspection
description: 在 LuaJIT 源码树里用一次性工具打印某段 Lua 每个 bcpos 的行号与 opcode（lj_debug_line 未导出需本地副本），用于给行→槽解析写有区分力的回归测试
---

# 何时用

需要确认某段 Lua 源码编译后每个 `bcpos` 的**行号**与 opcode（例如为 int3 行级 arm 写回归测试、核实行→槽的期望值、判断某条"跳过拒绝槽"的断言是否真能触发）。有 LuaJIT 源码树、能在 Windows/MinGW 下构建出 `lua51.dll` 即可。

# 为什么不能直接用公开 API

`jit.util.funcbc(f, pc)` 只给 opcode + 操作数，**不给行号**；行号在 `lj_debug_line()`，而它是内部符号，`lua51.dll` 不导出（链接报 `undefined reference to lj_debug_line`）。所以：include 内部头 + 把 `lj_debug_line` 的实现**照抄**进一次性工具（`proto_lineinfo` 可用）。

```c
/* lj_debug_line 的等价副本：pc==sizebc 返回 firstline+numline，pc==0 返回 firstline */
static int my_line(GCproto *pt, BCPos pc)
{
  const void *li = proto_lineinfo(pt);
  if (pc <= pt->sizebc && li) {
    int first = pt->firstline;
    if (pc == pt->sizebc) return first + pt->numline;
    if (pc-- == 0) return first;
    if (pt->numline < 256)      return first + (int)((const uint8_t *)li)[pc];
    else if (pt->numline < 65536) return first + (int)((const uint16_t *)li)[pc];
    else                        return first + (int)((const uint32_t *)li)[pc];
  }
  return 0;                      /* 无行表（stripped chunk）时恒为 0 */
}
```

opcode 名表：`BCDEF(BCNAME)` 展开即可（`lj_bc.h` 没有现成的 `bc_names`）：

```c
static const char *const opnames[] = { #define BCNAME(n, a, b, c, t) #n, BCDEF(BCNAME) #undef BCNAME "?" };
```

# 步骤

1. 工具里跑一段 chunk 定义被测函数，`lua_getglobal` + `lua_getfield` + `(GCfunc *)lua_topointer` → `funcproto(fn)`。
2. 逐个 `i < pt->sizebc` 打印 `i, my_line(pt,i), opnames[bc_op(proto_bc(pt)[i])]`，并在头部打印 `sizebc/firstline/numline/lineinfo 是否 NULL`。
3. 构建：`gcc -I . tool.c lua51.dll -o tool.exe`（MinGW，在 `src/` 下；链接 `lua51.dll` 而不是 import lib，内部结构体布局必须与当前构建一致）。
4. 读数得出期望值后**删掉工具**（它不是测试脚手架，不入库）。

# 已知结论（省得重复测量）

- 函数头 `FUNCF` 在 `bcpos 0`，行号 = `linedefined`，与首条语句共享行号。
- 多行函数里 `function f(...)` 那一行通常**只含函数头** ⇒ 行级解析应返回"无槽"。
- 单行 `generic-for`：`GGET, MOV, KPRI, ISNEXT, <body>, ITERN, ITERL, RET0`；先出现的是可 arm 的生成器表达式，所以**行首即拒绝槽的情况构造不出来**（ISNEXT/ITERN 与"被比较吞掉的 JMP"在同行的可 arm 指令之后）。行级解析真正需要的过滤是"跳过 `bcpos 0` 的函数头"。
- `string.dump(f, true)` + `loadstring` ⇒ `lineinfo=NULL`、`firstline=0`、所有槽的行号为 0；行级 arm 必须显式把这些变成"无槽/不存在"，否则会退化成"函数第一个槽"。
- 写测试时用**固定行号的 chunk 字面量**并注明每行用途；行号一动，断言应以返回码/回调 `bcpos` 立刻失败，而不是静默通过。

# 反向核对（区分力）

改完解析器后临时破坏关键判断（例如把扫描起点从 `bcpos 1` 改成 `0`、去掉 `line==0` 拒绝），重跑相关测试组，确认**必然失败**；恢复后再跑全绿。没有失败过的断言不算钉住行为。
