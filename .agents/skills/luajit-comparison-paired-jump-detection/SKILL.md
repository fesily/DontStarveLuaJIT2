---
name: luajit-comparison-paired-jump-detection
description: 按槽位插桩 LuaJIT 解释器：SAVE_PC==cframe pc 导致的伪 line hook、比较指令吞掉紧随 JMP 槽、lj_dispatch_topslot 的逐指令读取与 callback 栈视图断言
---

# 适用

在这个 LuaJIT fork（含 DST 系列分支、`BC_INT3` 断点模块）里做**按槽位**的插桩或改动：断点/命中、指令覆盖率、逐指令 profiler、`lj_dispatch_*` 的 hook 行为。不是通用 LuaJIT 调优。

三个陷阱按代价排序：SAVE_PC 别名 > 从属 JMP 槽 > topslot 的逐指令读取。

# 1. SAVE_PC 就是 cframe 的 pc 字段

**事实**：各后端 `.dasc` 的 `SAVE_PC` 偏移 == `lj_frame.h` 的 `CFRAME_OFS_PC`。已核对：x64 GC64 posix/WIN = 24/96，x86 = 24 / 100 / 28，arm = 8，arm64 = 8，mips = 20，mips64 = 160/96，ppc = 412/460/32（判据：同文件里 `SAVE_L` 偏移 == `CFRAME_OFS_L`，说明 `sp`/`rsp` 就是 cframe 基址）。

**后果**：汇编 handler 在 `call` C 之前写 `SAVE_PC = PC` 会摧毁 `lj_dispatch_ins()` 用作 `oldpc` 的 previous PC。它拿 `oldpc` 与入参 `pc` 比较（`pc <= oldpc` 视为回跳）决定是否发 line event，于是同一行的指令会多发一次 line event（实测 `baseline=2 armed=3`）。

**修法**：汇编不写 `SAVE_PC`；C 侧照 `lj_dispatch_stitch()` / `lj_dispatch_profile()` 的既有模式：

```c
cf = cframe_raw(L->cframe);
oldpc = cframe_pc(cf);          /* 真正的 previous PC */
setcframe_pc(cf, pc);           /* 发布当前 PC 给 callback / C 代码 */
... 回调 ...
setcframe_pc(cframe_raw(L->cframe), oldpc);  /* 再派发前还原 */
```

hook/record 的续执行路径（`4:`/`5:` tail）里写 `SAVE_PC = PC` 是**可以的**：那条路径不再进 `lj_dispatch_ins`，且下一个 C callee 期望的就是"当前 PC"。

**旁证**：`lj_meta_arith/comp/bitop/equal_cd` 的汇编慢路径自己在 `call` 前写 `SAVE_PC, PC`，所以 C 侧用 `cframe_pc(cf)-1` 解析执行中的 opcode 是安全的；依赖这一点前先确认四个慢路径都还写着。

# 2. 比较/测试指令吞掉紧随的 JMP 槽

`BC_ISLT..BC_ISF`（comparison ops 后接全部 unary test ops，枚举 0..15 连续；`BC_ISTYPE`/`BC_ISNUM` 不在内）的 handler 先 `add PC, 4`，再从 `PC_RD` 读紧随那个 JMP 的 D 当分支目标，然后或跳、或 `ins_next` 跳过该槽：

```lua
function f(x) if x then return 1 end return 2 end
-- 0001 ISF 0 ; 0002 JMP 1 => 0005    -- 0002 永不派发
-- repeat..until 尾部同样：ISGT 0 1 ; JMP => loop_start
```

给这种"从属槽"设断点/探针会**静默漏报**：arm 返回 OK、hits=0。检测方式：逻辑视图下取前一条指令，`bc_op(prev) >= BC_ISLT && bc_op(prev) <= BC_ISF` 即拒绝（`LUAJIT_INT3_UNARMABLE`）。

循环回边、`UCLO`、`ISNEXT` 的 JMP 都是真派发，可以插桩——写测试时要同时钉住"从属槽拒绝"和"回边可命中"两半，否则容易修掉后者。

用 `./luajit.exe -bl -e '...'` 看 `=>` 目标即可确认配对关系；不要只信算出来的 `bc_d()`（`-bl` 已经加过 `BCBIAS_J`）。

# 3. lj_dispatch_topslot() 是唯一逐指令读逻辑字节码的地方

hook/record 开启时它每条指令都被调用（`lj_dispatch_ins` 里），外加 `lj_dispatch_ins` 的 return-hook 判定；两者都必须能拿到"被 trap 槽的影子指令"。它们是断点会话唯一会落在"每条指令"上的查表成本——原型门控（`pt->flags & PROTO_NOJIT` 才查表，因 armed ⇒ NOJIT）可把它降为零，详见 `luajit-int3-lookup-cost-audit`。

**可观测结果不是 hits，而是 callback 里的 `lua_gettop()`**（`lua_gettop = L->top - (L->base-1)`）：

- CALLM：`L->top = base + (A+C+nres-1+1+LJ_FR2)`；frame 初始 `nres=1`，故 `lua_gettop() == A+C+nres+1+LJ_FR2`（A=0,C=2 时 GC64 得 5）。
- 退化成 `pt->framesize` 时实测 `depth=3` → 断言 `depth == 4 + fr2` 就能钉住。
- `LJ_FR2 == LJ_GC64`；运行时探测：`string.dump(function() end):byte(5)` 的第 3 位（同 `-bl` 之外最省事的 GC64 判定）。

# 4. 验证与 teeth 习惯

- 计数一律用**精确执行次数**（N 次迭代 = N 次命中、停止后归零），不要用区间；变体之间显式 cancel，避免上一条断点污染。
- 每条机制都要有"回退即失败"的 teeth：回填 `SAVE_PC` 写入 → line event 复现；回退从属 JMP 判定 → UNARMABLE 断言失败；门控无条件跳过 → `depth` 断言失败；前缀界不增长 → 命中查不到、`BCFMT` 直接崩。
- 计数变化时先怀疑测试而非实现：`ADDVV`/`ADDVN`/`ISGE`/`ISNEV` 的实际 opcode 与源码直觉不同（`if a<b` 生成 `ISGE`，`if a==b` 生成 `ISNEV`），确认用 `find_bcpos` 现查而不是手写 index。
