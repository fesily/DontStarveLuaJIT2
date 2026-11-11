---
name: win64-jit-unwind-metadata-audit
description: "Audit/verify Windows x64 UNWIND_INFO v1 against actual JIT machine code (prologue/epilogue offsets, stub coverage, thunk range tiling) using RtlLookupFunctionEntry/RtlVirtualUnwind and boundary CONTEXTs"
---

# 目的

审计/验证 Windows x64 JIT 生成的 `UNWIND_INFO`(v1) 与其实际机器码是否一致，尤其是 runtime stub、lazy-bb thunk/片段这类手写字节序列。适用：新增/修改 prologue 元数据、怀疑“异常/采样无法穿过某些帧”、或对照其他实现（如 madc）时。

# 1. 先把“元数据 ↔ 机器码”逐条对齐

对每个被审计的代码块，取 `RtlLookupFunctionEntry(pc, &base, NULL)` 得到 `RUNTIME_FUNCTION`，然后：

- `ui = base + rf->UnwindData`（**MinGW 头里叫 `UnwindData`，MSVC 叫 `UnwindInfoAddress`**；写可移植代码时自定 3×DWORD 结构体再 cast）。
- 打印 `version=ui[0]&7`、`SizeOfProlog=ui[1]`、`CountOfCodes=ui[2]`（**槽数，不含奇数补齐**）、`FrameRegister=ui[3]&15`、`FrameOffset=ui[3]>>4`。
- 逐槽解码 `CodeOffset=ui[4+2k]`、`UnwindOp=ui[5+2k]&15`、`OpInfo=ui[5+2k]>>4`，注意 `ALLOC_LARGE(info=0)`/`SAVE_*` 各占 2 槽、`ALLOC_LARGE(info=1)`/`_FAR` 占 3 槽——按槽遍历会把操作数槽误当操作码。

必查项：

1. `rf->EndAddress` 必须覆盖**整个可执行区间**（常见错误：只填了 prologue 结束偏移，如 `end=0x07`），否则 body 里任一 PC 都落成 leaf 规则。
2. 手写 stub 的代码若由多段拼接（`save_pat` + `prepare_pat` + 结果搬运 + 尾声），`CodeOffset` 必须从**整段第一条指令**计起；用“前缀长度 + 段内注释偏移”重算，不要照抄段内注释。
3. `SizeOfProlog` = 最后一条序言指令的结束偏移；epilogue 不描述。
4. 帧寄存器形态：`FrameRegister=RBP`、`FrameOffset=F/16`，帧基 `= RBP - F`；无帧寄存器时 `SAVE_*` 偏移相对**分配后的 RSP**。
5. 大帧：`F=min(frame_alloc,240)`，`bias=frame_alloc-F`，重基后 `FP_new+bias == FP_old`；`F` 需 ≥ 被保存非易失寄存器总长（最多 8 GPR + 10 XMM = 224）。

# 2. 用真实展开器验证（唯一可信判据）

构造合成 `CONTEXT`，对**每个指令边界**调用 `RtlVirtualUnwind(UNW_FLAG_NHANDLER, base, ctx.Rip, rf, &ctx, ...)`，要求得到同一个 caller RIP/RSP/RBP 与被恢复的寄存器：

- 私有栈：`E = align16(buf+off) + 8`（函数入口 RSP%16==8），`[E]=caller_rip`。
- 逐个状态：entry(0) / after push / after sub / after lea rbp / after each save / 尾声 `lea rsp` 之后。
- **陷阱：Windows 展开器会对“RIP 恰在/越过第一条 epilogue 指令”的帧走 epilogue 路径，不再恢复非易失寄存器**（认为 epilogue 自己已经恢复）。所以：序言末尾要额外插一条 `nop` 并把 `SizeOfProlog` 放到 nop 之后，才能测到 “save 之后”的真实恢复；epilogue 用例的初始寄存器值要设成“已恢复”的值并断言保持不变。
- `FrameOffset`/Saves 语义不要只信文档或 Wine/ReactOS 类似实现，必须用真实 `RtlVirtualUnwind` 结果反推。

# 3. 分区间代码（bb thunk）

thunk 若 `movabs; sub rsp,H; call [rip+lit]; add rsp,H; nop; jmp r10`：

- 区间必须 tile 成三段且无缝：`[0, end(sub))` 用 inherited/leaf（未调整）、`[end(sub), end(add))` 用“inherited + ALLOC H @offset 0”（已调整，覆盖 call 返回 PC 与 add 起始 PC）、`[end(add), exec_end)` 用 inherited/leaf。
- 用 `RtlLookupFunctionEntry` 在 0x00/0x0a/0x0e/0x14/0x18/0x1b 各点 dump，确认每个偏移落在预期区间、COM 重叠/空洞为 0。
- 入口 thunk（被 `call` 进入，RSP%16==8）用 leaf + alloc-only；内部 thunk（被 `jmp` 进入，有帧 RSP%16==0、真 leaf RSP%16==8）用 inherited；jret/jcall 连续体两者都是 RSP%16==0 且不可描述，只登记 wrapper 调用那一段。

# 4. 注册/API 检查

- `RtlGrowFunctionTable` 返回 **VOID**（SDK `rtlsupportapi.h` 与 mingw `winnt.h` 都是），不能当状态码判失败——否则一次成功 grow 可能被误判、删表并报错。
- `RtlAddGrowableFunctionTable` 的数组必须稳定、可写、`BeginAddress` 严格递增；容量不足要**换新 holder**，绝不 realloc 已注册数组。
- 表删除必须在代码 unmap **之前**；建议用自定义 `MIR_code_alloc` 的 `mem_unmap` 回调断言“该 PC 已查不到”；注意 `VirtualFree(addr, 0, MEM_RELEASE)`（size 必须为 0）。
- 若错误处理器可能 `longjmp`，不要在持锁时调用它：把失败状态带出临界区、解锁后再报。
- 元数据上限（prologue/CountOfCodes ≤255、分配/偏移可表示）必须是**硬错误**；`assert` 在 NDEBUG 下会消失，导致静默截断。

# 5. 快捷自检程序骨架

```c
MIR_context_t ctx = MIR_init ();            /* 或 MIR_init2(NULL, &custom_alloc) */
void *stub = _MIR_get_bb_wrapper (ctx, NULL, hook);
dump("bb_wrapper", stub);                   /* rf 范围 + prolog + 逐槽操作 */
dump("wrapper_end", _MIR_get_wrapper_end (ctx));
/* 生成若干 MIR 函数后 dump(f->u.func->machine_code) */
```

再对 `_MIR_get_ff_call` / `_MIR_get_interp_shim` / `_MIR_get_bb_thunk_win64`（含 framed 与 entry 两种）重复，最后删除这个临时程序。

# 6. 回归测试的落点

- 三种链接模式（full / lazy / lazy-bb）× optimize 0 与 2 各跑一遍“从 host probe 真实 walk 到外层 caller”的断言。
- 场景要覆盖：小帧、>240 字节帧、无帧寄存器有保存、alloca、varargs、block arg、inline（bstart/bend）、浮点参数穿过 wrapper、leaf。
- 机器码哨兵：单独写一段 machine code 保存/设置/校验 rbx/rsi/rdi/r12–r15（`xor` 累加后返回），并经同一个 publisher 注册自己的 unwind 信息；`_ReturnAddress()` 必须在**被 JIT 直接调用的那个函数里**取（被内联进 helper 时 MSVC 返回的是外层函数内的地址）。
