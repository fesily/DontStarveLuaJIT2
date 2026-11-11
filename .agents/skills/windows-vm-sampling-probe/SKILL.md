---
name: windows-vm-sampling-probe
description: 在 Windows 上验证 VM 内部采样机制（TF+VEH 陷阱、置陷阱必须先挂起、CONTEXT 寄存器、宿主栈回溯）的可复现步骤
---

# Windows 采样器机制验证

在 Windows 上验证“能否在目标线程内采样并读到 VM 状态”。用 MSVC + 仓库已构建的 LuaJIT DLL。

## 关键 API 事实

- `RtlVirtualUnwind(UNW_FLAG_NHANDLER, ...)` **成功时也返回 NULL**。不要用返回值判断成败；判断依据是传入的 `CONTEXT` 是否被推进（Rip/Rsp 变化、Rsp 单调递增）。
- `RtlLookupFunctionEntry(pc, &base, &hist)` 对无 `.pdata` 的地址（VirtualAlloc 分配的 JIT 代码）返回 NULL。此时**停止回溯**，不要按 x64 EH 文档的 leaf 规则硬解（会静默产生错误帧）。
- `RtlCaptureStackBackTrace` 在 VEH 内会混入 `KiUserExceptionDispatcher` 等异常分派帧。要干净栈就自己从 `CONTEXT` 回溯。
- 跨线程回溯（SuspendThread + GetThreadContext + RtlVirtualUnwind）可行，但读不到目标线程的 VM 内部状态。
- **置 trap flag 必须先挂起目标线程**（见下）。

## TF + VEH 采样骨架

```c
static int arm_trap(HANDLE h) {
  CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
  ctx.ContextFlags = CONTEXT_CONTROL;
  SuspendThread(h);                       /* 必须 */
  if (!GetThreadContext(h, &ctx)) { ResumeThread(h); return 0; }
  ctx.EFlags |= 0x100;                   /* trap flag */
  ctx.ContextFlags = CONTEXT_CONTROL;
  if (!SetThreadContext(h, &ctx)) { ResumeThread(h); return 0; }
  ResumeThread(h);
  return 1;
}

static LONG WINAPI veh(EXCEPTION_POINTERS *ep) {
  if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
    CONTEXT *c = ep->ContextRecord;
    c->EFlags &= ~0x100;            /* 必须清 TF，否则每条指令都触发 */
    /* 采样：c->Rip / c->Rsp / c->Rdx 都是被中断时刻的真实值 */
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  return EXCEPTION_CONTINUE_SEARCH;
}
```

VEH 回调在**目标线程**内运行，等价于 Linux 的信号处理函数：可以安全读该线程的 VM 状态。

## 为什么必须先挂起

省略挂起时陷阱**照样触发**（实测 300/300 次，延迟还更低），所以“能触发”不能作为可用性证据。真正后果是目标线程被破坏：

- `GetThreadContext` 对运行中的线程返回内核侧**陈旧**的上下文；写回它等于把 Rip/Rsp 回退到上次内核转换处。
- 实测：不挂起时目标线程连续 3 次以 `0xC0000005` 崩溃，故障地址是 0x0/0x3/0xFFFFFC66 等垃圾值；挂起路径 7.5 万次置陷阱后校验和完全正确。
- MSDN 明确禁止：`SetThreadContext` “Do not try to set the context for a running thread; the results are unpredictable.”

## LuaJIT 侧读取要点

- 定位 `global_State`：`global_State *g = mref(L->glref, global_State);`（`G(L)` 宏，`src/lj_obj.h`）。
- `g->vmstate` 语义：负值 = `~LJ_VMST_x`（INTERP/C/GC/...），正数 = trace 号，0 = VM 之外。
- x64 GC64 后端解释器 BASE 寄存器是 `Rdx`（`src/vm_x64.dasc:21`），`CONTEXT.Rdx` 即活的帧基址。
- `L->base` 缓存值与活的 BASE 多数时候不一致，不能直接用。
- 帧链回溯用 `lj_frame.h` 的 `frame_prev()`，止于 `L->stack + LJ_FR2`，跳过 dummy 帧与 vararg 伪帧。

## 验证要点（都是本轮踩过的坑）

- **用无歧义的目标健康度判据**验证安全性，例如有界循环的校验和。只看“陷阱是否触发/是否能读到状态”会漏掉目标已被破坏的情况。
- 多线程共享的 64 位计数器用普通 volatile 读会**撕裂成非单调值**，容易被误读成“目标被回退”。本轮就因此误判过一次；改用 32 位量或 `Interlocked` 系列。
- `printf` 参数个数要与格式串一致，缺一个会打印出看似“真实的”垃圾值（本轮出现过 `epoch_now=0` 实为缺参数）。
- `ExitProcess` 不 flush stdio，输出会全丢；退出前显式 `fflush(stdout)`。
- 必须用**真实 LuaJIT VM** 验证（链接仓库构建出的 `lua51DS.dll`），否则测不出 VM 状态语义。
- 区分解释器态与 trace 态：注册一个不可 trace 的 C 函数（如 `lua_pushcfunction` + 循环调用）可把 VM 固定在解释器；热循环则产生 trace。
- 断言“帧链干净终止在栈底”，而不只是帧数 > 0。
