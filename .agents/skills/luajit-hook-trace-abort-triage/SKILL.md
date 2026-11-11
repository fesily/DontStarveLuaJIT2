---
name: luajit-hook-trace-abort-triage
description: "Use when LuaJIT debug.sethook/profiler hooks interact with JIT traces: when tracing aborts or is bypassed; source map + measurement recipe."
---

# LuaJIT hook ↔ trace abort: triage & measurement

## When to use
- "为什么设了 hook 后 trace 不编译 / 被 abort / hook 在热循环里不触发"
- 排查 debugger/覆盖率工具在 LuaJIT 下行为不一致
- 确认 profiler（jit.profile/sysprof）能否观察到 mcode 内部

不适用于：纯 Lua hook 语义、非 LuaJIT 环境。

## 源码链（先读这几处，别猜）
1. `src/lj_trace.h:45` — `lj_trace_abort(g)` = `G2J(g)->state &= ~LJ_TRACE_ACTIVE`（只清位，延迟）。
2. `src/lj_jit.h:145-152` — trace 状态枚举；清位后为 1..6，落到 `trace_state` 的 `default:`（`lj_trace.c:751-760`）→ `trace_abort`，`LJ_TRERR_RECERR`。
3. `src/lj_dispatch.c:345`（`lua_sethook` 无条件 abort，含清除）与 `:372`（`callhook` 每次投递前 abort）。
4. `src/lj_dispatch.c:106-190` — 派发模式：LINE/COUNT→INS；CALL/RET 只换 call/ret 项；录制中整表 `lj_vm_record`；PROFILE→PROF|INS。
5. `src/vm_x64.dasc:2269-2312` — vm_record 检查 HOOK_VMEVENT/ACTIVE 并递减 hookcount；vm_inshook 检查后 `jmp 静态入口`。`4749-4756` — BC_JLOOP 静态入口直接跳 mcode（关键：INS 不阻止老 trace 进入）。`4564` — BC_FORL 静态入口仍 hotcount。
6. `src/lj_trace.c:788,802,818` — hot/hotside/stitch 遇 HOOK_GC|HOOK_VMEVENT 只是不录，不 abort。
7. `src/lj_record.c:2956-2976` — `LUAJIT_ENABLE_CHECKHOOK` 入口 guard（默认关）。`754-790, 2312` — `IR_PROF` 只由 profiler 模式录制；`src/lj_asm_x86.h:2701-2706` 生成 `test hookmask, HOOK_PROFILE` 退出。`src/lj_profile.c:333-337` 起停 'l'/'f' 先 flushall。
8. `src/lj_ffrecord.c:172-177` — 录制中调用 `debug.sethook` 是正常 stop（不 stitch），不是 RECERR。

## 判据速查
| 现象 | 结论 |
|---|---|
| line hook 下循环没 trace | 正常：回边/行变化必触发 hook → RECERR abort |
| count hook 很大时仍有 trace | 正常：计数未在录制期间耗尽 |
| call hook 下无调用循环有 trace | 正常：录制期间无 call 事件 |
| hook 设了但热循环里不触发 | 老 trace 仍走 JLOOP 进 mcode；hook 只在入口派发一次 |
| 移除 hook 后无重录 | 缓存未 flush，直接复用 |
| 想看 mcode 内部 | 只能 `jit.profile`/sysprof（IR_PROF），debug hook 无效 |
| CHECKHOOK 构建后行为剧变 | guard 只在 trace 入口，可能引发反复重录 |

## 测量配方（避免假象）
1. 用 `jit.attach(cb,"trace")` 记 start/stop/abort；abort 的 err 是 `jit.vmdef.traceerr[code]`，0 = RECERR。用 `jit.attach(cb,"texit")` 证明 mcode 真的跑了。
2. 事件按 `func == 目标函数` 过滤，否则 hook 函数自身被 trace 会污染结果。
3. 别在 hook 里调 `jit.util.traceinfo` 扫描：探测循环自己会被 JIT，产生额外 trace。
4. 默认 hotloop=56，短循环不会编译；要么加长循环（2000 次），要么显式 `jit.opt.start("hotloop=1")` 并接受污染。
5. 解释执行基线：`jit.off(); jit.flush()`——**`jit.off()` 单独不清缓存**，旧 trace 仍执行。
6. 交叉验证：`-jv` 看 `[TRACE --- ... abort ...]` / `[TRACE 1 ... loop]`；必要时 `XCFLAGS=-DLUAJIT_ENABLE_CHECKHOOK` 重建对比（记得恢复默认构建）。

## 关键实测数字（本仓库参考）
2000 次无调用循环：无 hook→1 start/1 stop；line hook 从零→6 次全 abort、2004 次 hook 调用；count=1000/100000→正常编译；先热编译再设 line hook→0 新 trace、只 8 次 hook 调用（解释 2002）；含调用循环先热编译再设 call hook→3 次 hook（解释 2003）。
