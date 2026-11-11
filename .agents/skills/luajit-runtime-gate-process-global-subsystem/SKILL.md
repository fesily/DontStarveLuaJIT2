---
name: luajit-runtime-gate-process-global-subsystem
description: 把 LuaJIT 子项目里进程全局的子系统(ETW provider/缓存/线程)改成多 VM 安全的运行时开关:作用域判定、退役表释放归属、jit.profile 暴露面、以及编译/场景/标签/lane/真实抓取/成本六步验证。
---

# 何时用

在 DontStarveLuaJIT2 的 `luajit` 子项目里,把一个**进程全局的子系统**(Windows ETW provider、符号缓存、后台线程、外部句柄…)从"隐式常开"改成**运行时开关**,并且必须在多 VM(多 `global_State`)下安全。典型触发:用户说"改成运行时启用/禁用"、"参看 jit.profile 的作用域"。

# 1. 先定作用域(不要照搬 jit.profile)

- `jit.profile` 的 C 模块是**单例且独占**:`static ProfileState profile_state;` 只记一个 `ps->g`,非启动者 `start` 会被 `stop+return` 丢弃,`stop/dumpstack` 只有启动者能用。它"不考虑多 VM"。
- 但如果子系统天然是进程唯一的(ETW provider GUID、`EventRegister`、符号缓存、工作线程),正确模型是:**一个全局开关 + 每个 VM 一个小 context**,最后一个注销时才销毁 provider/线程。这样"任何 VM 的调用都全进程生效",而且其它 VM 不会失去能力。
- 结论口诀:**全局开关(粒度=资源),per-VM 注册(粒度=参与者)**;别做"启动者独占"。

# 2. 多 VM 安全的两条硬规则

1. **不被别的线程解引用**:后台 worker 只能读自己拥有的、自包含的记录(context id/地址/字符串),绝不碰 `GCtrace`/`GCproto`/Lua 字符串。
2. **释放要归属主**:把全局状态拆成"发布表"和"退役表"。关闭时:发卸载事件 → 从发布表摘链 → 打 `retired` 标记移入退役表(内存不释放)。只有**属主 VM**(它自己的 `T->etw_entry` 可能还指着这条记录)在 `deltrace`/`freestate` 时才 `HeapFree`。谁都不能替别人的 VM 释放。

锁序固定 `lifecycle → cache`;worker 只取 cache 锁;`stop/join/unregister` 在 lifecycle 锁内但**不持 cache 锁**。

# 3. 开关的语义模板(本项目已选定)

- **默认关**;开启=重建干净符号表:对本 VM 执行 `lj_trace_flushall`(等价 `jit.flush`),避免"关闭期间编译的 trace 没有记录"或旧身份被地址复用继承;不要设计"从现存 trace 重建记录"那套(需要在别的 VM 线程上跑)。
- 关闭=立即上报卸载(consumer 视图立刻干净)+ 停发 + 退役记录;之后新编译的 trace 不再产生事件。
- 暴露面放 `jit.profile`(`LJLIB_CF(jit_profile_etw)`:无参查询、有参设置并返回结果;`setboolV(L->top++)`)。**不需要改模块注册表** —— LuaJIT 的 `lj_libdef.h` 由 buildvm 从 `LJLIB_CF(...)` 自动生成。
- 无平台支持时返回 `false`(API 面统一),`#else` 分支用 `((void)(J), (void)(on))` 风格的空宏。

# 4. 验证链(缺一不可)

1. 编译:`cmake --build builds\ninja-multi-vcpkg --config RelWithDebInfo --target luajit luajit-arenagc etw-symbols-default etw-symbols-arenagc`(工具链不在 PATH,走 vcvars64 的 bat;见 `dst-luajit-fork-build-ctest-verify`)。
2. 单场景快跑:测试 exe 支持 `--only=<场景名>`,先跑新加的那个开关场景(秒级)。**同时观察旧场景全超时** —— 那是"默认关"生效的正面证据。
3. 标签级:`ctest --test-dir builds\ninja-multi-vcpkg -C RelWithDebInfo --output-on-failure -L luajit_etw`(两个 GC 变体都跑)。
4. 全 lane:`-R luajit`(应为 28/28)。
5. 真实消费者:`python tests\performance\verify_jit_symbols.py --exe <etw-symbols exe> --out <dir>`(非管理员自动经 sudo 起 WPR;`--etl/--pid` 可离线复算),看 `JIT SYMBOL ACCEPTANCE: PASS` + `samples_in_trace_range` + `captured order`。
6. 成本:小 C 微基准(create/open/close N 个 VM,三种状态:关 / 开 / `LUAJIT_DISABLE_ETW` 编译期移除),**三次取最小**再比较 —— 单次跑摆动可达 ±15%,差值落在噪声里就不要宣称"零开销以外的数字"。

# 5. 收尾要说的

- 默认关会**打断"先跑后 attach"**的既有能力:必须有人显式开。所以在报告里明确点出"游戏/宿主需在注入 VM 的引导里调一次 `profile.etw(true)`",并把它当成待接线项(注入器往往在用户的脏树里,别擅自改)。
- 文档三处同步:`tests/performance/README.md`(开关语义 + 游戏侧要求 + 成本表)、`CHANGELOG.md`/`CHANGELOG_EN.md` 同一条;提交仍按"子项目产品代码/子项目测试"与"主项目工具/文档/gitlink"两笔分。
