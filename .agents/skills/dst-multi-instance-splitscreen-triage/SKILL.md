---
name: dst-multi-instance-splitscreen-triage
description: "Use when triaging whether a DST binary (Android/Windows/macOS) retains console same-process multi-client and split-screen architecture; maps instance slots, update/render job threads, and platform gating."
---

# 目标

判定某个 DST 二进制（Android `libDontStarve.so` / Windows exe / macOS）是否保留主机同进程双客户端 + 分屏架构，并给出线程/实例拓扑的地址级证据。

# 0. 落点

`list_open_programs` → `switch_program` 选目标（Android: AARCH64, image_base 0x100000）。带完整 `.symtab`，直接用符号名搜索，不要靠字符串猜。

# 1. 符号层证据（先做，几十秒出结论）

`search_functions` 逐个查：
- `GameInstance`（`SetNumGameInstances` / `InitializeGameInstances` / `StartGameInstances` / `AssignPlayerToGameInstance` / `SetGameInstanceAsOverlay` / `StartGameInstancesAsyncThread`）
- `SplitScreen`（`SimLuaProxy::GetIsSplitScreen` 等）
- `Viewport`（`GetViewportSizeAndSplit` / `HaveMultipleViewports` / `ViewportHasPlayer`）
- `Thread`（`RenderThreadUpdate` / `IsOnRenderThread` / `InitializeUpdateThread` / `SimThread`）

`search_strings` 查 `_ZN16cApplicationBase` / `MultiInstanceMode` / `_ZN11SimLuaProxy` 可拿到全部相关符号的 mangled 名。

# 2. 实例槽位语义

`decompile_function` 于 `cApplication::InitializeGameInstance`：末尾按 `sGameInstances[i] == this` 选日志标签，直接读出槽位含义。DST 为 0=Client0、1=Client1、2=Server、3=CaveServer、4=Overlay。

# 3. 启动即真相

`decompile_function` 于 `cApplication::Startup`：看 `SetNumGameInstances(?,?)` 的常量、`UpdateJobThread_%d` 循环、`RenderThread` JobThread、`gUseThreadedRenderer` 赋值、`InitializeGameInstance` 的槽位、`StartGameInstances(mode)` 的实参。

# 4. 全局变量与开关

- 从目标函数的 `disassemble_function` 读 `adrp xN,0xf16000 / ldr xN,[xN,#off]`，取 GOT 槽地址；`read_memory` 该槽得真实全局地址（GOT 内是 8 字节指针）。
- `get_xrefs_to <全局地址>` 看 READ/WRITE 点：唯一 WRITE 点 = 编译期硬编码；无 WRITE = 永远默认值（.bss 为 0）。
- 关键：`gUseThreadedRenderer` 唯一写入若为 0 ⇒ 渲染线程对象存在但只做 `OneFrame` 同步执行。

# 5. 调用可达性

`get_xrefs_to <PLT thunk>`（不是 impl 地址）拿全部调用点，看实参常量：决定哪条 `MultiInstanceMode` 分支在目标平台是死代码。

# 6. 每实例独立 Lua VM

`search_functions luaL_newstate` → `get_xrefs_to <thunk>` → 找到 `cSimulation::NewLuaState` / `SimThread`；`decompile_function` 确认 `luaL_newstate()` 在 `cSimulation` 上调用（一实例一 VM）。

# 判据

| 观察 | 结论 |
|---|---|
| `SetNumGameInstances(N>1)` 且槽位含 Client1 | 多客户端架构在 |
| `StartGameInstances` 的 mode 2/3 存在但无调用点 | 引擎在，平台入口不在 |
| `gUseThreadedRenderer` 唯一写入 = 0 | 该平台无独立渲染线程 |
| `SimLuaProxy::StartGameInstance(index)` 存在 | 脚本层可直接拉实例（前提：该槽位已初始化） |

# 输出

结论 + 地址表（符号 / 地址 / 反编译要点）+ 线程拓扑图 + 明确区分「引擎保留」与「平台层缺失」，禁止把后者说成前者被删。
