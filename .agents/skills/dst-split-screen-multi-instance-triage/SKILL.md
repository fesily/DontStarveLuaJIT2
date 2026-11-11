---
name: dst-split-screen-multi-instance-triage
description: 用 Ghidra MCP + 本地脚本判定 DST 各平台构建是否保留同进程多客户端/分屏子系统，并列出移植缺口
---

# 目标

判断某个 DST 构建（Android / Windows / macOS）是否保留"同进程多客户端 / 分屏"子系统，并给出移植缺口清单。结论必须落在具体符号/字符串/地址上。

# 0. 落点

- `list_open_programs` → 选目标；Windows 工程内路径 `/dontstarve_steam_x64.exe`，Android `/libDontStarve_android_1.1.28.so`。
- 头部信息里看 `executable_path`，确认平台与版本。Windows 是 stripped（无 C++ 符号），Android 带完整符号。
- 有 overlay address space 时，普通地址默认解析到物理空间，`_elfSectionHeaders::` 之类要带前缀。

# 1. 存在性探针（先字符串，再符号）

字符串搜索是跨构建唯一可靠的判据：这些字面量只由多实例代码生成。

```
sGameInstances            sNumGameInstances        StartGameInstance
UpdateJobThread           GameInstance::create     Created Game %d
instance_%d               S:PostUpdateTrigger      StartGameInstancesAsyncThread
GetIsSplitScreen          SendCommandToInstance    HaveMultipleViewports
```

- 全为空 ⇒ 子系统未编入（Windows 情况）。
- 命中 ⇒ 逐个落点：符号搜索对应函数，`get_xrefs_to` 找调用者。

# 2. 槽位语义（照抄不自造）

`cApplication::InitializeGameInstance` 末尾把 `sGameInstances[i]` 与 this 比较后写日志标签：

```
[2]=Server  [3]=CaveServer  [0]=Client0  [1]=Client1  其余=Overlay
```

`StartGameInstances(MultiInstanceMode)`：0=4+0，1=仅 4，2/3=0+1（真正的双客户端）。

# 3. 线程拓扑判定

- `SetNumGameInstances(n)` 里 `snprintf("UpdateJobThread_%d", i)` → 每实例一个 `JobThread<ThreadUpdate>` + `PostUpdateTrigger` 信号量。
- `tRenderJobThread::RenderThreadUpdate` 循环 `sNumGameInstances`：CreateCacheRender → 派发 DoWork → BeginFrame → 逐实例 DrawCacheRender → V(trigger)。
- `gUseThreadedRenderer`：找唯一 WRITE 点判定是否真开渲染线程。Android 1.1.28 是 Startup 硬编码 0（OneFrame 同步 DoWork+WaitUntilFinished）；Windows 是 client.ini `[GRAPHICS] use_threaded_renderer`。
- 每实例上下文一律 `__emutls`：`mActiveGameInstance / mActiveGameIndex / sDontStarveSettings / mActiveGameLibConfig / mLogName / mGetURL / mDedicatedServerMode`，由 `ScopedGameContext` 保存恢复。

# 4. 分屏标志与视口

- `cGame::StartPlaying` 里 `if (this == sGameInstances[1]) sIsSplitScreen = 1;`，`~cGame` 清零。
- `SimLuaProxy::GetViewportSizeAndSplit` 分屏时宽度 ×0.5。
- 渲染缓存是全局 `s_data_cache[mGameIndex]`（断言 `mGameIndex != -1 && mGameIndex != NumGameInstances`）。

# 5. Lua 侧

- PC 安装包只有 `splitscreenutils_pc.lua`（官方 stub，`IsSplitScreen`/`HaveMultipleViewports` 恒 false）；console 版是 `splitscreenutils.lua`。
- grep 脚本里的 native 调用点即"必须注册的 API 清单"：
  `TheSim:GetIsSplitScreen`、`GetViewportSize`、`SendCommandToInstance`、`StartGameInstance`、`Get/SetSplitScreenSessionId`、`GetViewportSizeAndSplit`、`SetViewportSplitPercentage`、`HaveMultipleViewports`、`ViewportHasPlayer`、`ShowViewport`、`SetGameInstanceAsOverlay`、`StopGameInstance`。
- `SimLuaProxy` 中每个 `lua_pushcclosure + lua_setfield` 就是注册点，按名字字符串反查方法表。

# 6. 地址落点技巧（AArch64 Android）

- 全局变量走 GOT：`adrp x8,0xf16000 / ldr x8,[x8,#off]` → 槽位 `0xF16xxx`，`read_memory` 读槽拿真实地址（`.data` 0xF35xxx / `.bss` 0xF4Fxxx）。
- 引擎→Lua 入口是 PLT thunk `0x00e9xxxx`；`get_xrefs_to <thunk>` 才是真正调用者，`get_function_xrefs` 只给 thunk 自身。
- 全局引用列表直接暴露全部读者/写者，比反编译快。

# 7. 输出

- 有/无子系统 + 判据（字符串/符号命中表）。
- 已有什么（渲染线程类、cGame/cSimulation、SimLuaProxy）与缺什么（多实例表、TLS 上下文、渲染循环、Lua API、输入/身份/存档）。
- 移植顺序：只读 Lua 接口 → 单线程双实例 PoC（内联 `cGame::Update` + 两次 DrawCacheRender）→ 线程化 → 身份/存档/会话。
- 明确标 `[INFERENCE]` 的部分（如 console 侧 `IsGameInstance` 的实例 id 取法）。
