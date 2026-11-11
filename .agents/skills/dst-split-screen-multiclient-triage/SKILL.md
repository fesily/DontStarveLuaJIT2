---
name: dst-split-screen-multiclient-triage
description: 判定 DST 各平台二进制是否保留同进程多客户端/分屏子系统，并评估 Windows 移植或双进程替代方案（含 Android/Windows 锚点地址）
---

# 目标

判定某个 DST 二进制是否编入了「同进程多客户端 / 分屏」子系统，并给出 Windows 端移植需要补什么。结论必须落在实际代码/字符串证据上，不要凭平台印象。

# 0. 对象与判据

- Android `libDontStarve.so`（AARCH64，image_base 0x100000）：带符号，可当**规格书**。
- Windows `dontstarve_steam_x64.exe`：strip，只能靠字面量字符串判定子系统是否编入。
- 判定一条子系统「在」的可靠证据：`snprintf` 格式串（`UpdateJobThread_%d`、`instance_%d`、`Created Game %d`）、日志串（`GameInstance::create %2.4f`）、Lua 注册名（`GetIsSplitScreen`、`SendCommandToInstance`）、assert 串（`!sGameInstances[index]`）。这些都由代码生成，缺一个可能是巧合，全缺即未编入。

# 1. Android 侧锚点（多实例规格）

- 全局：`sGameInstances`@0xF4FC50（vector<cGame*>）、`sNumGameInstances`@0xF35DB0、`sIsSplitScreen`@0xF4FC98、`gUseThreadedRenderer`@0xF4FB08、`sRenderJobThread`@0xF4FB00。
- `SetNumGameInstances`@0x007114e0：每实例建 `UpdateJobThread_%d`（JobThread<ThreadUpdate>）+ `GameRestartThread_%d` 信号量。
- `InitializeGameInstance`@0x0070dbbc：new GameLibConfig(0x218) → 换 settings/libconfig → new cDontStarveGame(0x468) → `cGame::StartGameInstance(argc,argv)` → `InitializeOnMainThread` → `InitializeBuffers` → 按槽位打标签（0 Client0 / 1 Client1 / 2 Server / 3 CaveServer / 4 Overlay）。
- `InitializeGameInstances`@0x0070e09c 只建 4 和 0；`StartGameInstances(MultiInstanceMode)`@0x00716af8：mode0=4+0，mode1=4，mode2/3=0+1；Android 两个调用点（Startup 0x007101c4、StartGameInstancesAsyncThread::Main）都传 0。
- `StartGameInstance(int)`@0x00716884：保存/恢复 __emutls 上下文（mActiveGameInstance / mActiveGameIndex / sDontStarveSettings / mActiveGameLibConfig / mLogName / mGetURL / mDedicatedServerMode）后 `StartPlaying`。
- `RecreateGameInstance`@0x00711e50 可重建任意索引；`PrepareInitializeGameInstance`@0x0070d860 只处理 2/3（丢给 server job thread）。
- 渲染：`RenderThreadUpdate`@0x0071cd20（CreateCacheRender → 派发 DoWork → BeginFrame → DrawCacheRender → V(PostUpdateTrigger)）、`UpdateAndRender`@0x0071249c（非渲染线程路径，首帧内联 `cGame::Update`，之后按实例派发；只对槽位 0/1 做线程派发）。
- 分屏：`cGame::StartPlaying`@0x007593c8 中「自己 == sGameInstances[1] → sIsSplitScreen=1」，`~cGame` 清零；`GetViewportSizeAndSplit`@0x008a8c00 宽度 ×0.5。
- Lua：`SimLuaProxy::GetIsSplitScreen`@0x008af1b8、`StartGameInstance`@0x008af738、`SetGameInstanceAsOverlay`@0x008af95c、`GetViewportSizeAndSplit`、`SetViewportSplitPercentage`、`HaveMultipleViewports`、`ViewportHasPlayer`、`ShowViewport`。
- 每实例 Lua VM：`cSimulation::NewLuaState`@0x0088708c → `luaL_newstate()` per cSimulation。

# 2. 快速判定脚本化检查

对目标二进制依次 `search_strings`：

```
sGameInstances | sNumGameInstances | StartGameInstance | InitializeGameInstance
UpdateJobThread | GameInstance::create | Created Game | instance_%d
GetIsSplitScreen | SendCommandToInstance | HaveMultipleViewports | sIsSplitScreen
```

- 全部命中 → 子系统在，查是否被调用（`get_xrefs_to <thunk>`，看调用点传的 mode）。
- 全部未命中 → 子系统被裁掉，移植 = 补代码，不是改配置。

# 3. Windows 端落点（dontstarve_steam_x64.exe）

- `Startup` = FUN_140004760：只 new 一个 0x2a8 的 game（FUN_140006450 → param_1[3]）；无 SetNumGameInstances。
- 渲染线程是配置：`[GRAPHICS] use_threaded_renderer` → DAT_140669aa0；`IsOnRenderThread` = FUN_140002160（GetCurrentThreadId 比对 DAT_140669c9c）。
- `WindowManager::Initialize` = FUN_1403d8190 → FUN_1403e4420 → FUN_1403e8240：窗口类名硬编码 `L"opengles2.0"`（0x1405a89a0，仅一处），`RegisterClassW` 失败即 `WinCreate failed`；`hInstance = GetModuleHandleW(NULL)`。
- argv：导入 `MSVCR90.dll!__getmainargs` → 进程级 GetCommandLine。
- 可用 CLI（Startup 解析链）：`-persistent_storage_root`、`-config_dir`、`-conf_dir`、`+connect`、`+connect_netid`、`+connect_steamid`、`+connect_lobby`、`+password`、`-lan`、`-port`、`-bind_ip`、`-use_session_identifier`。
- Lua 侧：`splitscreenutils_pc.lua` 是显式 stub（`IsSplitScreen()`/`HaveMultipleViewports()` 恒 false），脚本调用点：`widgets/controls.lua:579`、`widgets/moonstormover.lua:204-206`、`screens/DebugMenuScreen.lua:27`、`components/worldreset.lua:85`（`TheSim:SendCommandToInstance`）、多处 `IsGameInstance(Instances.Player1/Player2)`。

# 4. 「同 exe 同进程跑两份」可行性

- 同路径 `LoadLibrary` 去重（按完整路径），只 refcount+1；必须换路径/文件名或 manual map。
- 先查 PE：`DllCharacteristics` 的 DYNAMICBASE、`.reloc` 大小、`.tls` 段。可重定位只是必要条件。
- 硬阻塞（按出现顺序）：窗口类名全局唯一（不改名必失败）；argv 进程级（`__getmainargs`）；静态 TLS 需自建 + 自调入口；steam_api64 / fmodex64 / libEGL 进程级单例；手柄枚举进程级。
- 结论模板：同进程两份只省「引擎多实例」一项，却新增映射/TLS/入口、argv、窗口类、单例 DLL 四类问题，并原样继承身份/存档/手柄，故不建议；除非需求是「单渲染器单窗口共享缓存」。

# 5. 双进程方案清单（推荐）

1. 两份 profile：不同 `-persistent_storage_root` / `-config_dir`；
2. 第二份带 `+connect`/`+connect_netid` 自动进服；
3. 窗口：两个无边框窗口并排，或 `SetParent` 到宿主做上下分屏；
4. 手柄：hook `XInputGetState` 按槽位过滤，或键鼠给 1、手柄给 2；
5. 第二身份：换 Steam 账号，或离线/假 steam 层。

# 6. 输出

- 先给存在性结论（在 / 被裁掉），再给证据表（地址或字符串），再给「要补什么」分层清单。
- 未逐一验证的（如 Windows 侧某全局是否 TLS、是否有单实例 mutex）标注 `[INFERENCE]`。
- 区分「槽位容量」（Android 是 5）与「已初始化实例数」（用 sGameInstances 实际长度做边界），不要混用。
