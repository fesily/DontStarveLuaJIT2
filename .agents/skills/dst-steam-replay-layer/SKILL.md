---
name: dst-steam-replay-layer
description: 实现/扩展 DST 无 Steam 重放层（fake steam_api 插件、缓存 steamid/ticket 登录、多开身份）时用：x64 导入面、ContextInit 分发、接口版本与 vtable 槽、回调 ABI、插件挂载点；非通用 Steam 模拟器。
---

# DST Steam 重放层（fake steam layer）

## 适用
为 DST（Don't Starve Together）客户端做「脱 Steam 实例、用缓存 steamid/persona/ticket 登录」或改账号身份注入：定位 steam_api64 拦截面、写独立 EarlyNative plugin、跑 capture/replay 实验。

## 0. 判定面（x64 实测，先核对这些不变量）

- **导入面 14 个**（steam_api64）：`SteamAPI_Init/Shutdown/RunCallbacks/RestartAppIfNecessary/RegisterCallback/UnregisterCallback/RegisterCallResult/UnregisterCallResult`、`SteamAPI_GetHSteamUser`、`SteamGameServer_GetHSteamUser`、`SteamInternal_ContextInit`、`SteamInternal_CreateInterface`、`SteamInternal_FindOrCreateUserInterface`、`SteamInternal_FindOrCreateGameServerInterface`。若变多变少 → 客户端换 SDK，重新核。
- **接口版本字符串**（binary 内全量搜 `INTERFACE_VERSION` + `Steam[A-Za-z]+0[0-9]`）：SteamClient020、SteamUtils010、SteamFriends017、SteamController008、SteamMatchMaking009、SteamGameServer014、SteamNetworking006、STEAMUSERSTATS_INTERFACE_VERSION012、STEAMAPPS_INTERFACE_VERSION008、STEAMUGC_INTERFACE_VERSION016、STEAMREMOTESTORAGE_INTERFACE_VERSION016（另有 SteamUser021 字面量；实际调用按 023 形状，Valve 只追加）。
- **UGC 可为 NULL**：游戏 `InitSteam` 里 `SteamUGC()==NULL` 会打印 "SteamUGC returned NULL, Workshop functionality disabled." 并继续 —— replay 先返回 NULL 省掉最大一块模拟。

## 1. 找 InitSteam（x64 无符号）

- 搜字符串 `Steam must be running to play this game` → xref → 函数即 InitSteam（当前 FUN_140007950）。
- 顺序：`RestartAppIfNecessary(0x4EB1A)`（**x64 无 IsDebuggerPresent 分支，必 hook 返 false**）→ `SteamAPI_Init()`（返 true）→ SteamClient+0xB0 SetWarningMessageHook → SteamUtils+0x50 SetOverlayNotificationPosition(1) → SteamUserStats slot0 RequestCurrentStats（只看布尔，不等回调）→ UGC 可空。
- macOS 有符号二进制作交叉参考（`_SteamAPI_*` 符号 + vtable 槽 x86 对齐：GetSteamID=+8、GetAuthSessionTicket=+0x54 等），等价逻辑，注意 32/64 槽位移不同。
- 初始化时序：winmm 壳 → Injector `Inject()` → plugin EarlyNative `load()`（**游戏 main 之前**）→ 可安全装 IAT hook。

## 2. ContextInit 分发（最省事的接管点）

`steam_api_internal.h` 契约：
```c
static void* s[3] = { (void*)&SteamInternal_Init_X, 0, 0 };
return *(X*)SteamInternal_ContextInit(s);   // 返回 &s[2]
```
自实现：`if slot==null → ((void(*)(void*))d[0])(&d[2]); return &d[2];`（`d[0]` 内部会走被 hook 的 `SteamAPI_GetHSteamUser` + `SteamInternal_FindOrCreateUserInterface`，闭环）。
Ghidra 里看到 `SteamInternal_ContextInit(&PTR_FUN_xxx)` 后 `if (*p != 0)` 即静态块（首成员=init 函数指针）。

## 3. 游戏真正用到的槽位（反编译确认）

| 接口 | 槽 | 方法 |
|---|---|---|
| ISteamUser | +0x10 | GetSteamID()（账号目录/OU_id 来源） |
| ISteamUser | +0x68 | GetAuthSessionTicket(buf, 0x800, pcb, identity) |
| ISteamUserStats | slot0 | RequestCurrentStats() |
| ISteamClient | +0xB0 | SetWarningMessageHook(fn) |
| ISteamUtils | +0x50 / +0xF0 / +0xF8 | SetOverlayNotificationPosition / InitFilterText / FilterText |

槽位算法：按 `3rd/steam_sdk/isteam*.h` 声明顺序数第 N 个（x64 8B/槽）。仓库头文件版本低于游戏请求版本时（如 RemoteStorage 015 vs 016、Matchmaking 008 vs 009、Networking 005 vs 006、Controller 007 vs 008）→ 用 **宽槽 stub 表**（256 槽默认 stub + 定点覆盖），不要继承旧头。

## 4. 取票 → Klei 登录链（x64 位置）

- `cSteamAccountCommunication::SteamLogin` = 搜字符串 `[Steam] Auth Session Ticket requested...` 的 xref 函数（当前 FUN_1402C5D20/FUN_1402C5F00）：调 ISteamUser+0x68，buffer=this+0x1A8、size 0x800、pcb=this+0x1B4、handle 存 this+0x1B0，状态码 this+0x1B8=0xE。
- 之后 `POST /login/RegisterSteamAccount`（Klei 校验票）→ 账号 token 落到 `client_save/session/`（XOR key "DoNotStarveTogether"，`FileSystem::EncodeString`）+ `[ACCOUNT] encoded_user_cache`。
- 回调：`GetAuthSessionTicketResponse_t::k_iCallback=163`（=k_iSteamUserCallbacks 100 + 63）、`SteamServersConnected_t=101`。`CCallbackBase` = vptr / `uint8 m_nCallbackFlags@8` / `int m_iCallback@12`；**注册时必须置 flags|=0x01**（否则游戏析构不 Unregister，派发会打到已释放对象）；派发用 vtable[0] `Run(pvParam)`；CallResult 用 vtable[1] `Run(pvParam,false,hCall)`；尺寸用 vtable[2] `GetCallbackSizeBytes()`。

## 5. 账号/存档路径（replay 必须写回）

- 账号目录 = `<persistent root>/<conf_dir>/<accountid>/client_save`（conf_dir 默认 DoNotStarveTogether；`-persistent_storage_root` / `-conf_dir` 可整体隔离）。
- `accountid = steamid64 − 76561197960265728`（实测 76561198151751414 → 191485686 = 目录名；client_log 行 `SteamID: %llu` / `Offline user ID: OU_<steamid64>`）。
- 插件须在 `ds_plugin_module_init` 里把缓存的 account id 写回 `InjectorCtx::steam_account_id`（早于 refresh_cascade_after_plugins），否则 ConfigPaths 落 `<root>/0/`。

## 6. 插件落地（独立 plugin，无 L0 改动）

- 源码 `src/DontStarveInjector/plugins/plugin_steam_proxy/`；CMake `ds_add_dynamic_plugin(plugin_steam_proxy)`；部署 `Mod/plugins/plugin_steam_proxy/plugin_steam_proxy.dll`（包布局）。
- 选项：`SteamProxyMode=off|capture|replay`、`SteamProxyProfile`、`SteamProxyEnableWorkshop(false)`；`modinfo.lua` 由 `tools/bake_plugin_options.lua` 自动并入 Mod/modinfo.lua。
- hook 复用 `sdk/steam/Steam.cpp` 的 `get_plt_ita_address/hook_plt_ita`（匿名命名空间 → 抽 `util/gum_import_hook`）。
- 缓存文件：`<game>/data/unsafedata/steam_proxy/<profile>.json`：steamid64、accountid、persona、appid、ticket(hex)+size、captured_at。
- capture=转发真函数并 dump（票由游戏自己请求那次拿到）；replay=全假（Restart→false、Init→true、GetHSteamUser→1、ContextInit 自实现、接口按版本发 mock、UGC→NULL、Friends 计数 0、Networking/Matchmaking/Inventory 返 fail）。
- 别与 `-debug_random_data` 同开（会随机化 offline id/username，冲突）。

## 7. 验证锚点（跑实验而不是猜）

1. capture：`steam_proxy/default.json` ticket 非空 + `client_log` 有 `[Steam] Auth Session Ticket requested...`。
2. replay（退出 Steam 客户端、steam_api64.dll 仍在 bin64）：不弹 "Steam must be running"；`SteamID: <缓存>`、`Offline user ID: OU_<缓存>`；`Account Communication Success`（Klei 登录成功）。
3. 失败判据：`RegisterSteamAccount - OnValidateAuthTicketResponse Failure!` / `[%i] Account Failed` = 票被拒 → 回退用 Klei token/session 缓存（session 文件不动）；`Invalid SteamUser()` = ContextInit mock 未生效。
4. 票寿命/并发必须实测（可能单次/有寿命）；同票并发两进程风险最高。
