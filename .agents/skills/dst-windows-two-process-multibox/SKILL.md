---
name: dst-windows-two-process-multibox
description: "Set up / debug two DST Windows clients as two processes (random offline identity, isolated roots, input arbitration, connect to local server); not in-process multi-instance or split-screen porting."
---

# 目标

在同一台 Windows 上用**两个进程**跑两份 DST 客户端并进同一个世界，身份用随机离线 id（不依赖真实 SteamID 绑定）。不涉及引擎多实例/分屏移植。

# 1. 身份（随机离线 id）

- 游戏内实现：`cAccountManager` 初始化函数（x64 `FUN_140245e00`）读 `ACCOUNT.debug_random_data` 或命令行 `-debug_random_data` → `mOfflineUserID="FU_<rand>"`、随机用户名、`token="DebugRandomDataFakeToken"`，同时禁用 DATA_COLLECTION。
- **前提**：整块包在 `branch != "release"` 里。用注入器的 `AppVersionDevPatch`（`src/DontStarveInjector/config/InjectorHostConfig.hpp`，env 优先）→ `plugin_core_vm.cpp replace_game_branch_flag_to_dev()` 把 `GetBuildType` 钩成 `"dev"`。
- 两进程各自随机，id 天然不同；仍建议分开 persist root。

# 2. 启动

必须从 `bin64` 启动（游戏 `SetCurrentDirectoryW("../data")`），共用同一份 bin64/data，不复制 exe。

```powershell
$game="C:\Program Files (x86)\Steam\steamapps\common\Don't Starve Together"
$exe="$game\bin64\dontstarve_steam_x64.exe"
$env:AppVersionDevPatch="1"
Start-Process $exe -WorkingDirectory "$game\bin64" -ArgumentList @("-offline","-debug_random_data","-persistent_storage_root","D:\DST\mb\p1","-conf_dir","DoNotStarveTogether")
# 等第一份进入世界，再开第二份
Start-Process $exe -WorkingDirectory "$game\bin64" -ArgumentList @("-offline","-debug_random_data","-persistent_storage_root","D:\DST\mb\p2","-conf_dir","DoNotStarveTogether","+connect","127.0.0.1:10999")
```

- `-offline` 置离线标志并强制 LAN（`[Warning] Forcing LAN only setting in offline mode.`）；两端在线/离线必须一致。
- 入服参数：`+connect <ip:port>`、`+connect_netid`、`+connect_steamid`、`+connect_lobby`、`+password`。
- 目录：`<root>/<conf_dir>/<离线id>/client_save`。
- 窗口位置：`[GRAPHICS] window_x/window_y/windowed_width/height` 会被读，但 CreateWindowExW 用 CW_USEDEFAULT，定位靠外部 SetWindowPos。

# 3. 注入器侧必改

- `src/DontStarveInjector/DontStarveInjector.cpp:170`：`DontStarveInjector_{client|server}.log` 固定名 + `basic_file_sink_st(path, true)` 截断 → 第二份清空第一份日志。改成带 PID。
- `loader/bootstrap/InjectorBootstrap.hpp` 的 `ds_luajit_boot.log` 同理。
- 跨进程安全已具备：`ProcessMutex("DontStarveInjectorSignature")` 串行化签名库+VM 替换；`PluginProcessLock` 串行化共享 plugins 树。首启建议先单跑预热签名库。
- 可选：`sdk/steam/Steam.cpp:103` 的 `steam_account_id` 取真实 SteamID；共用 persist root 时需要改读引擎 `mOfflineUserID`。

# 4. 输入仲裁（必做）

XInput 是进程级枚举，两份都看得见手柄。exe IAT 以序号导入 `XINPUT1_3`：2=GetState、3=SetState、4=GetCapabilities、5=Enable、8=GetDSoundAudioDeviceGuids。新写 `plugin_input_filter`：EarlyNative 阶段 hook 这些 IAT 槽，按 `DST_PAD_INDEX`（env/命令行）把非本进程的 `dwUserIndex` 返回 `ERROR_DEVICE_NOT_CONNECTED`（GetState 与 GetCapabilities 都要过滤）。若有 `DINPUT8.DirectInput8Create` 路径，同样在 EnumDevices/GetDeviceState 过滤。

# 5. 验收

1. 两个 `DontStarveInjector_client_<pid>.log` 互不覆盖。
2. 两份 client_log 都有 `[debug_random_data] Setting mOfflineUserID to: FU_...` 且不同。
3. 实例 2 连接成功，实例 1 玩家列表出现两个不同名字。
4. mod 配置写各自 root/<id>。
5. 手柄只驱动匹配的那个客户端。
6. 杀任一进程另一份不受影响。

# 6. 不要走的路

同进程加载两份 exe 不可行：窗口类 `L"opengles2.0"` 硬编码（x64 0x1405a89a0），`RegisterClassW` 失败即建窗失败；argv 走 MSVCR90 `__getmainargs` 读进程命令行；steam_api64/fmodex64/libEGL 为进程级单例；`.tls` 静态 TLS 需自行初始化。
