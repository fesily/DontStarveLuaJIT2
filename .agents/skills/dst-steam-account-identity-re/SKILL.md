---
name: dst-steam-account-identity-re
description: "DST Steam 版账号身份/存档目录/多开(多实例)逆向:用 macOS 有符号二进制定位身份读取点,再用 Windows x64 与本机文件验证;适用于账号分析、多开、steamid 伪造/hook 点定位。"
---

# DST Steam 账号身份 & 多开 RE 流程

## 适用
- 问「游戏用了哪些账号信息」「多开怎么隔离/换账号」「hook 哪里改 steamid/persona/票」
- 不是通用 Steam 逆向，也不是纯 Lua/mod 调试

## 工具与目标
- Ghidra MCP：`connect_instance "DontStarve"`；program 用 `dontstarve_steam`（macOS x86 32-bit，143k 符号，地址=image base 0x1000 后）取符号，`dontstarve_steam_x64.exe`（stripped，仅字符串/函数）验现行 PC 行为。
- 本机实机证据：`~/Documents/Klei/DoNotStarveTogether/`（目录名=accountid；`client_log.txt` 打印 SteamID/OU_）。

## 关键符号（macOS 二进制）
| 功能 | 地址 |
|---|---|
| GameApp::InitSteam | 0xDC29 |
| cAccountManager ctor / LoadSettings / UpdateAuthToken | 0x146FF6 / 0x1474B0 / 0x14866E |
| cSteamAccountCommunication ctor / OnValidateAuthTicketResponse | 0x1BBB5C / 0x1BBFC8 |
| SimLuaProxy GetSteamIDNumber / GetFormattedSteamUserID / GetUsersName | 0xEF6EA / 0xEEFBA / 0xEF7B6 |
| cNetworkManager::GetClientDisplayName (SteamFriends vtable[0]) | 0x169D58 |
| FileSystem::EncodeString (XOR "DoNotStarveTogether") / GetDonotStarveDir | 0x25CD3F / 0x25C79A |
| cApplication::Startup（CLI 解析） | 0x88B7 |
- Windows x64：账号目录构建 `FUN_140183C10`；cached userid `FUN_140245D60`；`FUN_14028DAE0` 读 `ACCOUNT/encoded_user_cache`。

## 步骤
1. search_functions/strings：`Steam`、`Account`、`client_save`、`DoNotStarveTogether`、`Offline user ID`、`-persistent_storage_root`、`-debug_random_data`、`@steam`、`/login/RegisterSteamAccount`。
2. decompile GetSteamIDNumber/GetFormattedSteamUserID/GetUsersName 确认只用低 32 位 → 形成 `"<accountid>@steam"` 与存档目录名。
3. decompile cAccountManager ctor：offlineUserId="OU_"+steamid64；cSteamAccountCommunication ctor：netId=cNetID2(steamid64)。
4. 用 x64 二进制字符串(+`FUN_140183C10`)确认 PC 布局 `<root>/<conf_dir>/<accountid>/client_save/`。
5. 验证：本机 `client_log.txt` 应有 `SteamID: %llu`、`Offline user ID: OU_...`、`[debug_random_data] ...`；目录名 == steamid64−76561197960265728。

## 已知事实（避免重查）
- GetSteamID 的 vtable 偏移：x86=+8，x64=+0x10。
- macOS 旧构建 `client_save/` 直挂 DoNotStarveTogether 下，无 `<accountid>` 一层。
- 游戏不持久化 Steam 身份；只有 Klei token（UpdateAuthToken→settings）、会话/用户缓存（client_save/session，XOR 编码）。
- 多开隔离：`-persistent_storage_root <abs>`、`-conf_dir <name>`、`-debug_random_data`（FU_ 随机 id+NATO 名+DebugRandomDataFakeToken）、`-offline`；`+connect_steamid <base64 u64>` 写 GameLibConfig.netId。
- 无单实例互斥；同账号同时上线会被 Steam 票校验挡（ValidateAuthTicketResponse/RegisterSteamAccount 路径）。
- 换账号三路线：多 Steam 客户端实例 / steam_api 模拟器 / 进程内 hook（GetSteamID+GetPersonaName+ticket）。
