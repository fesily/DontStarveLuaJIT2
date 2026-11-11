---
name: dst-mod-path-vs-cwd-diagnosis
description: DST 更新后 mod 写的文件 native 读不到/清不掉（路径错位、invalid filepath）：用 CWD+绝对路径对比定位，并用 Steam 启动多跳验证；不用于纯 Lua 逻辑 bug。
---

# DST mod 路径错位诊断（CWD vs 绝对路径）

## 何时用
- 日志显示某文件被处理了（如 `clear luajit crash file`）但磁盘上没变。
- native 组件（Injector/插件）与 mod Lua 交换同一个文件（`unsafedata/*.json`）。
- 游戏更新后“以前好好的”行为突然失效。

## 关键事实（2026-10 实测，DST 759671）
- mod 运行时进程 CWD = 存档目录 `…/<steamid>/client_save`（旧版曾是 `<游戏>/data`；专服是 `Cluster_x/<Shard>`）。
- 注入器/插件一律用绝对路径 `getExePath().parent_path().parent_path()/"data"/"unsafedata"`。
- **DST 的 io 拒绝绝对路径**：`[string "../mods/<mod>/modmain.lua"]:N: invalid filepath`，栈顶是 `[C] in function 'open'` —— 失败方式是抛错，不是返回 nil，且会把 mod 判为出错并禁用（`error calling gamepostinit` + `Disabling <mod>`）。
- 结论：跨 native/Lua 的文件必须由 native 持有（读写都走导出接口），Lua 只能用相对路径写自己树内的文件。

## 步骤
1. 枚举所有写者/读者：`grep -rn "<文件名>" src Mod`，标出每边用的是绝对还是相对路径。
2. 证明 CWD：找“同一个相对路径落在了哪个目录”。最硬证据是两边同名文件的 mtime/content 不一致（例：`<save>/unsafedata/x.json` 为 0 字节而 `<game>/data/unsafedata/x.json` 还是 `{1}`）。
3. 用备份日志做时间线：`backup/client_log/client_log_<启动时刻>.txt` 是**上一会话**日志（轮转命名），配合日志内 `[00:00:00]: Version: NNNN` 和 `Steam AppBuildID:` 对齐版本；交叉验证 `steamapps/appmanifest_322330.acf` 的 `LastUpdated`（epoch 秒）。
4. 修：native 侧加导出（参考 `GameLuaModule.cpp` 的 `luaopen_GameInjector` + `util/CrashSentinel.hpp`），Lua 只做 `pcall(GameInjector.DS_LUAJIT_xxx)`；**所有 postinit 回调内的 IO 必须 pcall**，否则一次异常就禁用整个 mod。
5. 编译/部署（本机）：VS 自带 cmake 常被沙箱挡，用 python 包装 `subprocess.run([cmake_exe, ...])`；配置目录 `builds/ninja-multi-vcpkg`，开发/联调配置是 **RelWithDebInfo**（`Mod/Injector.dll` 大小 2,029,xxx 与之对应；Release 会把 `check_crash` 整段 `#ifndef NDEBUG` 编译掉）；`cmake --install ... --config RelWithDebInfo` 前缀即 `Mod/`，而 `steamapps/workshop/content/322330/3444078585` 是指向 `Mod/` 的 junction，所以安装一次即生效。
6. 端到端验证：`start "" "steam://rungameid/322330"` 启动客户端（必须经 Steam，否则 `SteamClientLaunch` 缺失、崩溃哨兵逻辑不参与），轮询新日志出现 + `ModIndex: Load sequence finished`，再核对哨兵文件大小/内容与 `bin64/DontStarveInjector_client.log`；测完 `taskkill /F /IM dontstarve_steam_x64.exe`。
7. 副作用清理：被 `invalid filepath` 抛错过一次会把 mod 写进 `client_save/modindex` 的 bad 列表；native 的 force-enable（`AlwaysEnableMod`）在**注入成功**的那一跳会自动恢复，所以先放行注入即可。
