---
name: dst-injector-cdb-debug
description: 用 WinDbg cdb + 专用服 harness 调试 DontStarveInjector 的注入器/plugin_core_vm 钩子（DST 本机进程），含 cdb 命令行怪癖与确定性复现套路
---

## 适用
调试 DontStarveInjector 在 DST 进程内的注入/钩子行为（plugin_core_vm、Lua VM、解密、dump 等），或需要确定性 smoke（专用服 + 控制台注入 Lua 片段）。

## 1. 启动客户端到 cdb
- cdb：`C:\Program Files\WindowsApps\Microsoft.WinDbg_*\amd64\cdb.exe`（Store 包路径随版本变）。
- 在 `<游戏>\bin64` 下启动 `dontstarve_steam_x64.exe -debug_random_data -offline`，进程 env 至少：
  - `DS_LUAJIT_INJECTOR=<repo>\Mod\Injector.dll`（winmm 壳据此加载真模块；也可由 `data\unsafedata\ds_luajit_injector.path` 提供）
  - `lua_vm_type=game`、`dump_lua_mods=<mod 目录名>`、`AppVersionDevPatch=1`
- 启动后核对 `<游戏>\data\unsafedata\ds_luajit_boot.log`（resolve/load 结果）；插件加载行形如 `[DynamicPluginLoader] loaded: <repo>\Mod\plugins\plugin_core_vm\plugin_core_vm.dll`。
- 注意：`Workshop\content\322330\3444078585` 常是 `<repo>\Mod` 的 symlink，路径不同但同一份文件。

## 2. cdb 命令行怪癖（1.26x 实测）
- 启动脚本用 `-cf <script.txt>`；否则（`-c "$$><file"`）在部分版本里文件内容会被吞进第一条命令（表现为 `.sympath+` 收到整段文本）。脚本文件必须 **CRLF**。
- 不带 `-g -G`：`-cf` 脚本会执行，但目标停在初始断点，脚本末尾要自己 `g`。
- 带 `-g -G`：初始/最终断点被跳过（适合纯运行/只收日志），但该组合下 `-cf` 启动脚本**不执行**（实测）——需要断点就别加。
- `-logo out.log` **不抓目标 stderr**；目标 stderr 走控制台，需在启动 bat 里 `> console.txt 2>&1`。
- 断点命令里**不要用 `gu`**：在事件处理里执行目标会产生 "Some commands were skipped..."，输出错位；要看每次调用的数据，改用插件内 env 门控的 `fprintf(stderr, ...)` trace（改完再删）。

## 3. 常用符号与断点
- 符号路径：`<repo>\Mod\plugins\plugin_core_vm`（Debug 部署树）与 build tree 的 `...\Debug\plugins\plugin_core_vm`。
- 未加载模块先 `bu plugin_core_vm!GameLuaContextGame::myReader "..."`，`sxe ld:plugin_core_vm` 后再 `x plugin_core_vm!GameLuaContextGame*` / `bl` 确认解析。
- 结构化打印：`dt plugin_core_vm!GameLuaContextGame::LuaReaderWrapper @rdx`（x64 第二参数是 wrapper 指针）。

## 4. 确定性 smoke：专用服 + 控制台 Lua
`tests/plugin_server/run_dedicated_sim_pause.py` 可直接 `import` 复用：
```python
sys.path.insert(0, str(ROOT / "tests/plugin_server")); import run_dedicated_sim_pause as H
H.install_probe_mod(game_dir)
env = H.build_inject_env(game_dir, {"dump_lua_mods": "plugin_lg_probe", "lua_vm_type": "game"})
srv = H.ServerProc(game_dir, "LGPluginTest", marker_dir, env); srv.start()
# 等 token LG_SIM_PAUSED（srv.joined_log()），再逐条注入：
srv.send_lua("loadstring('-- probe\\n', '../mods/plugin_lg_probe/probe.lua')")
# 轮询目标文件而不是固定 sleep（控制台命令可能被丢弃）
srv.stop()  # 走 c_shutdown，正常退栈
```
- 控制台片段本身经引擎 `lua_load` 执行，chunkname=片段内容（含 mod 名即会命中 dump 钩子）。
- dump 输出目录：`<游戏>\data\dumped_lua_mods\`（相对进程 CWD）。

## 5. 构建/部署循环
- 先 `taskkill /F /IM cdb.exe` 与 `dontstarve_steam_x64.exe`：Debug 插件被加载时重链会 LNK1201（PDB 占用）。
- 单目标增量：`ninja -f build-Debug.ninja plugin_core_vm`（builds/ninja-multi-vcpkg，需要 vcvars64 环境；用 .bat 包一层）。
- 部署：build tree `...\Debug\plugins\plugin_core_vm\plugin_core_vm.dll` → `Mod\plugins\plugin_core_vm\`；整栈部署用 `tools/deploy_debug_client.py`。
- 收尾：删除临时 trace、启动 bat、控制台日志与产物目录，别留在仓库或 builds/。
