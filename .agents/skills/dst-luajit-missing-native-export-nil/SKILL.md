---
name: dst-luajit-missing-native-export-nil
description: "DST LuaJIT2 运行期 attempt to call field 'DS_LUAJIT_X' (a nil value) 崩溃：动态插件导出缺失的定位与最小 guard 修法"
---

# 症状

崩溃日志形如：

```
[string "../mods/workshop-XXXX/plugins/plugin_ne..."]:123: attempt to call field 'DS_LUAJIT_SetNextRpcInfo' (a nil value)
  scripts/networkclientrpc.lua:1663 in SendRPCToShard
  scripts/shardnetworking.lua:46 in Shard_OnShardConnected
```

用户常说“代码里明明注册了”。注册代码确实存在——问题在加载。

# 模型（先确认，再动手）

1. 导出注册在**动态模块**的 `ds_plugin_module_init` 里
   （`plugins/plugin_network_rpc/GameNetwork.cpp` → `RegisterNetworkRpcHostServices` →
   `host->register_game_injector_export(...)`），**与选项门无关**：关掉 `NetworkOpt`
   不会让导出变 nil，只会跳过 `load()`。
2. `PluginHost::register_game_injector_export` 在 `registration_open_` 之外直接返回 false
   （loader 用 `begin/end_module_registration` 包住 init）。
3. `ds::core_vm::apply_game_injector_exports` 由 `luaopen_GameInjector` 调用，发生在该
   Lua state 的 `luaL_openlibs` 末尾 —— **每个 state 快照一次**。
4. Lua-face 包发现只看 `plugins/<stem>/modinfo.lua` 是否存在
   （`Mod/plugins/init.lua`，`DS_LUAJIT_list_plugin_packages`）；`package_load.lua` 的
   `load` 只判 `ctx.injector ~= nil`，**从不检查原生模块是否加载成功**。
5. 因此唯一结构性原因：那个 DLL 这次没进内存 ——
   `[DynamicPluginLoader] load_failed(err=126/127) / abi_mismatch / missing_init /
   init_failed / skipped duplicate module`。

# 定位

- 原生插件根是唯一的（`core/PluginPath.cpp: default_plugin_search_dirs`：
  `DS_LUAJIT_PLUGIN_DIR` 或 `injector_module_dir()/plugins`）。Lua 注册表
  （`list_installed_plugin_packages`）优先列这个唯一根，只有解析不到根时才用
  `MODROOT .. "plugins/"` 提示。若原生日志的 `plugin root:` 与游戏实际加载的 mod 目录不同，
  先查 `DS_LUAJIT_INJECTOR`/marker 是否钉到了另一棵树。
- 看 `plugin_network_rpc.dll` 的实际导入：`Injector`(mangled PluginHost 导出) / `frida-gum` /
  `function_relocation` / `spdlog` / `fmt` / MSVC runtime；任一解析失败即只它加载失败。
- 让报错者给出 stderr 里的 `[DynamicPluginLoader]` 行，don't guess.

# 严重度分级

- 运行期调用（`TheNet.SendRPC*` 包装、`SpawnPrefab` 包装）→ 致命，能拖垮
  `Shard_OnShardConnected`，服务器起不来。
- load 阶段调用（`DS_LUAJIT_disable_fullgc` 等）→ 被 `host.lua` 的 `pcall(load_fn)` 包住，
  只记 Failed，不致命。

# 修法（narrowest）

在 face 入口加一次 4 行 guard，不做调用点散改、不做全局抽象：

```lua
if type(injector.DS_LUAJIT_SetNextRpcInfo) ~= "function" then
    print("[luajit][plugin] network.rpc: ... missing (native plugin_network_rpc not loaded); RPC channel hooks skipped")
    return
end
```

同一 DLL 的所有导出都要 guard（rpc 与 `network.entity` 的
`DS_LUAJIT_EntityNetWorkExtension_Register`），否则只是把崩溃点挪到第一个联网 prefab。

# 验证

- 纯 Lua 复现：`GameInjector` 只给 `DS_LUAJIT_list_plugin_packages`，stub
  `TheNet`/`bit`，`PluginHost.new():register_all({plugin})` + `resolve({NetworkOpt=true},{injector={}})`
  + `load_phase(Phase.AfterModMain)`，再 `pcall(net_index.SendRPCToShard, TheNet, 205)`。
  改前得到同一条 `modmain.lua:123` nil 错误。
- 常驻测试：`tests/plugin/plugin_host_lua_spec.lua` 里加 `test_network_rpc_missing_native_export`，
  断言 status 仍 Loaded、`net_index.SendRPCToShard` 身份未被替换、`_G.SpawnPrefab` 未被替换、
  stock 调用成功。
- 跑：`REPO_ROOT=<repo> builds/ninja-multi-vcpkg/luajit/Release/luajit.exe tests/plugin/plugin_host_lua_spec.lua`
  （测试走 `Mod/?.lua`，所以 `Mod/plugins/plugin_<stem>/` 是 gitignore 的安装产物，改完要
  从 `src/DontStarveInjector/plugins/<stem>/` 同步一份；`Mod/plugins/*.lua` 扁平 face 是 tracked，直接改）。
