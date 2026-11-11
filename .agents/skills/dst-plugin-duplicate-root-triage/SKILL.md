---
name: dst-plugin-duplicate-root-triage
description: DST 插件同一 stem 被加载两次（service conflict + 0xC0000374）时：确认唯一插件根、外部包去重、修复并复测
---

# 症状

Windows 上 DST 启动即崩，退出码 `3221226356`（0xC0000374 堆损坏），日志里先出现同一个 stem 的两个路径：

```
[DynamicPluginLoader] loaded: <rootA>\plugins\plugin_core_vm\plugin_core_vm.dll
[plugin_core_vm] service conflict ds_core_vm_get_game_lua_context
[DynamicPluginLoader] init_failed: <rootB>\plugins\plugin_core_vm\plugin_core_vm.dll
```

当前代码里 built-in 只有一个根，出现 `<rootB>` 说明第二份来自**外部启用包**
（`ExternalPluginDiscovery` 载入的其他 DST mod 的 `plugins/plugin_<stem>/`），不是多根扫描。

# 根因

同一个插件被 `LoadLibrary` 两次：host 拒绝第二次 `init`（服务名冲突），loader
`close_library` 掉该副本，进程随后堆损坏。

插件根是唯一的（`src/DontStarveInjector/core/PluginPath.cpp::default_plugin_search_dirs`）：

1. `DS_LUAJIT_PLUGIN_DIR`（必须是已存在目录）
2. 否则 `injector_module_dir()/plugins` —— 解析到的真 Injector 所在树

没有 modmain/config、`<game>/mods`、Steam UGC 或 injector 兼容回退。`handled_stems_`
按 stem 去重（**尝试前**），所以外部包与 built-in 同 stem 时后到者打印
`skipped duplicate module (stem already handled from an earlier root)` 并跳过。

# 排查步骤

1. 对比 `loaded:` 与 `init_failed:` / `skipped duplicate` 两行路径：一份在根 `plugins/`，
   另一份在外部 mod 目录 → 外部包与 built-in 撞 stem。
2. 确认根：`[ds-plugin] info: plugin root: …`（stderr），或源码
   `default_plugin_search_dirs` / `injector_module_dir`。
3. 若代码里没有 `skipped duplicate module` 逻辑（`handled_stems_` + `mark_stem_handled`），
   说明修复未落地。

# 修复/规避

- `load_directory` 与 `load_module_path` 都走 `mark_stem_handled()`，先到先得；不要移除。
- 外部包不要复用 built-in stem（`plugin_core_vm`、`plugin_manager`、`plugin_network_*` …）。
- 开发/联调要让 repo 构建优先：设 `DS_LUAJIT_PLUGIN_DIR=<repo>/Mod/plugins`；只设
  `DS_LUAJIT_INJECTOR` 时根也会跟随该模块目录（不再读存档 config）。
- 别用 junction 把工坊项目录链到 repo `Mod`：`weakly_canonical` 会合并成一个根，同时让
  工坊打包/Steam 更新写进源码树。开发部署用 `tools/deploy_mod.py`（`cmake --install` /
  pre-push 自动跑）。

# 验证

1. 单测：`test_dynamic_plugin_loader.exe`（含 `duplicate_stem_across_roots`）。
2. 重新构建 `Injector`（RelWithDebInfo）→ `cmake --install` 部署 → 跑四个游戏测试：
   `ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R "plugin_dedicated_sim_pause|plugin_client_inject_smoke|plugin_client_host_smoke|game_mod_throw_abort"`
3. 游戏日志里出现 `skipped duplicate module …` 且进程不崩，即为预期。

Windows 构建必须在 VS 环境：`call "…/VC/Auxiliary/Build/vcvars64.bat" && cmake --build …`，否则 `fatal error C1083: 无法打开包括文件: cstdint`。
