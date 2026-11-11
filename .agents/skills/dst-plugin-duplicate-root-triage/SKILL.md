---
name: dst-plugin-duplicate-root-triage
description: DST 插件被两个搜索根重复初始化（service conflict + 0xC0000374）时：定位根顺序、确认去重规则、修复并复测
---

# 症状

Windows 上 DST 启动即崩，退出码 `3221226356`（0xC0000374 堆损坏），日志里先出现：

```
[ds-plugin] warn: also scanning injector_module_dir()/plugins as migration fallback
[DynamicPluginLoader] loaded: <rootA>\plugins\plugin_core_vm\plugin_core_vm.dll
[plugin_core_vm] service conflict ds_core_vm_get_game_lua_context
[DynamicPluginLoader] init_failed: <rootB>\plugins\plugin_core_vm\plugin_core_vm.dll
```

典型来源：`plugin_client_inject_smoke` / `plugin_client_host_smoke` / `plugin_dedicated_sim_pause` / `game_mod_throw_abort` 四个 ctest 全灭。

# 根因

`default_plugin_search_dirs()`（`src/DontStarveInjector/core/PluginPath.cpp`）返回多个根，任何两根都带同一套 `plugin_*` 包时，同一个插件会被 `LoadLibrary` 两次：host 拒绝第二次 `init`（服务名冲突），loader `close_library` 掉该副本，进程随后堆损坏。

根顺序（先到先得，`handled_stems_` 按 stem 去重，去重在**尝试前**）：

1. `DS_LUAJIT_PLUGIN_DIR`
2. `parent(modmain_path)/plugins` ← `<client_save>/unsafedata/luajit_config.json`，即游戏真正加载的 mod
3. `discover_mod_plugins_dir()`（仅 modmain_path 为空：游戏 mods + Steam UGC）
4. `injector_module_dir()/plugins`（`DS_LUAJIT_INJECTOR` / marker 指向的 Injector 目录）

# 排查步骤

1. 看日志第 4 根的 `migration fallback` 警告 → 说明存在两个根；再对比 `loaded:` 与 `init_failed:` 两行的路径，确认是同一 stem。
2. 打印两个根：`grep -rn "default_plugin_search_dirs" src/DontStarveInjector/core/PluginPath.cpp`，并在启动时看 `luajit_config.json` 的 `modmain_path`。
3. 若代码里没有 `skipped duplicate module` 逻辑（`handled_stems_` + `mark_stem_handled`），说明修复未落地。

# 修复/规避

- 已修（commit e452f895）：`load_directory` 与 `load_module_path` 都走 `mark_stem_handled()`，第一根胜出，后根打印 `skipped duplicate module (stem already handled from an earlier root)` 并跳过。
- 让仓库构建优先：`DS_LUAJIT_PLUGIN_DIR=<repo>/Mod/plugins`（序 1）；只设 `DS_LUAJIT_INJECTOR` 不改优先级。
- 别用 junction 把工坊项目录链到 repo `Mod`：`weakly_canonical` 会合并成一个根，同时让工坊打包/Steam 更新写进源码树。开发部署用 `tools/deploy_mod.py`（`cmake --install` / pre-push 自动跑）。

# 验证

1. 单测：`test_dynamic_plugin_loader.exe`（含 `duplicate_stem_across_roots`）。
2. 重新构建 `Injector`（RelWithDebInfo）→ `cmake --install` 部署 → 跑四个游戏测试：
   `ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R "plugin_dedicated_sim_pause|plugin_client_inject_smoke|plugin_client_host_smoke|game_mod_throw_abort"`
3. 游戏日志里 `service conflict` 应变成 `skipped duplicate module …`。

Windows 构建必须在 VS 环境：`call "…/VC/Auxiliary/Build/vcvars64.bat" && cmake --build …`，否则 `fatal error C1083: 无法打开包括文件: cstdint`。
