---
name: dst-dev-mod-deploy-copy
description: "Deploy a local DST mod build into the game's live mod dir (workshop item or mods/folder) by copy — cmake --install / pre-push / deploy_mod.py, including the .pkg-twin rule"
---

# 开发构建 → 游戏 mod 目录（复制，不用 junction）

## 何时用

需要把本地构建好的包部署到 DST 实际加载的 mod 目录（开发迭代、验证 `.pkg` 布局、`cmake --install` 后“装了没效果”排查）。不用于发布上架（见 workshop 发布类技能）。

## 三条入口（同一实现）

```bash
python tools/deploy_mod.py            # 直跑：Mod/ -> 工坊项 / mods/<folder>
python tools/deploy_mod.py --dry-run  # 只打印计划
cmake --install <build> --config RelWithDebInfo   # install(CODE) 末尾自动调上面这条
python tools/pre_push.py              # 测试通过后跑同一条 cmake --install（--no-deploy 跳过）
```

cmake 选项：`-DDS_DEPLOY_AFTER_INSTALL=OFF` 关闭、`-DDS_DEPLOY_MOD_DIR=…` 指定目标、`-DDS_DEPLOY_MOD_FOLDER=…` 改 `mods/<folder>`。改了顶层 `CMakeLists.txt` 的 install 规则后必须重新 configure，否则 `builds/*/cmake_install.cmake` 里没有部署块（`grep deploy_mod.py cmake_install.cmake` 自检）。

## 目标解析（与 install.ps1 同规则）

1. `--target`；
2. `<steamapps>/workshop/content/322330/3444078585`（工坊项存在时）；
3. `<游戏>/mods/DontStarveLuaJit2`。

游戏根目录：`cmake/GameDir.cmake` 的 `GAME_DIR` → `tools/steam_env.py`（`detect_steam_root` + `find_game_by_appid`）。

## 必守规则：打包树要写 `.pkg` 孪生

目标目录含任意 `<名>.dll.pkg` 即为打包树。此时**每个部署的模块还要写成 `pack_payload.published_name(rel)`**，否则：

- `PackagedModule::materialize` 按 PE build stamp 比对，旧孪生会覆盖刚部署的规范名 → 启动还是旧版；
- `prune_unpackaged_module` 会删掉没有孪生的规范名模块 → 部署的插件“消失”。

`bin64/windows/Winmm.dll` 按发布规则没有孪生（它被 install.bat 复制进游戏 `bin64`，从不从 mod 树映射）。

## 复制侧规则

- 逐文件比内容，相同不写（幂等：二次运行 `0 copied`）。
- 跳过：`*.lib/*.exp/*.ilk/*.obj/*.log/*.bak/*.orig/*.tmp`、`update_pending/`、`.ds_plugin_update.lock`、`*.ds_materialize_tmp*`、VCS/`__pycache__`。
- 保留 `*.pdb`（调试符号解析要用）。
- 单文件 `OSError` 不致命：游戏映射着 DLL 时报 sharing violation，收集后统一提示“关掉游戏再跑”，退出码 1；`cmake`/hook 只 WARNING，不拦。

## 验证

```bash
python tests/plugin/test_deploy_mod.py       # 14 用例
# ctest 里是 plugin_deploy_mod
sha256sum "<target>/Injector.dll" "<target>/Injector.dll.pkg" Mod/Injector.dll  # 三者应一致
```

## 反模式

- 用 junction/软连接把工坊目录指向仓库 `Mod/`：Steam 更新、`--push-content` 暂存、运行时 materializer 都会写进源码树（这正是 `.pkg` 打包“影响开发”的根因）。
- 只复制规范名 DLL 到打包树就以为部署完成。
- 把 `plugins/update_pending/` 一起部署（旧的热替换残留会被加载）。
