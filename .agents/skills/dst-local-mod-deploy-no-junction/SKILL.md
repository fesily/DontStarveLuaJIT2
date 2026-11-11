---
name: dst-local-mod-deploy-no-junction
description: "Use when deploying a freshly built DST LuaJIT mod tree into the game/Workshop mod dir (cmake --install, pre-push, or manual) — copy with .pkg twins, never a junction."
---

# DST 本地开发部署：复制，不要软连接

## 何时用
- 把 repo `Mod/`（构建产物）送进游戏实际加载的目录
- `cmake --install` 后游戏里还是旧版本 / 插件消失
- 想用手工软连接（junction）省事时 —— 不要

## 为什么不能 junction
工坊内容会被 Steam 差分更新、`tools/update_workshop_tags.py --push-content` 暂存、
运行时 materializer 改写。软连接让这些写入直接落进源码树。

## 一条命令
```bash
python tools/deploy_mod.py               # Mod/ -> 工坊项或 mods/<folder>，并装壳
python tools/deploy_mod.py --dry-run     # 只看计划
python tools/deploy_mod.py --target <dir> --no-shell
```

自动入口：
- `cmake --install <build> --config RelWithDebInfo`：install 规则结束时的
  `install(CODE)` 调用上述工具（`-DDS_DEPLOY_AFTER_INSTALL=OFF` 关闭，
  `-DDS_DEPLOY_MOD_DIR` / `-DDS_DEPLOY_MOD_FOLDER` 覆盖）
- git pre-push：`tools/pre_push.py` 测试通过后跑同一条 `cmake --install`
  （`--no-deploy` 跳过；部署失败只告警，唯一拦截条件是测试失败）

## 目标解析（与 install.ps1 同规则）
1. `--target`
2. `<steamapps>\workshop\content\322330\3444078585`（同库存在时）
3. `<game>\mods\<folder>`（默认 `DontStarveLuaJit2`）

壳：`bin64/windows/Winmm.dll` → `<game>\bin64\Winmm.dll`（等价 install.bat）。

## 必须记住的不变量：打包树的 .pkg 孪生
目标目录若含任何 `<名><平台模块后缀>.pkg`，就是“打包树”
（`src/DontStarveInjector/core/PackagedModule.hpp`）：
- `materialize` 按 PE 构建戳把规范名从孪生重写 → 只部署规范名 = 启动被打回旧版
- `prune_unpackaged_module` 删掉没有孪生的规范名模块 → 部署的插件被删

所以部署时对每个 loadable 模块（`pack_payload.published_name` 判定：mod 根、
`deps/`、`plugins/<stem>/` 的模块）同时写出 `.pkg` 孪生，字节一致。
`bin64/` 下的壳不算映射模块，不写孪生。

## 排错
- `failed <rel>: ...` → 游戏还在跑，模块被映射；关游戏重跑
- 部署成功但启动仍旧：确认目标树是否有遗留 `.pkg`、看
  `<game>/data/unsafedata/ds_luajit_boot.log`
- 幂等：第二次运行应输出 `0 copied, N unchanged`
