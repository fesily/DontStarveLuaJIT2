---
name: dst-signature-provider-runtime-verify
description: 验证 DST 特征码 provider/插件加载改动：cmake --install 部署到 workshop、专用服 smoke harness、日志与离线工具 create/update/check 的判据
---

# 目标
验证 DontStarveLuaJIT2 的特征码 provider / 插件加载改动在**真实运行时**生效（注册 → 发布 → 解析 → hook），而不是只靠离线工具。

## 前置
- 构建目录示例：`builds/ninja-multi-vcpkg`（Ninja Multi-Config，VS2026 MSVC 14.51）。
- cmake/ninja 只在 VS 目录里可执行：cwd 设为
  `C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin`，用 `./cmake.exe` / `./ctest.exe`。
  bash 里 `cd /c/Users/...` 偶发失败，改用工具的 `cwd` 参数。

## 步骤
1. `./cmake.exe --build <build> --config RelWithDebInfo` —— 全量构建（Injector、插件、工具、测试）。
2. `./cmake.exe --install <build> --config RelWithDebInfo` —— **必须**：deploy_mod.py 优先部署到已存在的 workshop item `3444078585`，游戏加载的是那份拷贝；不 install 就是旧 DLL。
3. 专用服冒烟（无 GUI，~70 s）：
   ```
   log_level=info DS_LUAJIT_PLUGIN_DIR="<build>/src/DontStarveInjector/RelWithDebInfo/plugins" \
     python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
   ```
   通过判据：`[lg] PASS core profile scenario=present`（`LG_INJECT_OK` + `plugins ok`）。
4. 读日志（spdlog 写到 `<game>/bin64/DontStarveInjector_server.log`，默认 err 级；只有 `log_level=info` 才有 info 行）：
   ```
   grep -n "\[signature\]" DontStarveInjector_server.log | tail -30
   ```
   期望：`runtime target …`、每 owner 一条 `provider registered owner=… entries=N`、每个消费点一条 `<owner>.<name> -> 0x… (scan|cache)`；没有 `MISS owner=` / `provider rejected`。
5. 缓存复用路径：先用工具把固定缓存生成到 Mod 再 install，第二次启动应出现 `(cache)`：
   ```
   cd <build>/tools/Creater/RelWithDebInfo
   SIGNATURE_TOOL_OUTPUT_DIR="C:/Users/fesil/DontStarveLuaJIT2/Mod" ./signature_updater.exe create
   ```
   然后 install + 重跑步骤 3。

## 离线工具验收（更快的一层，先做）
```
cd <build>/tools/Creater/RelWithDebInfo
for m in create update check; do SIGNATURE_TOOL_OUTPUT_DIR=<scratch> ./signature_updater.exe $m; echo $?; done
SIGNATURE_TOOL_OUTPUT_DIR=<scratch> ./signature_updater.exe        # Auto
```
- 全 0 才算过；`check` 前后 `<scratch>/plugin_signatures_*.json` 的 md5 与 mtime 必须不变。
- 负向：空目录 `check` → exit 1 且逐项 `cache=missing-file`；手改一个 `target_rva` → exit 1 且 `cached target RVA differs`。
- 工具**不要**在仓库根执行且不带 `SIGNATURE_TOOL_OUTPUT_DIR`，否则写 `Mod/`。

## 交叉校验（强信号）
工具给出的 `target RVA` 应等于运行时 `0xVA − module base`：例如 `rpc4_signal` 工具 0x351e20 ↔ 运行时 `0x7ff7a2d61e20 − 0x7ff7a2a10000`。不一致就说明两侧用了不同定义或不同基址。

## 已知坑
- 日志只有 4 条 L0 `option schema`、core.vm `soft miss: can't find luamodule base address`，但 `[core.vm] module mapped` 仍有 → 插件一个都没加载。先查 `DynamicPluginLoader` 的包布局候选路径（应为 `<plugins>/<stem>/<stem>.dll`，历史上被写成 `<plugins>/<stem>.dll`），再查搜索根（`[ds-plugin]` 行）。
- `DS_LUAJIT_INJECTOR` 会被 bootstrap marker 覆盖；以 install 结果为准。
- 客户端专属条目（render.shadow / render.vbpool）在专用服上应显示 `not-applicable`，不是失败。
- `ctest` 全量约 9 min；`-R` 跑子集（signature 相关 + `path_narrowing`）约 2 min。`path_narrowing` 会检查 `path::string()` 收窄，新代码用 `ds::util::path_to_native_lossy` / `path_to_utf8`。
