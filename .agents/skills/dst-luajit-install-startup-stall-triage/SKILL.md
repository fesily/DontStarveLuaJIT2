---
name: dst-luajit-install-startup-stall-triage
description: "DST LuaJIT: install.ps1 后游戏加载条/补丁窗卡在 0% 的判定（首次全量特征码生成、marker/env 指向另一棵树、隐形 MessageBox），含 signature_updater 量化命令"
---

# 症状

`install.ps1` 装完后游戏加载条/补丁窗进度条卡在 0% 不动。

# 先判定：生成中还是返工

1. `<mod>/signatures_client.json` 是否存在、mtime 是否为本次启动 → 不存在/没变 = 生在内存里没落盘。
2. `bin64/DontStarveInjector_client.log` 只有 err 级（release `spdlog::set_level(err)`）：`unresolved Lua functions` / `cannot generate signatures unique from Lua base` = 生成失败 → 隐形 MessageBox。
3. `data/unsafedata/ds_luajit_boot.log` 只到 `shell(winmm): installed injector startup hook` + 屏幕上是否有标题 `patch process...` 的窗口（有=生成中，0.0% 正常；无=没走到签名阶段）。
4. 读 `ds_luajit_injector.path`：解析顺序 `DS_LUAJIT_INJECTOR` → `DS_LUAJIT_INJECTOR_DIR` → marker → mod 别名扫描（`InjectorBootstrap.cpp:472-520`），成功即重写 marker。marker 指向的不是刚装目录 → 实际加载的是另一棵树（本机测试 harness 会 env 钉到 repo `Mod/`）。

# 量化（不要猜）

```
SIGNATURE_TOOL_OUTPUT_DIR=<temp> \
  builds/ninja-multi-vcpkg/tools/Creater/RelWithDebInfo/signature_updater.exe create   # 无 DB
  ... update   # 把 DB version 改成旧值模拟游戏更新
```

- `Release` 目标目录缺 vcpkg 运行时 DLL（0xC0000135），用 `RelWithDebInfo`/`Debug`。
- 不要把 `SIGNATURE_TOOL_OUTPUT_DIR` 指到仓库 `Mod/`。
- 参考值：client+server 两目标 12.3 s（本机），单目标约 6 s。

# 已知代码事实

- 发行包不带 `signatures_*.json`（`CMakeLists.txt:450-461` + `Mod/.gitignore:7-8` + release.yaml 不生成）→ 首次启动必全量生成。
- phase1–3（nucleus 分析 20 MB 主 exe 等）在 `DontStarveSignature.cpp:335` 的 `co_yield 0` 之前跑，故进度窗整段 0.0%；且跑在主线程（`SetCurrentDirectoryW` 钩子，`DontStarveInjector.cpp:359-373`）。
- 失败 = `MessageBoxA(NULL,…)` 无 owner/非 TOPMOST，藏在游戏窗口后阻塞主线程（`DontStarveInjector.cpp:82`、`plugin_core_vm.cpp:53`、`CoreVmBootstrap.cpp:159`）。
- `SignatureJson.cpp:127-135` 回写 ofstream 无错误检查 → 目录不可写则每次启动都重生成。
- `Progress.cpp:135` 的 `PostMessage(progress_ctx.hwnd, …)`：`hwnd` 从未赋值，收窗靠 20 ms 定时器兜底。

# 修法优先级

1. 发行包直接带 `signatures_*.json`（根治首次生成）。
2. phase1–3 移到建窗前/首个 yield 前先显示「分析模块…」。
3. 失败改为写 boot log + 有 owner/TOPMOST 提示，不阻塞主线程。
4. `update_signatures` 检查流状态并记 error。
