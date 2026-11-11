---
name: dst-injector-path-narrowing-crash-triage
description: DST Injector 启动即退出 0xE06D7363 / 错误 1113（No mapping for the Unicode character）：日志停在 option schema 后、core.vm 之前，根因是 std::filesystem::path::string() 窄化；含定位命令与修复约定
---

# DST Injector 路径窄化崩溃（0xE06D7363 / ERROR 1113）

## 何时用
- 开 LuaJIT 后专服/客户端**进程一启动就退出**，退出码 `0xE06D7363`，事件日志错误模块 `KERNELBASE.dll`。
- `serverlog.txt`/stderr 停在 `option schema:<key> type=Bool` 之后、`[core.vm] module mapped(required)` 之前。
- dump 的 `what()`：`No mapping for the Unicode character exists in the target multi-byte code page.`（错误 1113），抛出模块 `Injector.dll`。
- 删掉 `Documents\Klei\DoNotStarveTogether` **第一层**某个文件夹就恢复。
不适用：`0xC0000135`（缺 DLL 依赖）、`0xC0000374`（堆损坏/重复插件根）、路径 vs CWD 读不到文件。

## 机理（先确认再改）
MSVC `std::filesystem::path::string()` 按 ANSI 代码页窄化，遇到无映射码位抛 `std::system_error`。
典型触发名：GBK 字节被逐字符当 Latin-1 存下（`·è¿ñÀÏ»¢»ú` = U+00B7 U+00E8 U+00BF U+00F1 U+00CC U+00CF U+00BB U+00A2 U+00BB U+00FA），在 CP936 下 `è ¿ ñ` 等无映射。
`u8string()` / `wstring()` 恒成功；`WideCharToMultiByte(936, 0, …, NULL, NULL)` 反而**不**报错（会用 `?` 替换），所以别用它当判据——用 MSVC 实测 `path::string()`。

快速复现（不碰游戏）：建临时目录 + 该名字，跑 `probe.cpp` 打印 `filename().string()` 是否抛；`vcvars64.bat` 在 VS 安装目录（本机是 `C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\`），`cmd /c build.bat` 调 `cl /std:c++20 /EHsc`。

## 定位
1. 崩溃在 core.vm 之前 = 插件加载后、`refresh_cascade_after_plugins` → `ConfigSource::read`（`ModOverridesSource` / `SaveFileSource`）阶段。
2. 只查 `DoNotStarveTogether` **第一层**的枚举：`grep -rn "directory_iterator" src/DontStarveInjector/config`，找 `entry.path().filename().string()`。
3. 更深的层级（`client_save\world_presets(...).wsp`）不触发，说明只需修根目录那层 walk。

## 修复约定（DontStarveLuaJIT2）
- 用途分类，别一刀切换 `u8string()`：
  - 比较/去重 → 用 path 分量比较（`filename() == fs::path{name}`），**根本不窄化**。
  - 日志/消息 → `ds::util::path_to_utf8`（`util/PathText.hpp`）。
  - 仍要喂窄接口（脚本键、legacy API） → `ds::util::path_to_native_lossy`（能转 ANSI 就转，否则 UTF-8）。
  - 输入是 UTF-8 文本 → `ds::util::path_from_utf8`（Windows 窄构造按 ANSI，必须显式解码）。
  - 真实文件 I/O → 传 `std::filesystem::path` 给宽重载（`std::ifstream{path}`、`_wfopen(path.c_str(), …)`）。
- 用户数据来源的 walk 包 `try/catch`，坏条目只 `warn` 并继续（级联不能因一个目录名终止）。
- 现有实现参考：`config/path/OwnerDirs.cpp` 的 `list_owner_dirs(config_root, cluster_name, &stop_reason)`（依赖自由，可单测）；`util/PersistentString.hpp` 已改收 path。

## 验证
- 单测而非跑游戏：`test_util`（`src/DontStarveInjector/util/tests`）建临时目录 + 不可表示名，断言 walk 不抛且只返回该目录；`doctest` 里用 `CHECK_NOTHROW`。
- 构建：`cmake --build builds/ninja-multi-vcpkg --config Release --target Injector test_util`，再直接跑 `builds/ninja-multi-vcpkg/src/DontStarveInjector/util/tests/Release/test_util.exe`。
- 坑：`ctest` 里 `game_performance_unit` 可能因工作区未提交的 `tests/performance/server_load.py` 而红，先看是不是自己的改动。
- 坑：**不要**对本仓跑 `clang-format`——`.clang-format` 带 `NamespaceIndentation: All`，会把整个文件重排成巨 diff；手写保持仓库风格（命名空间不缩进）。
- 坑：新增文件含非 ASCII 注释会触发 MSVC `C4819`（CP936 编译），注释写英文/码位。
