---
name: msvc-path-utf8-narrowing-sweep
description: "Use for MSVC C++ repos where path::string() throws error 1113 on non-ANSI names: sweep filesystem path→text to u8string, wide/native host APIs, and gate regressions."
---

# 适用

C++/MSVC 项目里 `std::filesystem::path::string()` / `generic_string()` 把路径按 ANSI 代码页（如 CP936）窄化，遇到无映射码位（GBK 字节被当 Latin-1 存成文件名 U+00B7/U+00E8/…/U+00FA）会抛 `std::system_error(ERROR_NO_UNICODE_TRANSLATION == 1113)`，在无 catch 的初始化路径上直接终止进程（0xE06D7363）。本流程＝把全仓窄化调用改成 `u8string → std::string` 调用链，并加闸门防回归。

## 1. 先确认机制（不要只凭直觉）

写一个 MSVC 探针（`cl /std:c++20 /EHsc`）在同一台机器上对该名字分别调用 `.string()` / `.u8string()` / `.wstring()`：

```
 narrow threw: No mapping for the Unicode character exists in the target multi-byte code page.
 u8 ok: 20   wide ok: 10
```

同时清点存量：`grep -rn '\.string()\|\.generic_string()' --include=*.cpp --include=*.hpp src | grep -v /tests/ | awk -F: '{print $1}' | sort | uniq -c | sort -rn`。

## 2. 建立三向规则（写进一个 header，随后全仓只此一条路）

| 方向 | 用什么 |
|---|---|
| path → 文本 | `path_to_utf8`（`u8string()`）、`path_to_utf8_generic`（`generic_u8string()`，比较/键用）——全量映射，恒不抛 |
| 文本 → path | `path_from_utf8`（`MultiByteToWideChar(CP_UTF8, …)`，绝不用 CP_ACP） |
| 系统 API | Windows 宽 API（`LoadLibraryExW/W`、`_wfopen`、`std::ifstream{path}`、`GetModuleFileNameW`）；POSIX `path.native()` |
| 改不了的窄消费者 | `path_to_native_lossy`（能转 ANSI 就转、否则退 UTF-8，绝不抛）：cmd.exe 行、batch 的 ANSI 环境、引擎/第三方窄文件名、Lua 窄路径缓冲 |

header 用 `inline`（header-only）：仓库里常有只编译单个 TU 的独立 test/tool 目标，out-of-line 符号链不到。

## 3. 入站文本必须同时归一，否则编码错位

- 环境变量：`getenv` 读的是 ANSI 环境 → 改 `_wgetenv` + UTF-8 转换（否则非 ASCII 值先被代码页毁掉）。
- 命令行：`CommandLineToArgvW` 的宽 token → 同样转 UTF-8，和 `get_cmds()` 一致。
- 落盘/回读的路径文本（marker 文件、缓存）：写 UTF-8，读回 `path_from_utf8`；两侧编码必须一致。
- 结构化配置（`game_info` 的 persist_root/conf_dir/cluster/shard/ownerdir）：拼成 path 时统一 `path_from_utf8`。

## 4. 机械替换 + 必须逐处判断的例外

可以脚本批量替换的：日志/`fprintf`/report/JSON/Lua 字符串（→ `path_to_utf8`）、集合键与路径比较（→ `path_to_utf8_generic`）。

必须手改的边界：
- `LoadLibraryA/ExA` → `W`；`dlopen(p.string())` → `p.native()`。
- `fopen(p.string())` → `_wfopen(p.c_str())` / `std::ifstream{p}`；封装类给文件接口加 `const std::filesystem::path&` 重载。
- 拼接/去后缀别再走字符串：`path += ".ext"`、`path.replace_extension()`、`parent / filename`。
- 第三方要 UTF-8 的（libzip `zip_open`、Steamworks、libcurl）→ `path_to_utf8`。
- fmt/spdlog 不接受 `std::filesystem::path`：日志里一律包 `path_to_utf8(...)`（否则 C2079 `type_is_unformattable_for<path>`）。

## 5. 闸门（防止回归）

`tools/check_path_narrowing.py`：扫 `src/**`（跳过 `*/tests/*` 与被包装的 header 本身），命中 `.string()`/`.generic_string()` 即失败；确需 ANSI 的行加 `// path-narrowing-ok: <理由>`。注册成 ctest（pre-push 跑 ctest 就自动覆盖）。

反向验证一次：人为塞一处 `path.string()` → 闸门必须退出 1 并定位到行；还原后退出 0。

## 坑

- 用 `git checkout -- <file>` 还原探针时会把该文件里**所有未提交改动**一起丢掉：还原前先备份或改用精确撤销。
- `generic_string()` 语义是 `/` 分隔符：换 `path_to_utf8` 会得到 `\`，前缀/后缀比较要改用 `path_to_utf8_generic`。
- 宽字面量（`const wchar_t*`）传进 fmt 会报不可格式化，日志用窄 ASCII 常量。
- 共享的 recipe header 若被不加 Injector include 目录的 tool/test 使用，就别 include 该 header，改就地写 3 行 `u8string` 取字节。
