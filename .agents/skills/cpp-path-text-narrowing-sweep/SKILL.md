---
name: cpp-path-text-narrowing-sweep
description: 系统清除 C++/Windows 仓库里 path→string 的 ANSI 窄化（1113 崩溃）：盘点分类、u8string helper、宽/原生 API 替换、header-only 与 fmt/hash/大小写坑、ctest 闸门
---

# 适用

C++/Windows 仓库里 `std::filesystem::path` 与 `std::string` 混用，出现「某条路径转窄字符串时抛 1113 / 崩溃」，要系统性地清掉而不是逐点打补丁。触发信号：

- 崩溃信息 `No mapping for the Unicode character exists in the target multi-byte code page`（`ERROR_NO_UNICODE_TRANSLATION = 1113`），模块是自家 DLL，形态是 `0xE06D7363`。
- 典型诱因：NTFS 上合法但当前 ANSI 代码页（如 CP936）无法表示的目录名（GBK 字节被逐字符当 Latin-1 存下：U+00B7/U+00E8/…/U+00FA）。

# 0. 先确认方向

崩溃点是 `path → std::string`（`path::string()` / `generic_string()` 按 CP_ACP 窄化），**不是**「path 与 string 混用」。先写一个 20 行 MSVC 探针证明：同一名字 `path.string()` 抛、`path.u8string()`/`path.wstring()` 正常，再动手。

```cpp
const char8_t *weird = u8"\u00b7\u00e8\u00bf\u00f1\u00cc\u00cf\u00bb\u00a2\u00bb\u00fa";
try { auto s = fs::path{weird}.filename().string(); } catch (const std::exception &e) { puts(e.what()); }
```

# 1. 盘点

```bash
grep -rn '\.string()\|\.generic_string()' --include=*.cpp --include=*.hpp src | grep -v /tests/
grep -rn '\.string()\|\.generic_string()' --include=*.cpp --include=*.hpp src | awk -F: '{print $1}' | sort | uniq -c | sort -rn
```

按 **消费者** 分类，不要按文件：

| 消费者 | 做法 |
|---|---|
| 日志 / 诊断（spdlog、fprintf） | `path_to_utf8` / `path_to_utf8_generic` |
| 文本契约（JSON、Lua、Steamworks、libzip、HTTP、状态机字符串） | `path_to_utf8`（这些 API 按定义就是 UTF-8 文本） |
| 键 / 比较（去重集合、前缀判断） | 优先改成 path 键 / path 原生比较；确属 ASCII 常量比较才保留文本 |
| 窄 Win32/CRT（`LoadLibraryA`、`fopen`、`cmd.exe`、批处理环境） | Windows 改宽 API（`LoadLibraryExW`/`LoadLibraryW`/`_wfopen`/`std::ifstream{path}`/`GetModuleFileNameW`）；POSIX 用 `path.native()`；改不了才 `path_to_native_lossy` + 注释理由 |
| 入站文本（env、argv、Lua、JSON） | 在入口一次性转成 UTF-8 或直接 `path_from_utf8` |

经验比例（DontStarveLuaJIT2 实测 134 处）：日志 ≈48%、文本契约 ≈9%、键比较 ≈15%、其余 28%。**日志与文本契约那部分不可消除**（fmt 没有 path formatter；JSON/Lua 的定义就是文本）。

# 2. 建立唯一转换头

`util/PathText.hpp`，**header-only（`inline`）**——`tests/` 里常有独立目标单独编译单个 TU，外部符号会 LNK2019。

```cpp
inline std::string path_to_utf8(const fs::path &p);          // u8string()，恒不抛
inline std::string path_to_utf8_generic(const fs::path &p);  // generic_u8string()，'/'
inline std::string path_to_native_lossy(const fs::path &p);  // try string()，失败退 UTF-8
inline fs::path path_from_utf8(std::string_view text);       // MultiByteToWideChar(CP_UTF8)
struct PathHash { size_t operator()(const fs::path &p) const noexcept { return fs::hash_value(p); } };
```

# 3. 批量替换的注意点

- 用脚本替换，但每个锚点 `count(old)` 断言唯一；相同代码块出现两次会一次全替换，别重复断言。
- 同一文件内 `abs.string()` 之类全部是文本时，可用正则整体替换后逐行复核 diff。
- 构建驱动优先：改 2–4 个文件就编译一次，否则错误会被后续编辑遮住。

# 4. 常见坑（都被真实踩过）

- **fmt/spdlog 没有 `std::filesystem::path` formatter**：`spdlog::info("{}", some_path)` 直接编译失败（`type_is_unformattable_for<std::filesystem::path>`）。宽字面量（`const wchar_t*`）同理。必须包 `path_to_utf8`。
- **`std::hash<fs::path>` 不存在**：path 键集合要自定义 hash（`fs::hash_value`）。
- **`lexically_relative()` 在 Windows 大小写敏感**：把「前缀字符串 + 大小写不敏感比较」的 jail/path containment 检查换成它会改变判定，属于语义变更，需保留文本比较并注释。
- **成对的写/读必须同编码**：marker/缓存文件写 UTF-8，读回必须 `path_from_utf8`，否则路径含义变了。
- **带 scheme 的「路径」是文本**：如 `APP:Klei/`，先剥前缀才是路径，字段保留 `std::string`。同理 JSON/Lua 暴露的路径值属文本契约。
- **`getenv` 读的是 ANSI 环境**：要 UTF-8 就 `_wgetenv` + 转换；否则非 ASCII 值在入口已被代码页毁掉。
- **不要把 `.string()` 结果再当路径用**（`fs::path(p.string() + ".dll")`）：改成 `auto q = p; q.concat(L".dll");` 或 `p.replace_extension()`，零转换。
- **clangd/IDE 诊断可能用错标准**：没有 `char8_t`/`std::filesystem` 的报错多是编译数据库缺失，以真实构建为准。
- **别对既有文件跑 clang-format**：若 `.clang-format` 里 `NamespaceIndentation: All` 而代码未按其风格写，会整文件重排（一次踩出 8000 行 diff）；要格式化只对新文件做，或先与团队对齐。

# 5. 加闸门（关键收尾）

没有闸门就会回退。写 `tools/check_path_narrowing.py` 并注册成 ctest（pre-push 通常已经跑 ctest，于是自动覆盖）：

- 扫描源码目录，排除 `/tests/` 与转换头自身；
- 命中 `.string()` / `.generic_string()` 即失败；
- 同一行带 `// path-narrowing-ok: <理由>` 豁免；
- **做反向验证**：临时塞一处违规 → 退出码 1 并定位到行；还原 → 0。

# 6. 验证清单

1. 全量构建（Release）通过。
2. 单元测试：为新 helper 加「不可表示名字」的用例（临时目录里真建出该名字的文件夹，断言扫描/转换不抛）——在 CP936 机器上它同时验证 `path::string()` 确实会抛。
3. 全量 ctest，确认只有与本改动无关的历史失败。
4. `grep` 复核：目标目录内 `.string()/.generic_string()` 归零（测试除外）。
5. 汇报转换点数量前后对比，并说明哪些是**不可消除**的边界转换（避免把「搬家」说成「消除」）。
