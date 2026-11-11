---
name: windows-path-narrowing-1113-triage
description: Windows MSVC 下 ERROR_NO_UNICODE_TRANSLATION(1113) / 0xE06D7363 崩溃的诊断与修复：path::string() 窄化、宽路径 I/O、非抛出 UTF-8 日志转换、回归测试
---

# 适用

Windows(MSVC) 构建下，程序在遍历/记录用户数据路径时抛 `std::system_error`（`No mapping for the Unicode character exists in the target multi-byte code page.`，错误 1113），或直接终止（`0xE06D7363`）。典型触发：Klei 存档根 `Documents\Klei\DoNotStarveTogether` 第一层有个名字是 GBK 字节被逐字符当 Latin-1 存下的文件夹（`U+00B7 U+00E8 U+00BF U+00F1 … U+00FA`），CP936 无映射。不是 spdlog 的问题——它只写字节。

# 步骤

## 1. 先证明机制（30 秒 MSVC 探针）

临时目录建出该名字的文件夹，然后分别调 `filename().string()` / `u8string()` / `wstring()`：`string()` 抛，另两个不抛，即确认是 `path::string()` 的 CP_ACP 窄化。

## 2. 找出真正的抛出点

- 崩溃点常常不是日志：先 grep `.string()`、`.generic_string()`，再逐个判断「输入是否来自用户数据」；`entry.path().filename().string()` 用于比较是最常见的隐形炸点。
- 只看调用栈里的模块不够（异常穿过所有帧才到 KERNELBASE）；把日志最后一行和后续应有输出对位，确认是哪个阶段。

## 3. 修法优先级

| 场景 | 改法 |
|---|---|
| 目录名比较 / 过滤 | 按 `std::filesystem::path` 分量比较，不落字符串 |
| 真读写文件 | 宽路径：`_wfopen`、`std::ifstream{path}`（C++17 起有 path 重载） |
| 必须产窄字符串（日志、配置值） | 非抛出转换：`path_to_utf8`（`u8string()`，恒成功）、`path_to_native_lossy`（ANSI 可映射时保持 ANSI，否则退回 UTF-8） |
| 遍历本身 | walk 包 try/catch，通过 `stop_reason` 回报，调用方记 warn —— 单个坏条目不能打断上层级联 |

关键：**不要**把「全链路改宽字符」当唯一解，也不要只加 catch 了事；先去掉窄化，剩下的窄口用非抛出转换兜住。

## 4. 回归测试（必须真建文件夹）

在临时目录真建出该不可表示名字的目录，断言：扫描函数不抛且返回它；`path_to_utf8` 逐码位保真；`path_from_utf8` 往返；CP936 机器上再用 try/catch 探测 `path::string()` 确实抛（非 936 机器上只验「不抛」契约，用 MESSAGE 说明跳过）。

# 陷阱

- 别在已有文件上跑 `clang-format`：本仓库 `.clang-format` 的 `NamespaceIndentation: All` 会把整个命名空间重排成整文件 diff。
- 新写的源文件保持 ASCII（含注释），否则 MSVC 报 C4819；中文放 BOM 文件或避免。
- `.log` 里出现 UTF-8 中文是该路径的预期行为；CP936 控制台 `type` 出来是乱码，不要据此改回 ANSI。
