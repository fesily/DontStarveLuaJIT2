---
name: dst-android-build-symbol-diff
description: 判定新版 DST Android libDontStarve.so 是否被 strip / 符号少了：解析 .dynsym 做名字集合差分 + Ghidra MCP 导入对比；含 load_program 同名去重陷阱。
---

# DST Android 两版 libDontStarve.so 符号差分

## 何时用
用户拿到新版 Android APK 的 `lib/arm64-v8a/libDontStarve.so`，问“是不是 strip 了很多函数符号 / 符号比以前少”。不要看 Ghidra 的 `symbol_count` 下结论。

## 1. 先做 ELF 层（唯一可信）
直接解析 `.dynsym`/`.dynstr`（24 字节 Elf64_Sym：name,info,other,shndx,value,size），统计：
- 条目总数、`shndx!=0 && type==2` 的已定义 FUNC 数、唯一地址数、GLOBAL/WEAK 分布
- 是否有 `.symtab` / `.gnu_debugdata`（DST Android 两版都没有；只有 `.dynsym`）
- 名字集合差分：交集 / only-old / only-new，再按前缀归类（`_ZN`、`lua*/lj_`、`FT_`、`hb_`、Imgui/`Im*`）
- 同名函数的地址 delta 分布（LTO 重排 → 通常几百种 delta、几乎 0 个同址）
- `.comment` 里的 clang 版本、`readelf -S` 的 note 节差异

已测基线（1.1.28 → 2.2.1）：29,681→30,718 条；24,897→25,889 个 FUNC；交集 23,569；only-old 1,328（ImGui 1,251）；only-new 2,320（字体栈 1,921）；lua/lj 均 157；旧文件副本在 `%LOCALAPPDATA%\Temp\dst_apks\config_arm64\lib\lib\arm64-v8a\libDontStarve.so`。

## 2. Ghidra MCP 导入（注意陷阱）
- `/load_program` 有 idempotency guard：**按 DomainFile 名去重，同名会静默重开旧程序**而不报错。必须先把新文件复制成不同名（如 `libDontStarve_2.2.1.so`）再 load，否则 list_open_programs 里看不到新程序、status 却返回 success。
- headless 实例下 `import_file` / `open_program` / `list_project_files` 会报 “requires GUI mode”；只能用 `load_program`。
- 导入后 symbol 已生效可直接 `decompile_function`，不必等 auto-analysis。
- `search_functions_enhanced` 只枚举自动命名（`FUN_*`）函数，可用 `^FUN_` + `regex:true` 数未命名函数；`search_functions` 才能按名字找已命名符号。
- `run_analysis` 会 30s 超时但后台继续，用 `analysis_status` 看 `analyzing/function_count`。

## 3. 交叉校验新旧是同一程序
取一个已知符号（如 `_ZN22DontStarveInputHandler10IsPasteKeyEi`）的 ELF `st_value`，加 image base `0x100000`，应等于 Ghidra 旧程序里的地址（1.1.28：0x684f1c → 0x784f1c）。

## 4. 结论表述
- `symbol_count` 差异是 Demangler 命名空间符号造成的分析状态差异，不能作为 strip 证据。
- 地址全变 ≠ 符号丢失；应先给“同名符号重定位表”，再谈代码形状扫描。
