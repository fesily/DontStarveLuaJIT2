---
name: ghidra-symbol-table-markdown-export
description: "Export Ghidra symbol tables to markdown aggregated by type (engine globals/classes, third-party libs, imports), with correct count reconciliation and unused-symbol metrics"
---

# Ghidra 符号表 Markdown 导出（按类型聚合）

1. 只用项目里**已存在**的程序（`switch_program`），不要 `load_program` 从磁盘导入；已 open 的用 `list_open_programs`，未 open 的从 `<project>.rep/idata/*/*.prp` 的 NAME 字段查。

2. 每个程序跑一段 inline 脚本导出 TSV（`run_script_inline`，脚本体不能声明方法）：
   - `FUNC\t<entry>\t<name>\t<parentNamespace>\t<size>\t<EXT|LOC>`，遍历 `FunctionManager.getFunctions(true)`；
   - **再遍历 `getExternalFunctions()`** 追加 `EXT` 行——否则本地函数数对不上 `getFunctionCount()`（差值恰为外部函数数）；
   - `SYM\t<addr>\t<name>\t<ns>\t0\t<SymbolType>\t<EXT|LOC>`，跳过自动名 `FUN_/LAB_/DAT_/caseD_/switchD_/INIT_/FINI_/thunk_FUN_`；
   - 写盘到 `build/symexport/<name>.syms.tsv`，不要靠 MCP 返回值回传大列表。

3. Python 聚合（`build/symexport/gen_symbol_md.py`）：
   - Mach-O 名字去掉一个前导下划线；Itanium 名用 `c++filt` 批量 demangle（`__Z...` 先去掉额外下划线）；
   - 分类规则**先按命名空间**（RakNet::、bt*、std::、lua、hb、OT/AAT 等），命名空间不是库时才按名字前缀；否则引擎类成员 `cLuaNetworkVariableType::lua_*` 会被误判成 Lua；
   - 平台特有族（ObjC `-[..]`、`Java_*`/`JNI_*`、`CF*`、CoreAudio、`dispatch_`/`xpc_`、`objc_*`、Android NDK）整体剔除并单列计数；注意 HarfBuzz 的 `dispatch_recurse_func<...>` 要豁免；
   - 展示名统一 `类型名::函数名`（与类标题冗余也要保留）；
   - vtable/typeinfo 统计按**地址去重**（同一地址同时有 `vtable` 与 `_ZTV...` 两个标签），Mach-O 的 `_ZTV/_ZTI` 先 demangle 再归类。

4. 未引用（悬空）符号统计：`ReferenceManager.getReferencesTo(entry)` 计数为 0；外部导入在独立 EXTERNAL 空间**永远 0 引用**，必须改成「是否存在同名本地 stub 且该 stub 被引用」判定，否则 600+/3000+ 全被误算。

5. 跨版本/跨产品比对前先确认产品同一性（字符串 + 关键类是否存在），再比名字集合；SDL2/RakNet 的差异优先怀疑「静态链接 vs dylib」，而非库 API 变化。
