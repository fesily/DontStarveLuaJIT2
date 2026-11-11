---
name: ghidra-symbol-export-and-unused-audit
description: Ghidra MCP 导出大二进制符号表（按类/第三方库聚合、类型名::函数名、剔除平台族）并统计未被引用符号，含 external 引用伪影与去重口径。
---

# Ghidra 二进制符号表导出 + 未使用符号统计

适用：DST/DS 等大二进制，需要按类/第三方库聚合导出符号表，或统计“没有被引用”的符号。

## 0. 前置
- 确认 Ghidra 程序已完整 auto-analysis（`analysis_status` 的 `analyzed=true`）；**分析未完成时导出会少几千个函数**（r578406 曾把 13,665 当成最终值，实际 14,279）。
- 版本/产品识别先做：字符串里找 `PRODUCTION / OSX_STEAM / <rev> / <build>`，以及产品名（`Don't Starve` vs `Don't Starve Together`、appid 322330）。两者 mac 可执行文件都叫 `dontstarve_steam`，不要按文件名判断。

## 1. 导出（内联脚本，`run_script_inline`）
- 行格式：`FUNC\taddr\tname\tnamespace\tsize\tEXT|LOC`，追加 `SYM\taddr\tname\tns\t0\t<SymbolType>\tEXT|LOC`。
- **必须同时遍历 `fm.getExternalFunctions()`**，否则 `getFunctionCount` 与导出行数不符（差值 = 外部函数个数）。
- 过滤自动名：`(LAB|DAT|UNK|SUB|PTR|FUN|thunk|caseD|switchD)_[0-9a-f]*`、`(INIT|FINI)_\d+`、`GCC_except_table*`、`eh_frame`、`__ZStL8__ioinit`、`methods`。
- 名字处理：Mach-O 去掉一个前导下划线；Itanium 名批量 `c++filt`（Mach-O 的 `__Z...` 先去掉多余下划线）；输出始终 `类型名::函数名`（`ns + '::' + name`，即使与分组标题冗余）。

## 2. 分类（按优先级）
1. 命名空间前缀（`RakNet`、`bt`、`std`、`hb`、`zlib`…），HarfBuzz 的 `OT::/AAT::` 单独识；
2. **引擎类成员不再参与名字前缀判定**（否则 `cLuaNetworkVariableType::lua_*` 会被算成 Lua）；
3. 自由函数才按名字前缀判定（OpenSSL 全大写前缀兜底，但排除 `JNI_/DEV_`）；
4. 平台特有族整体剔除并统计：ObjC 方法、`Java_*`、`JNI_*`、Android NDK、`CF*`、CoreAudio、`objc_*`、`dispatch_/xpc_`（HarfBuzz ns 下的 `dispatch_*` 例外）。

## 3. 未使用符号统计（“悬空”符号）
- 函数：`ReferenceManager.getReferencesTo(entry)` 为空即未引用；排除入口/导出（`SymbolTable.getExternalEntryPointIterator`）。
- **导入**：external 地址空间永远 0 引用（实测 extRefs=0），不能直接数；用“是否存在同名本地 stub 且该 stub 被引用”判定。无同名 stub = 真正悬空导入。
- **数据符号按地址去重**（同一地址常有 `vtable` 与 `_ZTV...` 双标签），否则 vtable/typeinfo 数量翻倍。
- 外部数据（`_NSApp` 等）恒无引用，是伪影，单独报告不计入合计。

## 4. 验证
- 抽一个未使用函数，用 `search_byte_patterns` 搜其地址的小端字节；搜不到 ⇒ 确实没有任何指针指向它（不是 Ghidra 漏建引用）。
- 抽一个符号用 `get_function_by_address` 核对地址/名字。
