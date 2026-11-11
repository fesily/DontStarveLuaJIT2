---
name: ghidra-unused-symbol-audit
description: "Count unused/dangling symbols per binary with Ghidra MCP (refs=0 for functions/data, stub-based import usage), avoiding external-space and vtable-label artifacts."
---

# Ghidra 未使用 / 悬空符号审计

## 何时用
用户问“某个二进制有多少符号没被引用 / 悬空引用 / 死代码符号”，或在 Ghidra MCP 里要清理未被引用的函数、数据、导入。

## 口径
未使用 = `ReferenceManager.getReferencesTo(symbolAddress)` 为空（直接 call/jump + 数据指针都算引用）。必须先决定三类符号的口径，否则数字会误导：
1. 本地函数：按入口地址数引用；
2. 导入符号：在独立 EXTERNAL 地址空间，恒 0 引用，不能这样数（见下方“坑”）；
3. 数据符号：按地址去重后计数。

## 操作步骤
1. `list_open_programs` 确认目标程序已 `analyzed`（`analysis_status` 的 `analyzed=true`），否则分析中途导出会少函数。
2. 用 `run_script_inline` 跑下面的 Java 片段（脚本体会被塞进类体，**不能写方法声明**，变量必须声明，`println` 只接受字符串）。
3. 结果写成 `*.unused.tsv`（列：类型/地址/名字/命名空间/大小/标记/备注），再在本地分类汇总。

```java
import java.io.*; import java.util.*; import java.util.regex.*;
import ghidra.program.model.address.*; import ghidra.program.model.symbol.*; import ghidra.program.model.listing.*;
PrintWriter w=new PrintWriter(new FileWriter(new File("OUTDIR", NAME+".unused.tsv")));
ReferenceManager rm=currentProgram.getReferenceManager();
Pattern auto=Pattern.compile("^(LAB|DAT|UNK|SUB|PTR|FUN|thunk|caseD|switchD)_?[0-9a-f]*$|^(default|val)$");
Pattern meta=Pattern.compile("^_*(GCC_except_table|eh_frame|__ZStL8__ioinit|methods|__const)");
FunctionManager fm=currentProgram.getFunctionManager();
HashMap<String,Integer> maxRefs=new HashMap<>();
for (Function f: fm.getFunctions(true)) {      // 不含 external
  int c=0; for (Reference r: rm.getReferencesTo(f.getEntryPoint())) c++;
  String nm=f.getName(); maxRefs.merge(nm.startsWith("_")?nm.substring(1):nm,c,Math::max);
  if (c==0) w.println("FUNC\t"+f.getEntryPoint()+"\t"+nm+"\t...");
}
for (Function f: fm.getExternalFunctions()) {  // 导入：靠同名本地 stub 判定
  String nm=f.getName(); Integer mr=maxRefs.get(nm.startsWith("_")?nm.substring(1):nm);
  if (mr==null || mr==0) w.println("IMPORT\t"+f.getEntryPoint()+"\t"+nm+"\t...");
}
for (Symbol s: currentProgram.getSymbolTable().getAllSymbols(true)) {
  SymbolType t=s.getSymbolType();
  if (t==SymbolType.FUNCTION||t==SymbolType.NAMESPACE||t==SymbolType.CLASS||t==SymbolType.LIBRARY) continue;
  String nm=s.getName(); if (auto.matcher(nm).matches()||meta.matcher(nm).find()) continue;
  int c=0; for (Reference r: rm.getReferencesTo(s.getAddress())) c++;
  if (c==0) w.println("DATA\t"+s.getAddress()+"\t"+nm+"\t...");
}
w.close();
```

## 必踩的坑
- **导入恒 0 引用**：Mach-O（__stubs）和 ELF（PLT）都如此，`ReferenceIterator` 里 `isExternalAddress()` 的引用数为 0。若直接数 external functions，会得出“614/614 全未使用”的假结果。只信“同名 stub 是否被引用”。
- **函数总数对不上**：`getFunctions(true)` 排除 external，`getFunctionCount()` 包含，差值是 external functions 数；两者相加才等于程序总数。
- **vtable/typeinfo 双标签**：同一地址常同时有 `vtable`/`typeinfo` 与 `__ZTV...`/`__ZTI...`，按地址去重，否则翻倍（实测 89 行 → 65 个唯一地址）。
- **编译器元数据**：`GCC_except_table*`、`eh_frame`、`__ZStL8__ioinit`、`methods` 必须排除，r578406 有 1,763 个无引用异常表。
- **名字下划线**：Mach-O 前缀一层 `_`；判断库/元数据用 `lstrip('_')`（`__ZTV` 会剩 `_ZTV`），显示时只剥一层。
- 脚本报 `class ... not found / 找不到符号`：通常是脚本体里写了方法声明或未声明变量，重写为内联循环。

## 验证与交付
- 抽样验证：对随机未引用函数用 `search_byte_patterns` 搜其地址的小端字节，确认镜像中无指针字 → 真死代码，而不是漏建引用。
- 交付：汇总 Markdown（每个二进制的 函数/导入/数据 三行数字 + 分类样例）+ 逐条 TSV；明确写出 EXTERNAL 空间伪影不计入合计。

## 实测基线（2026-10，dst 项目）
| 二进制 | 函数未引用 | 数据未引用 | 导入未使用 |
|---|---:|---:|---:|
| Android 2.3.1 libDontStarve.so | 223 / 44,490 | 33（全编译器产物） | 0 / 593 |
| macOS r578406 | 2 / 13,665（均匿名） | 65 | 0 / 614 |
| macOS r181048 | 1 / 19,769 | 51 | 2 / 3,550（1 个无 stub） |
