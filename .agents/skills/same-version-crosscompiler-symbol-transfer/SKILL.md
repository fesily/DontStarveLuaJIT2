---
name: same-version-crosscompiler-symbol-transfer
description: 同版本不同编译器构建(mac/clang Mach-O ↔ Windows/MSVC PE)之间迁移函数名:通道标定、vtable ABI 析构槽修正、ctor 定类、候选落地与校验。
---

# 同版本跨编译器符号迁移(Mach-O/clang ↔ PE/MSVC)

## 何时用
两个**同一游戏版本**的构建(不同平台/编译器)之间迁移函数名:例如 mac r759671 → Windows r759671。
不是跨版本(那要另加旧构建符号表),也不是跨架构(那是 BSim/结构对齐的领域)。

## 先决条件检查
1. 两侧程序都能在 Ghidra 里打开。headless MCP 用 `load_program_from_project`(**参数名 `path`**);
   `open_program`/项目列表需要 GUI,别浪费时间。
2. 两侧都有**每函数特征**:size / 指令数 / 块数 / 字符串集 / 立即数集 / 被调名集。
   用 `DstExportInventory.java`(单文件 jsonl,含 `n q sz ni nb str imm ce cal`)。
3. 覆盖率统计用 `DstExportNamesAll.java`(含 thunk);`DstExportNames.java` 跳过 `isThunk()` 会低估。

## 第一件事:用同名符号做 ground truth
按**末段名(tail)唯一**配对两侧名字,得到 N 百~N 千对已知同名符号。
后面每个通道都要在这批上量覆盖率与精度,**不要凭直觉采信通道**。

## 通道清单(按实测可靠性,2026-10 DST r759671 数据)

| 通道 | 实现 | 实测 |
|---|---|---|
| 字符串互唯一 | 某字符串在两库各只被 1 个函数引用 | 94.7–100% |
| 字符串严格 | rare≤3、jaccard≥0.5、margin≥1 | 94.2% |
| 被调名集合 | 共有已被命名的被调 ≥2、margin≥2 | 94.2–95.4% |
| 调用图传播 | 锚点做种,≥3 共有被调、margin≥2、迭代 4 轮 | holdout 100% |
| assert(文件,行号) | 两侧 AssertFunc(msg,line,file) 三元组;文件归一取 `source/` 之后、`\`→`/`、小写 | 100% |
| vtable 槽位 | 见下节 | 高(需 ABI 修正) |

**已被否证、别再试**:地址序位插值(函数顺序无关,窗口跨度 MB 级)、调用者名集合(0%)、
(指令数,块数) 精确桶(真配对仅 9% 落入)、类内尺寸序位(27%)、精确立即数指纹(覆盖太低)。

## vtable 对齐:ABI 前缀必须排除

| ABI | 布局 |
|---|---|
| Itanium(clang/GCC) | `[offset-to-top=0][typeinfo][D1][D0][方法0][方法1]…` |
| MSVC | `[COL=0][scalar-deleting dtor][方法0][方法1]…` |

mac 比 Windows **多一个析构槽**。按同下标直接比 = 全错(实测 0/917);排除析构槽后逐槽同名成立。

流程:
1. `DstExportVtablesViaRefs.java` 导出真 vtable(ctor 里存 vptr 引出)。**不要用 `DstExportVtables`**(它导的是指针 run,混入 dynapi 表)。
2. mac 去掉前 2 槽(off/typeinfo)+ 再跳 D1/D0;Windows 跳过 COL 与 deleting-dtor 槽;其余按同下标比。
3. 类归属:优先 **ctor 名**(`X::X`)——用 `DstVtableUsers.java` 扫全函数里指向 vtable 的引用;
   其次 vtable 内**具名槽的多数类**。两边类名一致才允许配对,再要求同名槽比例 ≥0.75~0.9 且 ≥3 槽。
4. 1:1 贪心分配(避免一个 mac 表对多个 Windows 表)。
5. 槽位目标常常**不是 Ghidra 函数**(vtable 里是原始指针),先 `DstDefineFunctionsFromList.java` 建函数,再 `rename_function_by_address`。

注意:若目标构建关了 RTTI(MSVC `/GR-`),`DstExportVtablesRtti` 会得到 0 张表(整 exe 可能只有 7 条 `.?AV`),
只能靠上面的 ctor/多数类定类。

## 候选落地与校验
1. 过滤:目标地址当前仍匿名(`FUN_`/`thunk_FUN_`)、地址唯一、名字 tail 未在目标库出现过。
2. 用 MCP 工具 `rename_function_by_address`(`function_address` + `new_name`)逐条落地;
   批量脚本 `DstApplyNames.java <tsv>,apply` 需要脚本执行开启(`GHIDRA_MCP_ALLOW_SCRIPTS=1`)。
3. **抽样复验**:`get_function_by_address` 比对;对 vtable 通道再抽 1–2 条**反编译比对字段偏移**
   (例:两侧 `setMargin` 都写 `+0x40` 才算对)。
4. 分级落地:先只落 T1/高精度 tier,再评估是否放宽。

## 何时停
- 自举链(ctor 命名 → vtable 定类 → 同类对齐)某一轮新增为 0 即收敛;
- 目标构建剩余匿名函数多是**平台壳**(Cocoa/SDL ↔ GLEW/Win32/DirectX),源库名字对它们无意义;
  此时改用目标构建**自身的锚**(assert 文件:行号、luaL_Reg 表、回调常量)或反编译体相似度。
