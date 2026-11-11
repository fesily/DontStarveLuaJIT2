---
name: dst-macos-xarch-symbol-sync
description: i386→x86_64 DST macOS 符号迁移流程：顺序打开项目程序、导出序列/字符串/调用/绑定特征、bind+bindtab+str+strvote 通道打分与落名
---

# DST macOS 跨架构（i386→x86_64）符号同步

适用：把 DST macOS 旧版（`macos_dontstarve_steam_x86_r181048`，i386）的函数名迁移到新版（`macos_dontstarve_steam_x64_r759671`，x86_64）。**不要**用单人版 `..._single_x64_r578406` 当施主，只能作参考。

## 前提
- Ghidra headless（MCP）已开，`GHIDRA_MCP_ALLOW_SCRIPTS=1`。
- 项目内程序内部名都是 `dontstarve_steam`，不能同时打开；**顺序处理**：开一个 → 导出特征 → 关闭 → 开另一个。用 `load_program_from_project`，不要从磁盘导入。

## 步骤
1. 导出特征（inline Java，写到 `build/symmatch/mac_xarch/`，tag 由 `defaultPointerSize` 区分 `_x86`/`_x64`）：
   - `funcs.tsv`：addr/size/name/ns/source
   - `strings.tsv`：指令地址 + 被引用字符串（只取 `Data.getValue() instanceof String`）
   - `calls.tsv`：指令地址 + 调用目标
   - `bind.tsv`：脚本注册表 `{name,func,…}`，stride = 2/3/4/5/6×指针大小，run≥3，name 指针可读、func 指针指向已定义函数；输出 name/func/table_base/stride
2. `python build/symmatch/mac_xarch/match_xarch.py` 生成 `engine_matches.tsv`；通道：
   - `bind`：注册名两侧各自唯一
   - `bindtab`：按表内名字序列 LCS 对齐，逐槽同名
   - `str`：字符串在两侧各只被一个函数引用（≥10 字符）
   - `self`：函数体字符串等于自身限定名（升权）
   - 图传播（callee/caller 邻域）实测误配高，**不要应用**
3. 第二通道扩展：字符串集合投票（共享字符串计票 ≥2、Jaccard ≥0.4–0.5、双向唯一最优），只写给「目标仍未命名」或「同名但缺命名空间」的函数。
4. 应用前过滤：目标已有不同名 → 跳过（可能是新版改名）。应用用 inline Java：创建/复用 `类型::` 命名空间、`setName(short, USER_DEFINED)`、`setComment("sym:<donor> <限定名> tier=…")`；先 dry-run 再真跑，最后 `save_program`。

## 验证
- 抽查 `get_function_by_address`；按**唯一限定名**统计命中率（不要用含 thunk 的具名函数数）。
- 具名数暴涨通常是历史标签/次符号在补命名空间后变主符号，不是本轮成果；用注释前缀区分 `sym:r181048` 与 `same-arch: seed`。

## 坑
- 外部导入在 EXTERNAL 地址空间恒 0 引用，按「同名本地 stub 是否被引用」判定。
- inline 脚本不能声明方法，辅助逻辑要内联。
- Mach-O 名字多一个前导 `_`，匹配前先剥离；Itanium 名用 `c++filt` 批量 demangle（`__ZN…` 先去掉一个下划线）。
