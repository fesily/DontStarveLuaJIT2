---
name: binding-table-selfnaming
description: 用 luaL_Reg 风格注册表给引擎绑定函数命名、纠正错位/换名，含共享桩/同名/漂移过滤与两阶段改名
---

# 用脚本注册表给 DST 风格引擎的 Lua 绑定函数命名（并可纠错）

适用：Windows/ELF/Mach-O 里存在 `{name_ptr, func_ptr, ...}` 注册表（luaL_Reg 风格），目标函数大量无名。
不需要另一侧符号；若手边有同构建的另一平台，仅用来确认类名。

## 1. 导表

```
DstExtractBindingsRows.java <out.tsv>   # table_base, index, name, func_addr
```

步长：Windows/MSVC `{name,func,0}` = 24；macOS clang `{name,func,0,0}` = 32（偶见 48）；裸 `{name,func}` = 16。
Mach-O 的表在 `__data` / `__DATA_CONST`（可能只读）→ 扫描所有“已初始化且非可执行”块，别只看可写块。
先用一个已知方法名字符串的 xref + `read_memory` 确认真实步长再定 STRIDES。

## 2. 定类名（槽位只有方法名，没有类）

按优先级：
1. **表内已具名槽位**：`X::Method` 且 base==method 的槽位，取前缀多数票；
2. **同构建另一平台同名序列表**：mac 表与 Windows 表按名字序列 LCS 对齐，取 mac 侧函数名前缀；
3. 都没有 → 放弃（DST 里剩下的就是 PUC Lua 标准库表，本来就具名，别浪费力气）。

## 3. 落地前必须过滤的三类坑

- **共享桩**：同一 `func_addr` 被多个方法名注册（ICF 折叠的空实现）→ 不能按槽位命名；
- **同名已存在**：目标名已在别的地址 → 说明要么是重载、要么早前迁移错了；整批里若该名字还出现在“待改名”集合里，先改名再补名（见 4）；
- **多类同表**：只在表内前缀一致时采用；出现多个前缀就整表跳过。

## 4. 交换/环形错位：两阶段改名

直接改成最终名会撞名（A↔B、六环旋转）。用两遍：

```
第一遍：把“基名会变的”目标全部改成 TMP_<addr>
第二遍：TMP_ -> 最终名，同时补新名、做只改命名空间的修正
```

跑完必须自检：无 `TMP_` 残留、无重名。

## 5. 纠错的三个证据源

注册表 method 名（运行时事实）+ 另一平台同构建符号 + **包装体最后调用的引擎方法名**。
三者一致才批量改；只有前两个也要先抽 3-5 个体检。**相反的证据必须当真**：
大表（200+ 槽）在两版之间会槽位漂移，出现“表说 A、体却在调 B”的比率时，一律逐函数裁决，禁止批量。

## 6. 顺带：哪些通道已经没用

- vtable 槽位：若槽位函数已全部具名（可先统计 `slots without name`），该通道为 0 产出；
- 构造函数：只能信 vtable **标签**自带类名（`PTR_~Class_…`）。deleting destructor 也存 vptr
  （用 `AND/TEST imm 1` 的删除标志区分，或看是否 call `X::~X`），派生类 ctor 还会先存基类 vtable，
  按“存的第一个 vtable 的类”命名错误率很高。

## 7. 验收

- `DstApplyNames.java <tsv>,dry` 看 renamed/skipped/missing/conflict/folded；
- 抽样反编译 4-6 个不同表的函数，确认是 `CheckPointer + luaL_check* + 引擎方法` 的形状；
- 重新导出名字统计总数与重名，并确认无 TMP_。

## 8. 应用前必查

`DstApplyNames` 作用于“当前程序”。切换过程序后一律先 `get_current_program_info` 确认；
在错的目标上跑只会整批 MISSING（无损，但要重跑）。
