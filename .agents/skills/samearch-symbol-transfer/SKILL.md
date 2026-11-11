---
name: samearch-symbol-transfer
description: 同架构跨构建（旧符号全、新符号稀疏）函数名迁移：特征导出、六通道匹配、分层精度控制、漏判诊断、apply 与复核
---

# 同架构跨构建（旧符号全、新符号稀疏）函数名迁移

适用：一个符号完整的旧构建 + 一个符号稀疏的新构建，同 CPU 架构、同编译器族。
不适用：跨架构（用 crossarch 那套）、两侧符号都缺。

## 0. 前置

两个程序都要在 GhidraMCP 里打开且已分析完。**每次 `switch_program` 后先确认当前程序**——
错程序上跑 `DstApplyNames` 会全部 MISSING（本轮踩过两次：一次在 Linux 程序、一次在 mac 程序）。
程序名相近时尤其危险（`dontstarve_steam` = mac，`dontstarve_steam_x64_r759671.exe` = Windows）。

## 1. 特征导出（当前程序 = 要导出的那侧）

```
DstExportNames.java         <out.tsv>    # addr, end, size, qualified name, source, tags
DstExportShapes.java        <out.tsv>    # size, insn, calls, mnemonic-shape hash, callee-set hash, name
DstExportCalleeSets.java    <out.tsv>    # callee 名字集合（cal 字段是 "0x..." 字符串，比较前必须 int(c,16)）
DstExportInventory.java     <out.jsonl>  # str/imm/imq/dref/cal/ce/blocks
DstExtractBindingsRows.java <out.tsv>    # 注册表全部行：table_base, index, name, func
DstExportVtables.java       <out.tsv>    # 每槽一行：data_va, slot, func_va, name, run_base, run_len
DstExportCtorVtables.java   <out.tsv>    # ctor -> vtable
```

Mach-O：注册表在 `__data`/`__DATA_CONST`（可能只读），步长 32 或 48；ELF/Windows 常见 24；裸 16。
先 `read_memory` 看清真实步长再决定 STRIDES。

## 2. 通道（每条都要求两侧唯一）

同编译器下按精度排序：

| 通道 | 说明 | 实测精度 |
|---|---|---|
| 组合签名 `(mh, size, imm-set, ni)` | 最强；可再加 `(mh,size,ni,blocks,edges)` 并集 | **99.9%（1722/1723）** |
| `name` 同名唯一 | 定义级 | 100% |
| `bind` 注册表 LCS 对齐逐槽 | 定义级 | ~100% |
| `self` 函数日志打印自己限定名 | 精确但覆盖面小 | ~100% |
| `str` ≥10 字符、df==1 | 高 | ~100% |
| `mh` 单用 / `imm` 单用 | 弱，单通道约 84% | 需邻居确认 |

跨编译器（如 clang→MSVC）时 `mh`/`imm` 基本归零（实测 mh 49 对、imm 143 对），
只剩 `str`/`bind`/`self`/`name` + 图传播；且 `self` 与 `name` 冲突率可达 137/187，只能辅助。

## 3. 分层

- **A**：≥2 条通道指向同一 (old,new) → 直接落地。
- **C**：图传播（3×匹配 callee + 2×匹配 caller 打分，互为最优，margin ≥1）**且必须有一条签名通道支持**。
  没有这条限制时 C 的精度只有 81–85%，误配集中在同形状兄弟（`ImageWidgetProxy::SetTexture` ↔ `ImageLuaProxy::SetTexture`）。
- **B**（单通道 + 邻居）精度 92–97%，视情况。

## 4. 漏判诊断顺序（重要）

某个函数没被定位时，**先查上一跳**，不要只看最后一跳：

1. 老构建→新构建：该函数是否在 `new_old_map.tsv` 里？（本轮 `kleiloadlua` 因为 218→335 字节 + 无字符串，在这一跳就丢了）
2. 新构建→目标：该函数是否在配对表里？没有名字就没有 `name` 锚，C 层门会挡掉图传播。
3. 目标函数的 callee 是否都未配对？那它自己的 graph score = 0，永远不会被提出。

补救通道：由**已知调用者**出发对 callee 做消元（见下），或临时放宽 C 层门（精度换召回，需人工复核）。

## 5. callee 消元通道（评审生成器，不是批量通道）

对 tier-A 配对 (W,M)：mac 侧命名 callee 去掉"Windows 已有同名"→ 要求恰好 1 个 orphan；
Windows 侧未命名 callee 里按字符串交集优先、否则尺寸比最接近 1 且 margin>0.25 选一个；
排除分配器/库桩（`_`/`operator`/`std::`/`Mutex`/`Thread`/`cLogger`/`TagSet`/`RakNet`/`boost`）。

实测：844 个 tier-A 配对 → 12 条提案 → 核验 6 条只对 2 条（33%）。
噪声来源：分配器被多个孪生提成不同名字、库桩、跨类误配。
**可靠信号**：同一 (地址, 名字) 被 ≥2 个不同孪生独立提出（`KleiFile::Close` 有 3 个孪生一致）。

## 6. 应用与复核

```
DstApplyNames.java <tsv>,dry
DstApplyNames.java <tsv>,apply     # 幂等；同名已在他处会加 _<hex> 折叠后缀
```

- 交换/错位组（A↔B 互换、n 循环位移）**不能直接改名**：先全部改成 `TMP_<addr>`，再落最终名；
  应用后必须检查无 `TMP_` 残留、无重名。
- 落地后 `DstExportNames.java` 复核：名字数、重名 0、`_<hex>` 折叠数可解释。
- 精度只能靠留出集（目标侧本来就有的名字，做 base-name 归一化：去 Mach-O 前导 `_`、去 `_<hex>`、去命名空间）。

## 7. 常见坑

- `inv.jsonl` 的 `cal` 是十六进制**字符串**，和 int 地址比较会得到"零匹配"的假象。
- 图传播要倒排索引（目标侧 seed 地址 → 引用它的函数），否则 O(未匹配 old × 全部 new) 跑几分钟以上。
- `DstExportShapes` 的 mnemonic 形状把 call 折成 `CALL`，所以同编译器跨构建可比，跨编译器不可比。
- Ghidra 的 `getParameterCount()` 对无签名函数返回 0，别用它判断 ctor/dtor；
  用 MSVC 删除析构惯用法（`AND/TEST imm 1` + free）或"callee 里含 `X::~X`"来区分（`DstCtorFilter.java`）。
- vtable 标签（`PTR_~ClassName_...`）能直接给类名（`DstLabelsAt.java`）；但 vtable 槽若已全部具名，该通道无产出。
