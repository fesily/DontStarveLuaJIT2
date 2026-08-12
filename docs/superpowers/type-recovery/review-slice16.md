# Review Slice 16 — PerfIndicator / PerfPane / cStringBuilder / cReader

- 比对基准:`docs/superpowers/../../3rd/dst/game_decompiler/types_common.h`(System 段)+ `docs/superpowers/type-recovery/tier3-e-system.md` 第 13/14/19/20 节。
- 工具:Ghidra `get_struct_layout` + `decompile_function`(只读)。idalib-mcp 会话 `f9cdc808` 不可达(`idb_list` 返回 0 会话),无法做 IDA decompile 交叉验证,改为 Ghidra decompile 验证偏移(每类型 ≤2 次)。

## 环境说明
- Ghidra 程序:`dontstarve_steam`(Mach-O x86:LE:32)。
- 4 个类型在 Ghidra 均已存在(get_struct_layout 全部命中),说明写回已完成。

---

### PerfIndicator
- 状态: PASS
- Ghidra 大小: 1048B (0x418) | 文档大小: 1048B (0x418) | 匹配: yes
- 字段比对: 无不一致。
  | 偏移 | Ghidra | types_common.h / tier3-e | 结论 |
  |---|---|---|---|
  | 0x00 | pGame `void*` | pGame `cGame*` | 一致 |
  | 0x04 | pM_strName `byte[4]` | m_strName `std::string(CoW) 4B` | 一致(4B 不透明指针表示) |
  | 0x08 | pHistory `float[256]` (1024B) | flHistory `float[256]` | 一致 |
  | 0x408 | nWriteIndex `int` | nWriteIndex `int` | 一致 |
  | 0x40C | pM_colour `byte[4]` | m_colour `Colour(4B)` | 一致 |
  | 0x410 | dwUpdateCount `uint` | nUpdateCount `uint` | 一致(命名前缀差异,无语义差异) |
  | 0x414 | dwSampleDivisor `uint` | nSampleDivisor `uint` | 一致 |
- 证据: `0xE480` PerfIndicator::Update(float) decompile — `dwUpdateCount+1`@0x410、`% dwSampleDivisor`@0x414、环形写入 `*(float*)(this + idx*4 + 8)`(idx 经 `& 0x3fffff00` 截断,对应 256 项 wrap)@0x08、`nWriteIndex+1`@0x408。与 tier3-e 字段表及环形历史语义完全吻合。
- 问题清单: 无。

### PerfPane
- 状态: PASS
- Ghidra 大小: 64B (0x40) | 文档大小: ≥48B (0x30,types_common.h 定稿 0x40) | 匹配: yes
- 字段比对: 无不一致。
  | 偏移 | Ghidra | types_common.h / tier3-e | 结论 |
  |---|---|---|---|
  | 0x00 | pVecIndicators_begin/end/cap `void*` | vecIndicators `vector<PerfIndicator*>(12B)` | 一致 |
  | 0x0C | pVecGrids_begin/end/cap `void*` | vecGrids `vector<PerfGridDef>(12B)` | 一致 |
  | 0x18 | pGame `void*` | pGame `cGame*` | 一致 |
  | 0x1C | flPosX `float` | flPosX `float = 0.1` | 一致 |
  | 0x20 | flPosY `float` | flPosY `float = 0.1` | 一致 |
  | 0x24 | flSizeX `float` | flSizeX `float = 0.8` | 一致 |
  | 0x28 | flSizeY `float` | flSizeY `float = 0.8` | 一致 |
  | 0x2C | pUNKNOWN_0x2C `byte[20]` | UNKNOWN_0x2C `uint8_t[20]` | 一致(tier3-e 标 ≥4B,types_common.h 定稿 20B → 0x40) |
- 证据: `0xE622` PerfPane::PerfPane(cGame*) decompile — 6 个 vector 指针清零、`pGame = param_2`@0x18、flPosX/Y=0.1@0x1C/0x20、flSizeX/Y=0.8@0x24/0x28,+0x2C 起未触碰。与 tier3-e 字段表完全吻合。
- 问题清单: 无(tier3-e 建议"至少 0x30",Ghidra 按 types_common.h 定稿 0x40 建,覆盖建议并一致)。

### cStringBuilder
- 状态: PASS
- Ghidra 大小: 32B (0x20) | 文档大小: 32B (0x20) | 匹配: yes
- 字段比对: 无不一致。
  | 偏移 | Ghidra | types_common.h / tier3-e | 结论 |
  |---|---|---|---|
  | 0x00 | pVtable `void*` | pVtable → 0x45BD90 | 一致 |
  | 0x04 | pBuffer `char*` | pBuffer `char*` | 一致 |
  | 0x08 | pWritePtr `char*` | pWritePtr `char*` | 一致 |
  | 0x0C | dwCapacity `uint` | nCapacity `uint` | 一致(命名差异) |
  | 0x10 | pM_str0 `byte[4]` | m_str0 `std::string(CoW)` | 一致(4B 不透明) |
  | 0x14 | pM_str1 `byte[4]` | m_str1 | 一致 |
  | 0x18 | pM_str2 `byte[4]` | m_str2 | 一致 |
  | 0x1C | pM_str3 `byte[4]` | m_str3 | 一致 |
- 证据: `0x288308` cStringBuilder::cStringBuilder(uint) decompile — `pVtable = &PTR__cStringBuilder_0045bd90`@0x00、4 个 str 均赋 `S_empty_rep_storage+0xC`(CoW 空串)@0x10..0x1C、`dwCapacity = param_1`@0x0C、`pBuffer = operator_new(cap+1)`@0x04、`pWritePtr = pBuffer`@0x08。与 tier3-e 字段表完全吻合。
- 问题清单: 无。

### cReader
- 状态: WARN
- Ghidra 大小: 17B (0x11) | 文档大小: 20B (0x14) | 匹配: no
- 字段比对: 字段名/偏移/类型全部一致;仅**尾部缺 3B padding**。
  | 偏移 | Ghidra | types_common.h / tier3-e | 结论 |
  |---|---|---|---|
  | 0x00 | pVtable `void*` | pVtable → 0x4509AC | 一致 |
  | 0x04 | nReadHead `int` | nReadHead `int` | 一致 |
  | 0x08 | dwBufferLength `uint` | nBufferLength `uint` | 一致(命名差异) |
  | 0x0C | pBuffer `void*` | pBuffer `void*` | 一致 |
  | 0x10 | bOwnsBuffer `byte` | bOwnsBuffer `byte` | 一致 |
  | 0x11..0x13 | (不存在) | (3B padding,隐含于 0x14 总大小) | **缺失** |
- 证据: `0x1C8310` cReader::~cReader() decompile — `pVtable = PTR_vtable_004509ac + 8`@0x00、`bOwnsBuffer && pBuffer → operator_delete`@0x10/0x0C。与 tier3-e 描述吻合;但 Ghidra 结构体总大小为 17B(alignment 1,无尾部 padding),而 C++ `sizeof(cReader)` 应为 20B(最大成员对齐 4)。
- 问题清单:
  1. **大小不匹配**: Ghidra 17B vs 文档/实际 20B。字段齐全且偏移正确,但缺 0x11..0x13 尾部 padding。任何按 17B 计算的容器/数组/包含结构的大小都会偏小 3B(alignment 1 使 Ghidra 无法推导真实 sizeof)。建议主 agent 将结构体大小补齐到 0x14(补 3B padding,alignment 4)。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| PerfIndicator | PASS | 无 |
| PerfPane | PASS | 无 |
| cStringBuilder | PASS | 无 |
| cReader | WARN | Ghidra 大小 17B ≠ 文档 20B,缺 0x11..0x13 尾部 3B padding |

## 备注
- idalib-mcp 会话 f9cdc808 不可达且无任何活动会话,IDA 侧交叉验证未能执行;以上证据全部来自 Ghidra decompile(只读)。
- PerfPane 的 Ghidra 布局(0x40)超过 tier3-e 报告建议的 0x30,与 types_common.h 定稿一致,视为符合预期。
