# Review Slice 19 — CSHA1 / BaseTexture / Attribute / BaseVertexDescription

- 日期:2026-08-08
- 二进制:dontstarve_steam (macOS i386, image base 0x1000)
- 对照文档:`docs/superpowers/../../3rd/dst/game_decompiler/types_common.h`、`tier3-e-system.md` (CSHA1)、`tier3-a-rendering.md` (BaseTexture/Attribute/BaseVertexDescription)
- 交叉验证:Ghidra decompile(idalib-mcp 无可用会话,`idb_list` 为空,f9cdc808 不可达;按约束仅使用 ghidra-mcp 只读工具)
- 本 agent 只读,未做任何回写。

## 1. CSHA1

- 状态: **PASS**
- Ghidra 大小: 196B (0xC4) | 文档大小: 196B (0xC4) | 匹配: yes
- 字段比对:

| 偏移 | types_common.h / tier3-e | Ghidra (get_struct_layout) | 一致 |
|---|---|---|---|
| 0x00 | m_state uint[5] | pM_state uint[5] (20B) | yes(仅命名 pM_ 前缀) |
| 0x14 | m_count uint64 (2×uint32) | pM_count uint[2] (8B) | yes |
| 0x1C | nField_0x1C (UNKNOWN) | nField_0x1C int (4B) | yes |
| 0x20 | m_buffer uchar[64] | pM_buffer byte[64] | yes |
| 0x60 | m_digest uchar[20] | pM_digest byte[20] | yes |
| 0x80 | m_workspace (64/80 项未定) | pM_workspace byte[64] | yes(Ghidra 取 64B) |
| 0xC0 | pWorkspace void* | pWorkspace void* | yes |

- 证据:
  - ctor `0x1F6ECA` decompile:`pM_state[0..4] = 0x67452301/0xefcdab89/0x98badcfe/0x10325476/0xc3d2e1f0`、`pM_count[0]=pM_count[1]=0`、`pWorkspace = pM_workspace`(即 +0xC0 = &+0x80),与 tier3-e 证据完全一致。
  - GetHash `0x1F8646` decompile:从 `this->pM_digest`(+0x60)拷 8+8+4 = 20B,与"GetHash 从 +0x60 拷 20B"一致。
- 问题清单:
  - 字段命名差异:`m_*`(文档)vs `pM_*`(Ghidra 回写),语义相同,属命名约定不一致。
  - tier3-e 标注 workspace 长度(64 或 80 项)未定;Ghidra 采用 64B,与 0xC0 自引用指针 + 0x80 的地址差(0x40)自洽,无布局冲突。
  - +0x1C 语义仍未定(文档亦标 UNKNOWN,一致)。

## 2. BaseTexture

- 状态: **PASS**
- Ghidra 大小: 20B (0x14) | 文档大小: 20B (0x14) | 匹配: yes
- 字段比对:

| 偏移 | types_common.h / tier3-a | Ghidra (get_struct_layout) | 一致 |
|---|---|---|---|
| 0x00 | pVtable void* | pVtable void* | yes |
| 0x04 | pMipData (sMipDescription*) | pMipData void* | yes(指针类型弱化为 void*) |
| 0x08 | dwFlags uint32 | dwFlags uint | yes |
| 0x0C | UNKNOWN_0x0C | nField_0x0C int | yes(命名差异) |
| 0x10 | name std::string | pName byte[4] | yes(存储等价,类型弱化) |

- 证据:
  - ctor `0x1c4872` decompile:`pVtable = &PTR__BaseTexture_00457708`(vtable 0x457700,实例指针 +8)、`pMipData = 0`、`dwFlags = 0xffffffff`、`*(undefined**)(this+0x10) = S_empty_rep_storage + 0xc`(std::string 空串指针),与 tier3-a 证据一致;+0x0C 默认 ctor 未置位(文档亦注"未初始化",一致)。
- 问题清单:
  - +0x10 `pName` 在 Ghidra 中为 `byte[4]`,文档为 `std::string`(4B 旧 ABI 指针)。布局等价,但类型未完全表达(建议可改为 `char*` 或注明 string 语义)。
  - +0x04 文档标 `sMipDescription*`(16B 结构),Ghidra 为 `void*` — 指针宽度一致,仅类型信息缺失。

## 3. Attribute

- 状态: **PASS**
- Ghidra 大小: 12B (0x0C) | 文档大小: 12B (0x0C) | 匹配: yes
- 字段比对:

| 偏移 | types_common.h / tier3-a | Ghidra (get_struct_layout) | 一致 |
|---|---|---|---|
| 0x00 | type uint32 | dwType uint | yes(命名差异) |
| 0x04 | elementType uint32 | dwElementType uint | yes |
| 0x08 | count uint16 | wCount ushort | yes |
| 0x0A | offset uint16 | wOffset ushort | yes |

- 证据:BaseVertexDescription::Add `0x1c4dfe` decompile 中 `std::vector<BaseVertexDescription::Attribute>::push_back((Attribute*)this->pAttributes)`,元素类型为 12B Attribute(结构体 4+4+2+2 = 12,对齐 1),与文档"Set 遍历 v11+=12"步长一致。
- 问题清单: 无(仅字段名与文档风格不同,dw/w 前缀)。

## 4. BaseVertexDescription

- 状态: **PASS**
- Ghidra 大小: 24B (0x18) | 文档大小: 24B (0x18) | 匹配: yes
- 字段比对:

| 偏移 | types_common.h / tier3-a | Ghidra (get_struct_layout) | 一致 |
|---|---|---|---|
| 0x00 | pVtable void* | pVtable void* | yes |
| 0x04 | nStride uint16 | wStride ushort | yes(命名差异) |
| 0x06 | nPad uint16 | wPad ushort | yes |
| 0x08 | dwAttributeMask uint32 | dwAttributeMask uint | yes |
| 0x0C | attributes vec<Attribute> (12B) | pAttributes byte[12] | yes(布局等价,类型弱化) |

- 证据:
  - Add `0x1c4dfe` decompile:`dwAttributeMask |= 1 << (type & 0x1f)`(+0x08)、`wStride += size`(+0x04 ushort)、`push_back((Attribute*)pAttributes)`(+0x0C,12B vector),与 tier3-a 证据("Add `*(a1+8) |= 1<<a2`;push_back(a1+12)")完全一致。
- 问题清单:
  - +0x0C `pAttributes` 为 `byte[12]`,未直接表达 `std::vector<Attribute>` 类型 — Ghidra 数据类型库中已存在 `/std/vector<BaseVertexDescription::Attribute,...>` 且 Add 已按该 vector 使用,字段类型可再细化(不影响布局)。

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| CSHA1 | PASS | 命名 pM_ 前缀差异;workspace 长度按 64B 落地(文档未定) |
| BaseTexture | PASS | pName 为 byte[4] 未表达 std::string;pMipData 为 void* 未表达 sMipDescription* |
| Attribute | PASS | 无(字段名 dw/w 前缀风格差异) |
| BaseVertexDescription | PASS | pAttributes 为 byte[12] 未表达 vector<Attribute>(类型库已有该 vector) |

## 结论

4 类型全部 PASS:偏移、大小、字段类型与 types_common.h 及分片报告 (tier3-e-system.md / tier3-a-rendering.md) 完全一致;Ghidra decompile 抽查(CSHA1 ctor/GetHash、BaseTexture ctor、BaseVertexDescription::Add)逐点证实关键偏移。所有问题均为命名约定差异或类型表达弱化(byte[N] vs std::string / 具体指针类型),无字段错位、无大小不匹配,不影响布局正确性。idalib-mcp 无可用会话,未能按原计划做 IDA 侧抽查,已以 Ghidra decompile 补足证据。
