# Review Slice 11 — CurlRequestManager / GetURL / cCachedPingResults / cGiftingManager

> 审查日期:2026-08-08
> 二进制:`dontstarve_steam` (macOS i386, base 0x1000)
> 方法:ghidra-mcp `get_struct_layout`(G)+ idalib-mcp `decompile`(I, 会话 f9cdc808)ctor/dtor 交叉验证 + Ghidra `disassemble_function` 复核 Mutex 偏移
> 对照文档:`docs/superpowers/../../3rd/dst/game_decompiler/types_common.h`(T)+ `tier3-d-network.md`(D)
> 本次 IDA decompile 计数:6 次(4 ctor + 2 dtor,每类型 ≤2,预算内)

---

### CurlRequestManager
- 状态: **PASS**
- Ghidra 大小: 8B | 文档大小: 8B (D §9 / T line 467) | 匹配: yes
- 字段比对: 无差异。Ghidra `{pVtable@0 void*, pClientThread@4 void*}` = T `{void* pVtable; void* pClientThread;}` = D 表(0x00 pVtable / 0x04 pClientThread)。
- 证据: I ctor 0x1b8354 — `*this = &unk_4571C8`(vtable ✓);`operator new(0x124)` → `ClientThread::ClientThread` → `*(this+4) = v2`;`Thread::Start`。与 D 一致(ClientThread 292B=0x124, vtable 0x4571C8)。
- 问题清单: 无。(注:ClientThread 本体 0x124 不属本分片,未审查。)

### GetURL
- 状态: **PASS**
- Ghidra 大小: 8B | 文档大小: 8B (D §10 / T line 468) | 匹配: yes
- 字段比对: 无差异。Ghidra `{pVtable@0 void*, pHttpClient2@4 void*}` = T = D 表(0x00 pVtable / 0x04 pHttpClient2)。
- 证据: I ctor 0x1b81ea — `*this = &unk_4571AC`(vtable ✓);`operator new(4)` → `HttpClient2::HttpClient2` → `*(this+4) = v3`。与 D 一致(HttpClient2 仅 4B 分配,与报告相符)。
- 问题清单: 无。

### cCachedPingResults
- 状态: **WARN**
- Ghidra 大小: 44B | 文档大小: 44B (D §11 / T line 469, 0x2C) | 匹配: yes(大小);字段偏移/类型全匹配,仅命名前缀不一致
- 字段比对: 偏移与类型全部一致;3/6 字段名不一致(仅前缀):
  - `pM_cachedPings` (G) vs `m_cachedPings` (T/D) — 偏移 0x04, byte[16] (map 基+header, 24B) ✓
  - `pM_hashCache` (G) vs `m_hashCache` (T/D) — 偏移 0x18, byte[12] (vector, 12B) ✓
  - `nM_cachedPingSize` (G) vs `m_cachedPingSize` (T/D) — 偏移 0x28, int ✓
  - `nField_0x00`@0、`nField_0x14`@0x14、`bDirty`@0x24 — 三者名称一致 ✓
- 证据:
  - I ctor 0x14949c — 不写 +0(无 vtable ✓);`*(this+0xC)=*(this+0x10)=&this+4`(map header 自引用@+0xC, 树基+0x04 ✓);`*(this+0x14)=0`;`vector<uint>::reserve(this+0x18, v)`(vector@+0x18 ✓);`*(byte)(this+0x24)=0`(bDirty ✓);`*(this+0x28)=5000`(读 "cached_ping_size" 默认 5000 ✓)。
  - I dtor 0x149584 — `if (*(byte)(this+0x24)) SaveCached()`(bDirty@0x24 ✓);`if (*(this+0x18)) operator delete`(vector 缓冲@+0x18 ✓);`_Rb_tree<uint, pair<const uint, ushort>>::_M_erase(this, *(this+8))`(map@+0x04, 值类型 ushort ✓)。
- 问题清单: 字段命名使用 `pM_`/`nM_` 前缀,与 types_common.h 的 `m_` 约定不一致(纯命名,不影响布局;后续按名对齐工具需注意)。

### cGiftingManager
- 状态: **WARN**
- Ghidra 大小: 160B | 文档大小: 160B (D §12 / T line 470, 0xA0) | 匹配: yes(大小)
- 字段比对: 已建模字段全部正确,但 Ghidra 缺 2 个已恢复字段,且 types_common.h 该条目自相矛盾:
  - 一致: `pVtable`@0 ✓、`nField_0x04`@4 ✓、`pM_listA_next/prev`@8/12(=D `m_listA` std::list 头, 8B ✓)、`Mutex_1`@0x10 ✓、`Mutex_2`@0x68 ✓
  - Ghidra 缺失: `m_giftItems` (std::map<string, list<GiftItemStruct>>) @ 0x48..0x60、`m_unverifiedReceipts` (std::list<UnverifiedReceiptStruct>) @ 0x60..0x68 — 0x48..0x68 (32B) 在 Ghidra 中为未建模空洞
  - types_common.h 错误: `UNKNOWN_0x48[40]` 尺寸错(0x48..0x68 实际 32B,且该区域是两个已知容器而非 UNKNOWN);`Mutex Mutex_2` 隐含偏移 0x70 错误(实际 0x68);条目注释 "0xA0" 与其字段自洽和 0xA8 矛盾
- 证据:
  - I ctor 0x14c2ca + G disasm 0x14c2ca: `*this=&unk_456E38`(vtable ✓);`MOV [EDI+8]/[EDI+0xC]=&this+8`(list@+8 ✓);`LEA EBX,[EDI+0x10]; CALL Mutex::Mutex` @ 0x14c313(Mutex_1@+0x10 ✓);`[EDI+0x4C..0x5C]` map header 初始化,`[EDI+0x54]/[EDI+0x58]=&this+0x4C`(map 树基@+0x48, header@+0x4C ✓);`[EDI+0x60]/[EDI+0x64]=&this+0x60`(list@+0x60 ✓);`LEA EAX,[EDI+0x68]; CALL Mutex::Mutex` @ 0x14c361(Mutex_2@+0x68 ✓)。
  - I dtor 0x14c3ca: `_List_base<UnverifiedReceiptStruct>::_M_clear(this+0x60)`(list@+0x60 ✓);`_Rb_tree<string, pair<const string, list<GiftItemStruct>>>::_M_erase(this+0x48, *(this+0x50))`(map@+0x48, 根@+0x50, 类型 ✓);2× `Mutex::~Mutex`(逆序销毁,对应 Mutex_1@+0x10 / Mutex_2@+0x68);手工遍历 `*(this+8)` list 节点 `operator delete`(m_listA@+8 ✓)。
- 问题清单:
  1. Ghidra struct 缺 `m_giftItems`@0x48 与 `m_unverifiedReceipts`@0x60 两个字段(0x48..0x68 空洞未建模)——布局未错位但结构不完整。
  2. types_common.h `cGiftingManager` 条目有误:`UNKNOWN_0x48[40]` 应为 32B 且应拆为 m_giftItems(map, 24B) + m_unverifiedReceipts(list, 8B);`Mutex_2` 偏移应为 0x68(非 0x70);注释 total 0xA0 与字段和 0xA8 矛盾。tier3-d-network.md §12 布局正确。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| CurlRequestManager | PASS | 无(8B 完全一致,ctor 0x1b8354 验证) |
| GetURL | PASS | 无(8B 完全一致,ctor 0x1b81ea 验证) |
| cCachedPingResults | WARN | 布局/大小/偏移全对;3 字段命名前缀 `pM_`/`nM_` 与文档 `m_` 约定不一致(仅命名) |
| cGiftingManager | WARN | 大小/已建模字段正确;Ghidra 缺 m_giftItems@0x48、m_unverifiedReceipts@0x60 两字段;types_common.h 条目 UNKNOWN_0x48[40]/Mutex_2@0x70/合计 0xA0 自相矛盾(实际 0x48..0x68 为 32B 两容器,Mutex_2@0x68) |

> 结论:4 类型大小与关键偏移经 IDA ctor/dtor 交叉验证全部正确,无字段错位。需跟进的两处均在"命名/完整性"层面:cCachedPingResults 命名前缀与文档不一致(可选修);cGiftingManager 需在 Ghidra 补齐 0x48..0x68 两容器字段,并修正 types_common.h 条目(写入操作,超出本只读审查范围,仅记录)。
