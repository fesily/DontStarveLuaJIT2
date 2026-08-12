# Review Slice 9 — AStarSearch_ulong / PathfinderComponent / cShardBroadcast / cShardManager

> 审查对象:回写到 Ghidra 的 struct 布局 vs `types_common.h` + 分片报告(tier3-b-map.md §6/§8、tier3-d-network.md §1/§2)
> 工具:ghidra-mcp get_struct_layout(search_data_types 定位) + idalib-mcp decompile(会话 f9cdc808,每类型 1 次,共 4 次 ≤ 预算)
> 只读审查,未做任何写入。

---

### AStarSearch_ulong
- 状态: **PASS**
- Ghidra 大小: 52B | 文档大小: 52B (0x34) | 匹配: yes
- 字段比对: 无不一致
  - +0x00 pVtable void* ✓ | +0x04 nStatus int ✓ | +0x08 pOpenSet byte[12] ✓ (doc `openSet` vector<sNode*>) | +0x14 pClosedSet byte[12] ✓ | +0x20 pParams void* ✓ | +0x24/+0x28/+0x2C nField_0x24/0x28/0x2C int ×3 ✓ (doc `nField[3]`) | +0x30 flSearchTime float ✓
  - 命名差异仅为 `p` 前缀(pOpenSet/pClosedSet vs doc openSet/closedSet),语义一致,可接受。
- 证据: idalib decompile 0x30497a (C2):`*a1 = &unk_464654`(vtable @ +0,与分片报告 0x464654 一致);清零覆盖 a1[2..7] = +0x08..+0x1C(openSet/closedSet 两个 12B vector);a1[9..11] = +0x24..+0x2C(nField×3)。与 Ghidra 布局逐项吻合。
- 问题清单: 无

---

### PathfinderComponent
- 状态: **FAIL**
- Ghidra 大小: 104B | 文档大小: 104B (0x68) | 匹配: yes(仅总大小)
- 字段比对: **map2 与 searches 两块整体偏移 −4/−8,node_count 字段错位/缺失**
  - +0x00 base cEntityComponent(16B) ✓ | +0x10/+0x14/+0x18 nField_0x10/0x14/0x18 ✓ | +0x64 nNextSearchId ✓
  - map1(nMap1_pad@0x1C、nMap1_color@0x20、pMap1_parent@0x24、pMap1_left@0x28、pMap1_right@0x2C)✓ — 5 个字段偏移全部正确
  - map2:**Ghidra 置于 0x30..0x40(20B 模型),真实偏移为 0x34..0x48(24B 模型)**。nMap2_pad@0x30 实为 map1 的 node_count;nMap2_color@0x34 实为 map2 的 _Compare 前缀;parent/left/right 各 −4
  - searches:**Ghidra 置于 0x44..0x54,真实偏移为 0x4C..0x60**。nSearches_pad@0x44 实为 map2 的 node_count;nSearches_color@0x48 实为 map2 node_count 邻域;parent/left/right 各 −4(累积 −8)
  - Ghidra 遗漏真实 node_count 槽位:map1@0x30、map2@0x48、searches@0x60
- 证据: idalib decompile 0x61f3c (C2) 自引用写入:
  - map1:`+0x28/+0x2C = this+0x20` → header@+0x20,清零 +0x20..+0x30(含 node_count@0x30),24B
  - map2:`+0x40/+0x44 = this+0x38` → header@**+0x38**,清零 +0x38..+0x48,24B
  - searches:`+0x58/+0x5C = this+0x50` → header@**+0x50**,清零 +0x50..+0x60,24B
  - nNextSearchId:`+0x64 = 1` ✓
  - 与分片报告一致(map1@+0x20、map2@+0x38、searches find(+0x4c)/end=+0x50、nNextSearchId@+0x64);GCC4.2 该二进制 std::map 实际为 24B(4B _Compare 前缀 + 16B header + 4B node_count),与 cShardManager 中 map 布局一致。
- 问题清单:
  1. **map2 字段整体 −4**(pMap2_left 标 0x3C,真实 0x40)
  2. **searches 字段整体 −8**(pSearches_left 标 0x50,真实 0x58)
  3. 三个 map 的 node_count 槽位(0x30/0x48/0x60)缺失或误标为下一 map 的 pad
  4. 根因:回写按 20B/RBTree 建模(0x1C→0x30→0x44),与报告/二进制 24B(0x1C→0x34→0x4C)不符;types_common.h 中 `int32_t map1[5]/map2[5]/searches[5]` 的 20B 表述同样不精确(按 24B 计算 16+12+72+4=104B 才成立)
  5. 修复建议(非本次执行):将三块 map 改为 base@0x1C/0x34/0x4C、header(color)@0x20/0x38/0x50、node_count@0x30/0x48/0x60

---

### cShardBroadcast
- 状态: **PASS**
- Ghidra 大小: 4B | 文档大小: 4B | 匹配: yes
- 字段比对: +0x00 pStr_0x00 byte[4] ✓ (doc `str_0x00[4]` std::string,4B 旧 ABI 数据指针)。命名 `p` 前缀差异可接受。
- 证据: idalib decompile 0x1a0e3a (C1):`*(_DWORD *)this = &std::string::_Rep::_S_empty_rep_storage + 12` — 仅写首字段 string 数据指针,无 vtable;cShardManager ctor(0x1a2e44)`operator new(4)` + `cShardBroadcast::cShardBroadcast(v4)` 证实分配大小 4B。
- 问题清单: 无

---

### cShardManager
- 状态: **PASS**
- Ghidra 大小: 168B | 文档大小: 168B (0xA8) | 匹配: yes
- 字段比对: 无不一致
  - +0x00 pField_0x00 byte[40] ✓ (doc `nField_0x00[40]`,覆盖 pVtable/eShardType/str_0x14/m_shardId 等) | +0x28 pM_shardPlayers byte[24] ✓ | +0x40 nField_0x40 int ✓ | +0x44 pM_incomingMigrations byte[24] ✓ | +0x5C bField_0x5C byte ✓ | +0x60 pM_restartMigrations byte[24] ✓ | +0x78 flReconnectInterval float ✓ | +0x7C Timer_1 ✓ | +0x84 nField_0x84 ✓ | +0x88 Timer_2 ✓ | +0x90/+0x94 pM_strList_next/prev ✓ (std::list 8B) | +0x98/+0x99 bField_0x98/0x99 ✓ | +0x9C pCheshireCat ✓ | +0xA0 pField_0xA0 ✓ | +0xA4 pShardBroadcast ✓
- 证据: idalib decompile 0x1a2e44 (C1):
  - m_shardPlayers:`+0x34/+0x38 = this+0x2C` → header@0x2C,map base@0x28,24B ✓
  - m_incomingMigrations:`+0x50/+0x54 = this+0x48` → header@0x48,base@0x44 ✓
  - m_restartMigrations:`+0x6C/+0x70 = this+0x64` → header@0x64,base@0x60 ✓
  - flReconnectInterval:+0x78 = 1114636288 (0x42700000 = 60.0f) ✓
  - Timer::Timer(+0x7C) 与 Timer::Timer(+0x88) ✓;m_strList 自引用 +0x90/+0x94 ✓;+0x98/+0x99 置 0 ✓;+0x9C = operator new(0x40) → tCheshireCat ✓;+0xA4 = operator new(4) → cShardBroadcast ✓
  - ctor 未写 +0x84,与文档 "UNKNOWN_0x84(未初始化)" 一致
- 问题清单: 无(首 40B 以 blob 表示而非展开字段名,与 types_common.h 一致,属已知简化)

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| AStarSearch_ulong | PASS | 无 |
| PathfinderComponent | FAIL | map2/searches 字段偏移 −4/−8;三个 map 的 node_count 槽位缺失/错位;根因 20B vs 实际 24B 的 RBTree 建模 |
| cShardBroadcast | PASS | 无 |
| cShardManager | PASS | 无(首 40B blob 为已知简化) |

**交叉验证结论**:PathfinderComponent 是唯一需要修正的类型。其余三类 Ghidra 布局与 types_common.h、分片报告、ctor 反编译三方一致。
