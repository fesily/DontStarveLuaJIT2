# Type Recovery Review — Slice 2 (SettingFile / MultiFileSettings / cDontStarveSettings / cNetworkComponent)

- 审查者:Review2
- 日期:2026-08-08
- 对照基准:`docs/superpowers/../../3rd/dst/game_decompiler/types_common.h`(规范);分片报告 `tier3-e-system.md` §30/§31、`tier0-core.md` §3/§4
- 验证方式:ghidra-mcp `get_struct_layout` 读取 Ghidra 当前 struct;idalib-mcp(会话 f9cdc808, `dontstarve_steam` @ 0x1000)`decompile` 抽查 4 个函数(SettingFile ctor 0x285844、MultiFileSettings dtor 0x2850BC、cDontStarveSettings dtor 0xAC50、cNetworkComponent ctor 0x5adec),每类型 ≤1 次
- 全程只读,未做任何写入

---

### SettingFile
- 状态: PASS
- Ghidra 大小: 56B | 文档大小: 56B | 匹配: yes
- 字段比对: 17 字段偏移/类型/大小全部一致。仅命名前缀风格差异(语义等价,非布局差异):
  - `nMap_pad`↔文档 `map_pad`、`nMap_color`↔`map_color`、`pMap_parent/left/right`↔`map_parent/left/right`、`nMap_count`↔`map_count`、`pList_next/prev`↔`list_next/prev`、`bCfgByte0`↔`cfgByte0`、`bCfgByte2`↔`cfgByte2`、`pM_strFileName`↔`m_strFileName`
  - Ghidra `nDataSize/nField_0x04/nField_0x08` 与 tier3-e 报告 `pszData/nDataLen/nDataSize` 同为 0x00/0x04/0x08 的 4B 字段,仅命名弱化
- 证据: IDA decompile 0x285844(ctor)逐条吻合文档:
  - +0x00/+0x04/+0x08 清零(pszData/nDataLen/nDataSize)
  - map 头 @0x0C:color@0x10=0、parent@0x14=0、left@0x18=&this+0x10、right@0x1C=&this+0x10、count@0x20=0(空树自引用模式,pad@0x0C ctor 不写)
  - list @0x24:next@0x24=&this+0x24、prev@0x28=&this+0x24(哨兵自指)
  - 配置字节 +44(0x2C)=0、+45(0x2D)=0、+46(0x2E)=0、+47(0x2F)=1(bMultiKeyEnabled)
  - nUnmatched@0x30=0;`std::string::string(&+0x34, "")` 文件名 CoW string @0x34
  - 与 tier3-e §30 字段表(含 `operator new(0x38)` = 56B)完全一致
- 问题清单: 无(命名前缀差异为纯风格问题,建议统一但非错误)

### MultiFileSettings
- 状态: PASS
- Ghidra 大小: 24B | 文档大小: 24B | 匹配: yes
- 字段比对: 6 字段(nAllocPad@0x00、nColor@0x04、pParent@0x08、pLeft@0x0C、pRight@0x10、nCount@0x14)偏移/类型/顺序与 types_common.h 及 tier3-e §31 完全一致
- 证据: IDA decompile 0x2850BC(dtor):
  - `if (*((_DWORD*)this + 5))` → count@+0x14 判空;erase 循环 `while ((*((_DWORD*)this+5))-- != 1)` → **count 在 +0x14 递减**(旧 20B 布局 count@0x10 越界,已修正)
  - `_Rb_tree_rebalance_for_erase(v2, (char*)this + 4)` → 头节点传 this+4(color@0x04)
  - `_M_erase(this, *((void**)this + 2))` → root@+0x08;`*((_DWORD*)this + 3)` = left@0x0C 遍历
  - 模板参数 `_Rb_tree<string, pair<const string, SettingFile*>, _Select1st, less<string>, allocator>` = `std::map<std::string, SettingFile*>` 确认
- 问题清单: 无

### cDontStarveSettings
- 状态: PASS
- Ghidra 大小: 28B | 文档大小: 28B | 匹配: yes
- 字段比对: pVtable@0x00 + settings(MultiFileSettings 24B)@0x04,与 types_common.h 一致;连带修正(24B→28B)已在 Ghidra 落实
- 证据: IDA decompile 0xAC50(dtor):
  - `*(_DWORD*)this = &unk_45D9D8` → +0 写 vtable 指针(实际安装值 0x45D9D8)
  - `MultiFileSettings::~MultiFileSettings((char*)this + 4)` → MFS 位于 +4
  - read_memory 0x45D9D0: vtable 数组 = [0x00000000, 0x00000000, 0x0000AC50, 0x0000AC78, 0, 0, 0x0000ACB8, 0x0000ACE6];xref: 全局 0x450070 → 0x45D9D0,故安装指针 0x45D9D8 = 数组基 0x45D9D0 + 8(跳过 2 个空槽)。与文档 "vtable 0x45d9d0"、"dtor 写 PTR_vtable_00450070+8" 语义一致
- 问题清单: 无(注:文档层 tier0-core.md §3 残留旧文本 "8 字节 / 16B+count / 两个 RBTree 头",已被 types_common.h(28B)与 tier3-e §31 修正覆盖,属文档内部不一致,非 Ghidra 问题)

### cNetworkComponent
- 状态: PASS
- Ghidra 大小: 684B | 文档大小: 684B | 匹配: yes
- 字段比对: 18 字段(base_cEntityComponent 16B@0x00、pReplica3Base[344]@0x10、nField_0x168、nField_0x16C、bField_0x170、bField_0x171、pad172[2]、dwSleepingFlagsLower@0x174、dwSleepingFlagsUpper@0x178、pMOwnerGUID[8]@0x17C、wMOwnerSystemIndex@0x184、pad186[2]、pMClassifiedTargetGUID[8]@0x188、wMClassifiedTargetIndex@0x190、pad192[2]、pBitStream[276]@0x194、nSerializeState@0x2A8)偏移/类型/大小与 types_common.h 及 tier0-core §4 完全一致
- 证据: IDA decompile 0x5adec(ctor):
  - `cEntityComponent::cEntityComponent(this)` + `RakNet::Replica3::Replica3(this+16)` → 基类 @0x00/0x10;`*(_DWORD*)this = off_455538`、`*((_DWORD*)this+4) = off_4555D8`(Replica3 虚表 @0x10)
  - +0x168/+0x16C 清零、+0x170/+0x171 清零
  - `*(_QWORD*)(this+0x17C) = UNASSIGNED_RAKNET_GUID` → mOwnerGUID;`*(_QWORD*)(this+0x188) = UNASSIGNED_RAKNET_GUID` → mClassifiedTargetGUID
  - sleepingFlags @0x174/0x178 = -1(0xFFFFFFFF)
  - `RakNet::BitStream::BitStream(this+0x194)` + nSerializeState@0x2A8 = 0 → 总大小 684B 收口
- 问题清单: 无(观察:ctor 对 +0x184/+0x190 做整 dword 写(覆盖 ushort 索引 + 2B pad),`dword_46A790` 所在段不可读故值未知;不影响偏移,pad 字节随索引一并初始化,布局无错位)

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| SettingFile | PASS | 无;仅字段命名前缀风格差异(nMap_pad 等) |
| MultiFileSettings | PASS | 无;24B map 头(pad@0,color@4,parent@8,left@0xC,right@0x10,count@0x14)已正确落库 |
| cDontStarveSettings | PASS | 无;安装 vtable 指针为 0x45D9D8(数组基 0x45D9D0+8),与文档一致;tier0-core.md §3 残留旧大小文本(文档层不一致) |
| cNetworkComponent | PASS | 无;ctor 对 +0x184/+0x190 整 dword 写(pad 随索引初始化),布局无错位 |

**结论**:4 个类型在 Ghidra 中的 struct 布局与 types_common.h 完全一致(名称/偏移/类型/大小),IDA 反编译抽查(4 函数、每类型 ≤1 次)全部佐证关键偏移。未发现需要修正的字段错位或大小不符;唯一建议是文档层清理 tier0-core.md §3 的过期描述,以及统一 SettingFile 字段命名风格(均非 Ghidra 数据错误)。
