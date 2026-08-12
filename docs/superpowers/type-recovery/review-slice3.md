# Review Slice 3 — EntityLuaProxy / cPrefab / cHashedStringLookup / cGameEvent

- 审查日期: 2026-08-08
- 程序: dontstarve_steam (macOS i386, base 0x1000)
- 对照: types_common.h + tier0-core.md + tier3-b-map.md + tier3-c-input.md
- 方法: ghidra-mcp get_struct_layout 读取当前布局;idalib-mcp (session f9cdc808) decompile 交叉验证;ghidra-mcp disassemble 核对指令级偏移。只读,无任何写入。

---

### EntityLuaProxy
- 状态: **WARN**
- Ghidra 大小: 16B | 文档大小: 16B (0x10) | 匹配: yes
- 字段比对:
  - +0x00 pEntity (cEntity*) ✓ 与文档一致
  - +0x04 pSimulation — **类型为 `-BAD-`(数据域引用失效)**,文档应为 `cSimulation *`;偏移/尺寸正确
  - +0x08 dwGuid (uint) ✓ 偏移正确(文档名 guid,命名风格差异)
  - +0x0C nVersionSnapshot (int) ✓ 偏移正确(文档名 versionSnapshot)
- 证据:
  - ctor @ 0xe171c 反汇编:`[ECX+0]=arg(cEntity*)`、`[ECX+4]=[EAX+0x40]`(entity->simulation)、`[ECX+8]=[EAX+4]`(entity->guid)、`[ECX+0xC]=[EDX+0x44]`(simulation 版本计数)— 4 独立字段,与文档逐字节吻合
  - CheckPointer @ 0xe17be 反汇编:`[ESI+0xC]` 与 `[pSimulation+0x44]` 比较版本计数;超限时 `GetEntityByGUID(0xd309a, [ESI+8])` 刷新 `[ESI]` → 证实 +0=pEntity、+4=pSimulation、+8=guid、+0xC=snapshot
- 问题清单:
  1. `pSimulation` 字段类型显示 `-BAD-`。`/cSimulation`(412B)与 `/cSimulation *` 均存在,数据域本身未失效,疑为字段的指针类型引用指向了被删/未解析的 typedef。偏移与大小不受影响,建议重建该字段类型为 `cSimulation *`(记录不修改)。
  2. 字段名 `dwGuid`/`nVersionSnapshot` 与文档 `guid`/`versionSnapshot` 不一致 — 仅命名,非布局问题。

### cPrefab
- 状态: **PASS**(重点修正项)
- Ghidra 大小: 52B (0x34) | 文档大小: 52B | 匹配: yes
- 字段比对: 13 字段全部偏移一致 —
  - +0x00 pName (char*) ✓;+0x04 nFlags (int) ✓;+0x08 dwNameHash_dwHash (uint) ✓;+0x0C pNameHash_pCstr (char*) ✓
  - +0x10 pSName2 (char*) ✓;+0x14/0x18/0x1C pVecAssets_begin/end/cap (void*) ✓
  - +0x20 nField_0x20 (int) ✓;+0x24 pGame (Ghidra: void*) ✓ 偏移正确,文档类型为 cGame*(精度略低)
  - +0x28/0x2C/0x30 pVecDeps_begin/end/cap (void*) ✓
- 证据:
  - ctor @ 0xf5bf6 (IDA decompile):`[this+4]=a6`(int)、`[this+8..0xF]=cHashedStringCSL::Set(*(char**)this)`(对 +0 name 算 hash → +0x08 dwHash/+0x0C pCstr)、`string::string(this+0x10)`(sName2)、`[this+6/5/8/7]=0`(+0x14..0x20 清零 = vecAssets+nField_0x20)、`[this+9]=a3`(+0x24 = cGame*)、`[this+10/11/12]=0`(+0x28..0x30 = vecDeps)
  - dtor @ 0xebfac (IDA decompile):`~vector(this+0x28)`、`~vector(this+0x14)`、`_Rep::destroy(*(this+0x10))`、`_Rep::destroy(*(this+0x00))` — 与字段归属完全对应
  - 与 tier3-b-map.md 证据链(0xf5cbb `[EDI+8]=local(8B)`;AddPrefab 0x13ffa 以 +8 排序;AddPrefDep 0xec160 push_back(+0x28);AddAsset 0xec20a push_back(+0x14))一致
- 问题清单: 无。此前 tier3-b 判定"字段归属错误、需重建"已落实;nameHash @ +0x08(非 +0x00)、vecAssets @ +0x14、pGame @ +0x24、vecDeps @ +0x28 全部正确。仅 `pGame` 落库为 `void*` 而非 `cGame*`(类型精度,偏移无错)。

### cHashedStringLookup
- 状态: **PASS**
- Ghidra 大小: 84B (0x54) | 文档大小: 84B (types_common.h total 0x54) | 匹配: yes
- 字段比对: 7 字段全部一致 —
  - +0x00 pVtable (void*) ✓;+0x04 criticalSection (Mutex, 56B) ✓;+0x3C/0x40/0x44 pLookupVec_begin/end/cap ✓
  - +0x48 pStringPool (char*) ✓;+0x4C pStringPoolEnd (char*) ✓;+0x50 nStringPoolSize (int) ✓
- 证据:
  - ctor @ 0x284002 (IDA decompile):`[this+15/16/17]=0`(+0x3C..0x44 vec 头清零)、`[this+20]=3145728`(+0x50 = 0x300000)、`operator new[](0x300000)` → `[this+18]=v2`(+0x48)、`[this+19]=v2`(+0x4C)、`vector::reserve(this+0x3C, 30000)` — 与字段逐一吻合;`*(this)=&unk_45BD80` 证实 vtable @ 0x45BD80
- 问题清单:
  1. 文档自身不一致:types_common.h 头部注释及 tier0-core.md 均写 "92 bytes (0x5C)",但两处字段表合计均为 84B (0x54),与 Ghidra 一致。属文档勘误项,非 Ghidra 问题。

### cGameEvent
- 状态: **PASS**
- Ghidra 大小: 8B | 文档大小: 8B | 匹配: yes
- 字段比对: +0x00 pVptr (void*) ✓;+0x04 nType (int) ✓
- 证据: DispatchEvent @ 0xd810 (ghidra decompile) 读取 `*(param_1+4)` 作为 `rb_tree<Type, vector<listener*>>` 查找键 → 证实 [vptr@0, nType@4] 公共事件基类布局;与 tier3-c-input.md 结论一致
- 问题清单: 无。tier3-c 记录的 `/Demangler/cGameEvent` 1B 占位已重建为 8B 正确布局。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| EntityLuaProxy | WARN | `pSimulation` 字段类型为 `-BAD-`(数据域引用失效,偏移/大小正确,应重建为 `cSimulation *`) |
| cPrefab | PASS | 无(重点修正项已正确;仅 `pGame` 落库为 `void*` 非 `cGame*`,类型精度问题) |
| cHashedStringLookup | PASS | 无(文档 "92B/0x5C" 注释与 84B 实际不符,需勘误文档) |
| cGameEvent | PASS | 无 |

## 结论
- 4 类型中 3 个完全 PASS,1 个 WARN。
- cPrefab 重建(52B, nameHash@+8 / vecAssets@+0x14 / pGame@+0x24 / vecDeps@+0x28)经 IDA ctor+dtor 双重验证**全部正确落库**。
- 唯一需修复项:EntityLuaProxy.pSimulation 类型 `-BAD-`(建议改回 `cSimulation *`)。其余均为文档勘误或命名/类型精度级别,不影响布局正确性。
