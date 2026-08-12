# Review Slice 5 — 事件类: cInputTextEvent / cTogglePauseEvent / cFocusGainedEvent / cFocusLostEvent

> 日期: 2026-08-08
> 目标程序: `dontstarve_steam` (i386, base 0x1000)
> 方法: `get_struct_layout`(Ghidra) + `decompile`(idalib-mcp, session f9cdc808) 交叉验证
> 对照: `docs/superpowers/../../3rd/dst/game_decompiler/types_common.h` 与 `tier3-c-input.md`

---

### cInputTextEvent
- 状态: **WARN**(实为 FAIL — 结构大小与字段类型均与二进制证据矛盾)
- Ghidra 大小: 20B (0x14) | 文档大小: 20B (0x14) | 匹配: yes(Ghidra 与文档一致,但两者均与二进制矛盾)
- 字段比对:
  - +0x00 vptr: Ghidra `pVptr` (void*) / 文档 `vptr` — 一致 ✓
  - +0x04 nType: Ghidra `nType` (int) / 文档 `nType` (int32_t) — 一致 ✓
  - +0x08 sText: Ghidra `pSText` (byte[12]) / 文档 `sText` (uint8_t[12]) — **不一致 ✗(应为 4B CoW std::string,总大小 0x0C)**
- 证据:
  - D1 dtor @ 0x153a0:`v2 = *((_DWORD*)thisa + 2)` 读取 `[event+8]` 为**单指针**;`v2-12` 与 `&std::string::_Rep::_S_empty_rep_storage` 比较;`_InterlockedExchangeAdd(v2-4, -1)` 做 **refcount--**;`_M_destroy(v2-12)`。这是**旧 ABI CoW std::string 的标准析构模式** — 字符串对象仅 4 字节(单指针指向 `_Rep`),绝非 12B 新 ABI 字符串。
  - HandleEvent type2 @ 0xfd604:`v10[0] = &_S_empty_rep_storage + 12`(CoW 空串)、`v10[2] = 2`(type),随后 `std::string::assign` + `_M_destroy` — 全部 CoW 字符串操作。
  - ProcessTextInput @ 0x137e4(构造点):`[esp+0x18] = vptr(0x45DBDC)`、`[esp+0x1c] = 2`(nType)、`std::string::string` 在 `[esp+0x20]`(= event+8)就地构造。事件对象共 **12 字节 = vptr(4) + nType(4) + sText(4)** → **总大小应为 0x0C**。
- 问题清单:
  1. **sText 类型/大小错误**: 二进制证据(CoW refcount-- / `_S_empty_rep_storage` / `_M_destroy`)证明 `sText` 是 **4 字节 CoW std::string**,而 Ghidra 与文档均写成 `byte[12]`(12B)。
  2. **结构总大小错误**: 应为 **0x0C (12B)**,Ghidra 与文档均为 0x14 (20B)。tier3-c-input.md 1.5 自身证据表已写 "D1 0x153ad-0x153e3 对 [event+8] refcount-- / _M_destroy" — **refcount-- 正是 CoW 特征**,与它得出的 "12B" 结论自相矛盾。
  3. 字段名差异(`pSText` vs `sText`)仅为命名差异,不影响布局。

---

### cTogglePauseEvent
- 状态: **WARN**(字段/偏移全部正确,仅大小与文档不一致)
- Ghidra 大小: 9B | 文档大小: 12B (0x0C) | 匹配: no(缺 3B 尾部 padding)
- 字段比对:
  - +0x00 vptr: Ghidra `pVptr` (void*) / 文档 `vptr` — 一致 ✓
  - +0x04 nType: Ghidra `nType` (int) / 文档 `nType` (int32_t) — 一致 ✓
  - +0x08 bPaused: Ghidra `fPaused` (bool) / 文档 `bPaused` (bool) — 一致(仅命名差异)✓
- 证据:
  - SetPaused @ 0x13ba8:`v6[0] = &unk_45DBBC`(vptr ✓)、`v6[1] = 4`(nType=4 ✓)、`v7 = a3`(bPaused ✓)。栈上对象 9 字节(8B + 1B),按 4B 对齐实际占 12B。
  - D1 dtor @ 0x153ec: 空析构(RET)— 无字符串成员,与文档一致 ✓
- 问题清单:
  1. **大小不匹配**: Ghidra struct 为 9B(未 materialize 尾部 padding),文档明确写 "回写建议:新建 cTogglePauseEvent 0x0C" 且注明 "+0x09 起填充未知(对象按 4B 对齐 ≥0x0C)"。建议补 `byte[3]` padding 至 0x0C。
  2. 字段名 `fPaused` vs `bPaused` 为命名差异。

---

### cFocusGainedEvent
- 状态: **PASS**
- Ghidra 大小: 8B | 文档大小: 8B | 匹配: yes
- 字段比对:
  - +0x00 vptr: Ghidra `pVptr` (void*) / 文档 `vptr` — 一致 ✓
  - +0x04 nType: Ghidra `nType` (int) / 文档 `nType` (int32_t) — 一致 ✓
- 证据:
  - FocusGained @ 0x11b51:`v3[0] = &unk_45DBF8`(vptr=0x45DBF8 ✓)、`v3[1] = 13`(nType=0xD ✓)。
  - SetHasFocus @ 0x1d208c:`vptr = PTR_vtable_00450b68 + 8 = 0x45DBF0 + 8 = 0x45DBF8` ✓、`nType = 0xD` ✓。两处构造点均只写 8 字节,无额外字段。
- 问题清单: 无

---

### cFocusLostEvent
- 状态: **PASS**
- Ghidra 大小: 8B | 文档大小: 8B | 匹配: yes
- 字段比对:
  - +0x00 vptr: Ghidra `pVptr` (void*) / 文档 `vptr` — 一致 ✓
  - +0x04 nType: Ghidra `nType` (int) / 文档 `nType` (int32_t) — 一致 ✓
- 证据:
  - FocusLost @ 0x11b11:`v3[0] = &unk_45DC08`(vptr=0x45DC08 ✓)、`v3[1] = 12`(nType=0xC ✓)。
  - SetHasFocus @ 0x1d208c:`vptr = PTR_vtable_00450b64 + 8 = 0x45DC00 + 8 = 0x45DC08` ✓、`nType = 0xC` ✓。两处构造点均只写 8 字节,无额外字段。
- 问题清单: 无

---

## 汇总表

| 类型 | 状态 | 主要问题 |
|---|---|---|
| cInputTextEvent | **WARN**(实为 FAIL) | sText 应为 4B CoW std::string(非 12B),总大小应为 0x0C(非 0x14);Ghidra 与文档均错 |
| cTogglePauseEvent | WARN | 字段/偏移正确;缺 3B 尾部 padding,大小 9B vs 文档 0x0C |
| cFocusGainedEvent | PASS | 无 |
| cFocusLostEvent | PASS | 无 |

## 结论

- **cInputTextEvent 是本次唯一实质性错误**: 二进制反编译证据(CoW 旧 ABI 字符串的 refcount-- / `_S_empty_rep_storage` / `_M_destroy` 模式)明确显示 `sText` 为 **4 字节单指针**,而非文档/回写所采用的 12B 数组。该结构应修正为 `{ vptr@0; nType@4; sText(CoW std::string)@8 }`,总大小 **0x0C**。tier3-c-input.md 1.5 节自身引用的证据与结论自相矛盾。
- **cTogglePauseEvent** 仅差尾部 padding(9B vs 0x0C),字段与偏移完全正确。
- **cFocusGainedEvent / cFocusLostEvent** 与文档完全一致,无问题。
- 所有 vptr 值(0x45DBDC / 0x45DBBC / 0x45DBF8 / 0x45DC08)与文档记载一致。
