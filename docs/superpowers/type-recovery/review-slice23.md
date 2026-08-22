# Review Slice 23 — WorkingVB / BitmapFontManager / BitmapFontRenderer / VFXEffect

- 审查时间:2026-08-08
- 对照文档:`docs/superpowers/../../3rd/dst/game_decompiler/types_common.h` + `docs/superpowers/type-recovery/tier3-a-rendering.md`
- 数据源:ghidra-mcp `get_struct_layout`(dontstarve_steam, i386, base 0x1000)+ idalib-mcp(decompile, session f9cdc808)
- 方法:每类型 `get_struct_layout` 取 Ghidra 布局 → 与 types_common.h / tier3-a-rendering.md 比对 → ctor 抽查交叉验证
- 只读审查,未做任何写入

---

### WorkingVB
- 状态: **PASS**
- Ghidra 大小: 64B | 文档大小: 0x40 = 64B | 匹配: yes
- 字段比对:
  | 偏移 | Ghidra | 文档(types_common.h / tier3-a) | 一致 |
  |---|---|---|---|
  | 0x00 | pVertexData `void*[4]` | pVertexData[4] | ✓ |
  | 0x10 | pCurVertex `void*[4]` | pCurVertex[4] | ✓ |
  | 0x20 | pVertCount `int[4]` | nVertCount[4] | ✓(名称前缀差异,类型/偏移一致) |
  | 0x30 | pVertCap `int[4]` | nVertCap[4] | ✓(名称前缀差异) |
- 证据: `WorkingVB::WorkingVB` @0xadd32 — 循环 4 次 `new[]` 顶点缓冲,`*((_DWORD*)thisa+i) = v3+1`(pVertexData[i] @0..0x0F);随后 `pCurVertex[i] = pVertexData[i]`、`nVertCount[i] = -1`、`nVertCap[i] = 0`(i=0..3),与 Ghidra 四个数组偏移 0x00/0x10/0x20/0x30 完全吻合。
- 问题清单: 无(仅 Ghidra 字段名 `pVertCount`/`pVertCap` 与文档 `nVertCount`/`nVertCap` 的 p-/n- 前缀命名约定差异,不影响布局)。

---

### BitmapFontManager
- 状态: **WARN**
- Ghidra 大小: 88B | 文档大小: 0x58 = 88B | 匹配: yes
- 字段比对:
  | 偏移 | Ghidra | 文档(tier3-a 报告) | 一致 |
  |---|---|---|---|
  | 0x00 | pVtable `void*` | pVtable | ✓ |
  | 0x04 | nField_0x04 `int` | nField_0x04(cResourceManager +0x04,ctor 未置位) | ✓ |
  | 0x08 | pResources `byte[12]` | resources vec(this+2/3/4) | ✓ |
  | 0x18 | pHashMap `byte[20]` | hashMap RBTree(this+6..10,左/右自指 0x18) | ✓ |
  | 0x2C | pVec_2C `byte[12]` | vec_2C(this+11/12/13) | ✓ |
  | 0x38 | pName `byte[4]` | name std::string(this+14 = empty) | ✓ |
  | 0x3C | pRegisteredFonts `byte[20]` | RBTree 基址 @0x3C + body @0x40..0x53(20B,左/右自指 0x40) | ⚠ 边界差 4B(见下) |
  | 0x54 | pRenderer `void*` | pRenderer(this+21) | ✓ |
- 证据: `BitmapFontManager::BitmapFontManager` @0xac7c6 — `this+2/3/4=0`(resources@0x08)、`this+6..10` 置 0 且 `this+8/9 = this+24`(hashMap 左/右自指 0x18,body @0x18..0x2B)、`this+11/12/13=0`(vec_2C@0x2C)、`this+14 = &_S_empty_rep_storage+12`(name@0x38)、`*this = &off_456168`(vtable@0)、`this+16..20` 置 0 且 `this+18/19 = this+64`(registeredFonts 左/右自指 0x40,body @0x40..0x53)、`this+21 = a2`(pRenderer@0x54)。ctor 写点与 Ghidra 各字段全部吻合;总大小 88B、pRenderer@0x54 与报告一致。
- 问题清单:
  1. **types_common.h 第 520 行声明错误(与 Ghidra 及报告均不符)**: 字面字段和 = 80B(0x50),与注释 `// 0x58`(88B)矛盾;按字面顺排 hashMap@0x14、vec_2C@0x28、name@0x34、registeredFonts@0x38、pRenderer@0x4C,整体比 Ghidra/报告提前 8B。Ghidra 与 tier3-a 报告相互一致(hashMap@0x18 起),故问题在 header 声明,建议修正字段尺寸/偏移(或补 4B RBTree 基址 `hashMap_base@0x14`)。
  2. Ghidra `pRegisteredFonts` 声明为 20B @0x3C,而报告为 基址@0x3C + 20B body@0x40;ctor 实际写入 0x40..0x53,Ghidra 字段包含基址 dword(0x3C)却漏掉 body 末尾 count dword(0x50..0x53,成为 pRenderer 前隐含 pad)。字节区域 [0x3C,0x54) 两种表示等价,pRenderer@0x54、总大小 88B 均正确 — 属字段边界表示精度问题,非字节错位。

---

### BitmapFontRenderer
- 状态: **PASS**
- Ghidra 大小: 96B | 文档大小: 0x60 = 96B | 匹配: yes
- 字段比对: 9 字段全部一致
  | 偏移 | Ghidra | 文档(tier3-a) | 一致 |
  |---|---|---|---|
  | 0x00 | pVtable `void*` | pVtable | ✓ |
  | 0x04 | nField_0x04 `int` | UNKNOWN_0x04(ctor 未置位) | ✓ |
  | 0x08 | workingVB `WorkingVB` (64B) | workingVB(this+8) | ✓ |
  | 0x48 | pRenderer `void*` | pRenderer(this+18) | ✓ |
  | 0x4C | pFontManager `void*` | pFontManager(this+19) | ✓ |
  | 0x50 | dwVertDescHandle `uint` | dwVertDescHandle(this+20,VertexDescription::Add) | ✓ |
  | 0x54 | dwEffectHandle_font `uint` | dwEffectHandle_font(this+21,font.ksh) | ✓ |
  | 0x58 | dwEffectHandle_packed `uint` | dwEffectHandle_packed(this+22,font_packed.ksh) | ✓ |
  | 0x5C | dwEffectHandle_outline `uint` | dwEffectHandle_outline(this+23,font_packed_outline.ksh) | ✓ |
- 证据: `BitmapFontRenderer::BitmapFontRenderer` @0xade62 — `*this = 4546968`(=0x456198,vtable@0)、`WorkingVB::WorkingVB(this, this+8)`(workingVB@0x08)、`this+18 = a3`(pRenderer@0x48)、`this+19 = a4`(pFontManager@0x4C)、`this+20 = cResourceManager<VertexDescription>::Add(...)`(dwVertDescHandle@0x50,Add 0/10/1/2 四属性)、`this+21/22/23 = Load("shaders/font.ksh" / "font_packed.ksh" / "font_packed_outline.ksh")`。与 Ghidra/报告逐字段精确吻合。
- 问题清单: 无。

---

### VFXEffect
- 状态: **PASS**
- Ghidra 大小: 28B | 文档大小: 0x1C = 28B | 匹配: yes
- 字段比对:
  | 偏移 | Ghidra | 文档(types_common.h / tier3-a) | 一致 |
  |---|---|---|---|
  | 0x00 | pVtable `void*` | pVtable | ✓ |
  | 0x04 | pUNKNOWN_0x04 `byte[24]` | UNKNOWN_0x04[24](header);报告细分:cEntityComponent base 16B @0x04 + nNumEmitters uint @0x10 + pEmitterIds uint* @0x14 + pEmitterManager @0x18 | ✓ 大小一致(24B 不透明块与细分字段等价) |
- 证据: `VFXEffect::VFXEffect` @0x85d1c — 调 `cEntityComponent::cEntityComponent`(base@0x04)、`*this = off_455FA8`(vtable@0)、`this+4 = 0`(nNumEmitters@0x10)、`this+5 = 0`(pEmitterIds@0x14)。`VFXEffect::InitEmitters` @0x85e70 — `this+4 = a3`(nNumEmitters)、`this+5 = new uint[n]`(pEmitterIds)、`this+6 = *(*(*(this+3)+64)+92)+52`(pEmitterManager@0x18)。三字段偏移全部确认。
- 问题清单: 无(Ghidra 与 header 采用 24B 不透明块,与报告细分字段字节完全等价;如需更细粒度可后续拆分,非错误)。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| WorkingVB | PASS | 无;仅 pVertCount/pVertCap 名称前缀与文档 nVertCount/nVertCap 不同 |
| BitmapFontManager | WARN | types_common.h 第 520 行声明偏移整体提前 8B(字段和 80B ≠ 注释 88B),与 Ghidra/报告不符;Ghidra pRegisteredFonts 字段边界比报告 body 早 4B(区域等价,pRenderer@0x54/88B 正确) |
| BitmapFontRenderer | PASS | 无 |
| VFXEffect | PASS | 无;Ghidra 以 24B 不透明块表示,与报告细分字段等价 |

**结论**: Ghidra 中 4 个 struct 的字节布局全部正确(ctor/InitEmitters 交叉验证通过)。唯一实质问题是 types_common.h 的 `BitmapFontManager` 声明与 Ghidra/分片报告偏移不一致,需修正文档;Ghidra 侧仅 `pRegisteredFonts` 字段边界表示与报告相差 4B,属可选的表示精度改进,不影响布局正确性。
