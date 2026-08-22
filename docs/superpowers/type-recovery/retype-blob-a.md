# Retype Blob A — 拆分字段回写报告

> program=`dontstarve_steam` (macOS i386)。方法:delete+create_struct 全量重建(ghidra-writeback-tier0.md 安全法),字段名/类型/偏移按二进制证据(ctor/dtor/accessor 反编译)校正。

## 1. WaveComponent — 重建 ✓ (144B → 144B)

pVec_0x64 (byte[12] @0x64) 拆分:

| offset | size | type | name | 证据 |
|--------|------|------|------|------|
| 0x64 | 4 | float | flWidth | ctor/DoRender (blob-split-a) |
| 0x68 | 4 | float | flHeight | 同上 |
| 0x6C | 4 | int | nNumWaves | ctor 0;SetRegionNumWaves |

其余 31 字段保持原样(含 base cEntityComponent 16B、nTime、handle 系列、bEnabled、nGameRenderer)。**size 144 不变** ✓

## 2. cNetworkManager — 重建 ✓ (5048B → 5048B)

wField_0x8E (ushort @0x8E) 拆分:

| offset | size | type | name | 证据 |
|--------|------|------|------|------|
| 0x8E | 1 | byte | bPad_0x8E | ctor 0x165992 `wField_0x8E=0x100`→[0x00,0x01] |
| 0x8F | 1 | bool | fAutosaverEnabled | LoadSettings 0x166a6a "autosaver_enabled" SETZ;GetAutosaverEnabled 0x195516 |

额外修正(pending-investigate 证据,ctor 0x165992 确认):
- pStr_0x1A0 → **str_0x1A0 (cStdString)** — ctor `= empty_rep+0xc`(COW 4B 内联 string,非指针)
- pStr_0x1B0 → **str_0x1B0 (cStdString)** — ctor `std::string::string`
- pStr_0x1B4 → **str_0x1B4 (cStdString)** — ctor `std::string::string`
- pStr_0x1F8 → **str_0x1F8 (cStdString)** — ctor `= empty_rep+0xc`

**size 5048 不变** ✓ (字段总数 133)

## 3. DynamicShadowComponent — 重建 ✓ (36B → 36B)

nSizeX/nSizeY retype + nField_0x18 (int @0x18) 打包区拆分:

| offset | size | type | name | 证据 |
|--------|------|------|------|------|
| 0x10 | 4 | float | flSizeX | ShadowEntityComponent::SetSize 0x71792 |
| 0x14 | 4 | float | flSizeY | 同上 |
| 0x18 | 1 | bool | fEnabled | Enable 0x717ce bFlags^=1 |
| 0x19 | 1 | byte | bPristine | Pool GetNew 0x9080e obj+0x19=0 |
| 0x1A | 1 | byte | bFlags | Enable/SetSize 位操作 |
| 0x1B | 1 | byte | bPad_0x1B | 对齐 |
| 0x1C | 4 | int | nField_0x1C | 保留 |
| 0x20 | 4 | int | nField_0x20 | 保留 |

**size 36 不变** ✓

## 4. cNetworkClientObject2 — 重建 ✓ (544B → 544B)

pColour@0x1B8 + pUNKNOWN_0x1BC@0x1BC (错位窗口) 修正为内嵌 cPlayerListingData:

| offset | size | type | name | 证据 |
|--------|------|------|------|------|
| 0x178 | 4 | cEntity* | pPlayerEntity | 保留(ctor 0x162dea) |
| 0x17C | 128 | cPlayerListingData | listing | ctor `cPlayerListingData(&field_0x17c)`;dtor 0x16305a |
| 0x1FC | 8 | Timer | Timer | 保留(ctor `Timer(&field_0x1fc)`) |

**size 544 不变** ✓ — 内部 colour 现位于 listing.colour @0x1B8,与 dtor `ReleaseColour(this+0x1B8)` 一致。

## 5. cPlayerListingData — 新建 ✓ (128B)

按 blob-split-c.md 表 create_struct,但以 ctor 0x19aa1a / dtor / SetFromOther 0x19ac5e / SetEquip 0x19b2b6 / GetEquip 0x19b27e 反编译**校正证据表错误**:

| 证据表(blob-split-c) | 实际(二进制) | 说明 |
|---|---|---|
| cNetID2 44B + nField_28/2C 分开 | nField_28/2C 是 cNetID2 内部字段(44B 覆盖 +0x28/+0x2C) | ctor 先写 +0x28/+0x2C 再 Clear;cPendingConnection 同模式 |
| hash1/hashPrefab/hashSkin* 均 4B | hash1 4B(仅 dwHash);hashPrefab+skin1-3 为 **8B cHashedString**(dwHash+pBuf=0);hashSkin4 4B | ctor dwHash@X + 0@X+4 配对 |
| pEquipBegin@+0x70 | 同(SetEquip vector resize @+0x70) | 一致 |
| pEquipEnd@+0x74 | 同 | 一致 |
| wAgeOrScore@+0x7C (ushort) | **bDirty_0x7C/bDirty_0x7D**(SetColour/SetNetID 置位)| SetFromOther `this[0x7c]\|=0x10` 等 |
| — | **wAge ushort @0x42** | SetFromOther clamp <10000 |
| — | nField_50 @0x50 (uint) | SetFromOther 8B copy @+0x50 |
| — | pEquipCap @0x78 | SetEquip vector 第 3 指针 |

最终字段:strName(cStdString)、netId(cNetID2 44B)、pRakStr(void*)、dwHash0、dwHash1、dwColour、bUserFlags、bNetScore、wAge、bAdmin、pPad_0x45、dwField_48、hashPrefab(cHashedString)、hashSkin1-3(cHashedString)、dwHashSkin4、pEquipBegin、pEquipEnd、pEquipCap、bDirty_0x7C、bDirty_0x7D、pPad_0x7E。**size 128B** ✓

## 验证

| struct | 重建前 | 重建后 | 状态 |
|--------|--------|--------|------|
| WaveComponent | 144 | 144 | ✓ |
| cNetworkManager | 5048 | 5048 | ✓ |
| DynamicShadowComponent | 36 | 36 | ✓ |
| cNetworkClientObject2 | 544 | 544 | ✓ |
| cPlayerListingData | 1(占位) | 128 | ✓(新建) |

每 struct 重建后已 save_program;最终 save_program 于 2026-08-10 完成。
