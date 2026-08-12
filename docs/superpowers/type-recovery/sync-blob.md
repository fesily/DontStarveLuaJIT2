# Sync Blob — 拆分后 struct 布局同步到 types_common.h

> 输入: task-blob-sync-brief.md(同步范围 + 方法)
> 数据源: ghidra-mcp `get_struct_layout`(program=`dontstarve_steam`, 5 个 struct 全部实时拉取)
> 目标文件: `3rd/dst/game_decompiler/types_common.h`(仅此文件 + 本报告)
> 日期: 2026-08-10

## 同步结果

| struct | 变更 | 头文件 size | Ghidra size | 状态 |
|--------|------|------------|-------------|------|
| WaveComponent | pVec_0x64 → flWidth/flHeight/nNumWaves; flPhase[20] → nField_0x10..0x5C; flTime → nTime | 144B | 144B | ✓ |
| cNetworkManager | wField_0x8E → bPad_0x8E + fAutosaverEnabled; pStr_0x1A0/1B0/1B4/1F8 → cStdString | 5048B | 5048B | ✓ |
| DynamicShadowComponent | nSizeX/nSizeY → flSizeX/flSizeY (float); nField_0x18 → fEnabled/bPristine/bFlags/bPad_0x1B | 36B | 36B | ✓ |
| cNetworkClientObject2 | 删 pColour + pUNKNOWN_0x1BC; embed `cPlayerListingData listing` @0x17C | 544B | 544B | ✓ |
| cPlayerListingData | **新类型** 128B | 128B | 128B | ✓ 新增 |

struct 总数: 276 → **278**(+ cPlayerListingData + cStdString,见下节)

## 关键差异记录

### 1. cStdString 实际不在头文件中(brief 前提修正)
- brief 称「cStdString 已在头文件(4B COW)」— **事实不符**:全仓 grep 无 cStdString 定义(仅 Ghidra 内由 retype-pending.md 创建 + docs 提及)。
- 按方法「字段名/类型与 Ghidra 一致」,已在头文件顶部新增:
  `struct cStdString { void* pRepData; }; // total 0x4 = 4`(libstdc++ COW 旧 ABI 数据指针,retype-pending.md 同规格)。
- 因此 struct 总数 276 + 2 = **278**(brief 预期 277 是基于 cStdString 已存在的错误前提)。

### 2. WaveComponent — flPhase vs nField(brief 注明「以 Ghidra 为准」)
- 头文件原 `float flPhase[20]`(扫描建议)vs Ghidra `int nField_0x10..nField_0x5C`(20 × int)。
- 按 brief 规则**保留 Ghidra 版**:nField_0x10..0x5C int 系列 + `nTime`(int,原 flTime)。
- pVec_0x64[12] → `flWidth`(float @0x64)/`flHeight`(float @0x68)/`nNumWaves`(int @0x6C)。
- 其余 nField_0x70/0x74、handle 系列、bEnabled、nGameRenderer 原样保留。
- 注意:重命名后语义字段名(flPhase/flTime)丢失,但与二进制(ctor/DoRender int 用法)一致。

### 3. cNetworkManager
- `uint16_t wField_0x8E` → `uint8_t bPad_0x8E` + `bool fAutosaverEnabled`(Ghidra 拆分,ctor 0x165992 证据)。
- `void* pStr_0x1A0/1B0/1B4/1F8` → `cStdString str_0x1A0/1B0/1B4/1F8`(COW 4B 内联 string,非指针;ctor `= empty_rep+0xc` 证据)。
- size 5048 不变 ✓;其余字段未动。

### 4. DynamicShadowComponent
- `int32_t nSizeX/nSizeY` → `float flSizeX/flSizeY`(ShadowEntityComponent::SetSize 0x71792 证据)。
- `int32_t nField_0x18` → `bool fEnabled` + `uint8_t bPristine` + `uint8_t bFlags` + `uint8_t bPad_0x1B`(Enable 0x717ce 位操作证据)。
- nField_0x1C/0x20 保留。size 36 不变 ✓。

### 5. cNetworkClientObject2 + cPlayerListingData
- 删除错位窗口 `pColour[4] @0x1B8` + `pUNKNOWN_0x1BC[60]`(60B 是内部字段错位)。
- 嵌入 `cPlayerListingData listing @0x17C`(128B,ctor 0x162dea `cPlayerListingData(&field_0x17c)` 证据)。
- 内部 colour 现位于 listing.dwColour @0x1B8,与 dtor `ReleaseColour(this+0x1B8)` 一致。
- cPlayerListingData 字段按 Ghidra 布局:strName(cStdString)/netId(cNetID2 44B)/pRakStr/dwHash0/dwHash1/dwColour/bUserFlags/bNetScore/wAge/bAdmin/pPad_0x45/dwField_48/hashPrefab/hashSkin1-3(cHashedString 8B)/dwHashSkin4/pEquipBegin/End/Cap/bDirty_0x7C/bDirty_0x7D/pPad_0x7E。

## 验证

- `grep -c "^struct "` = **278**(276 + cPlayerListingData + cStdString)。
- cPlayerListingData 定义(行 626)先于 cNetworkClientObject2(行 627)引用,无缺失。
- 旧字段名 `pUNKNOWN_0x1BC / flPhase / vec_0x64 / wField_0x8E / pStr_0x1A0 / pStr_0x1B0 / pStr_0x1B4 / pStr_0x1F8 / nSizeX / nSizeY` 全部清零(无残留引用)。
- 头文件本身非独立可编译的 C(既有裸 struct tag 用法,clang 报错行 25-486 全在未编辑区);本次编辑行(43/565/573/605/626/627)无新增报错。
- 其他 273 struct 未改动。

## 只写文件

- `3rd/dst/game_decompiler/types_common.h`
- `docs/superpowers/type-recovery/sync-blob.md`(本报告)
