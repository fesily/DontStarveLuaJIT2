# Review Slice 20 — VertexDescription / Region / Atlas / AtlasManager

> 审查范围:Ghidra 回写的 4 个渲染类型 struct 与 `docs/superpowers/../../3rd/dst/game_decompiler/types_common.h`、`tier3-a-rendering.md` 的一致性。
> 方法:get_struct_layout 读 Ghidra 布局 → 比对文档 → idalib-mcp decompile 抽查关键函数(每类型 ≤2 次)。
> 会话:ghidra-mcp(当前程序)+ idalib-mcp `f9cdc808`(dontstarve_steam, i386, base 0x1000)。只读,未做任何写回。

## 1. VertexDescription

### VertexDescription
- 状态: PASS
- Ghidra 大小: 24B | 文档大小: 24B (0x18) | 匹配: yes
- 字段比对: 无布局差异。仅命名前缀差异(不影响布局):Ghidra `wStride`/`wPad`/`pAttributes` ↔ 文档 `nStride`/`nPad`/`attributes`;Ghidra 字段 `byte[12]` 对应文档 `uint8_t attributes[12]`。
  - 0x00 pVtable (void*) = 文档 pVtable ✓
  - 0x04 wStride (ushort) = 文档 nStride (uint16_t) ✓
  - 0x06 wPad (ushort) = 文档 nPad (uint16_t) ✓
  - 0x08 dwAttributeMask (uint) = 文档 dwAttributeMask (uint32_t) ✓
  - 0x0C pAttributes (byte[12]) = 文档 attributes[12] ✓
- 证据: decompile `BaseVertexDescription::Add 0x1c4dfe` — `*(a1+8) |= 1<<a2`(dwAttributeMask@0x08)、`*(WORD*)(a1+4)` 读/累加 stride(nStride@0x04, ushort)、`std::vector<BaseVertexDescription::Attribute>::push_back(a1+12, v7)`(attributes@0x0C);局部变量 v7[0]=type、v7[1]=elementType、v8=count、v9=offset 与 Attribute 12B 布局吻合。24B 确认。
- 问题清单: 无(Ghidra 与文档/证据完全一致;命名前缀差异为风格问题)

> 同族附带检查:BaseVertexDescription 24B、Attribute 12B 均已回写且与文档一致(`dwType/dwElementType/wCount/wOffset` @ 0/4/8/10),无问题。

## 2. Region

### Region
- 状态: PASS
- Ghidra 大小: 24B | 文档大小: 24B (0x18) | 匹配: yes
- 字段比对:
  - 0x00 dwHash (uint) = 文档 dwHash (uint32_t) ✓
  - 0x04 pUNKNOWN_0x04 (byte[20]) = 文档 UNKNOWN_0x04[20] ✓
- 证据: decompile `Atlas::GetRegion 0xa6252` — 二分查找元素步长 `v5 = 6 * (v3>>1)`(6 dword = 24B 元素)、比较 `v2[v5] < a2->hash`(首 dword 为 hash@0)。Region=24B、hash@0 确认。
- 问题清单: 无(后 20B 语义未定符合文档 UNKNOWN 约定,tier3-a-rendering.md 已知问题已声明)

## 3. Atlas

### Atlas
- 状态: WARN
- Ghidra 大小: 25B | 文档大小: 28B (0x1C, `// 0x1C` 注释;tier3-a-rendering.md §8 声明 28B、alloc `new 0x1C`) | 匹配: no(大小)
- 字段比对: 所有字段偏移/类型完全一致,仅大小差 3B:
  - 0x00 pName (byte[4]) = 文档 name (std::string, 4B 旧 ABI) ✓
  - 0x04 nTextureHandle (int) = 文档 nTextureHandle (int32_t) ✓
  - 0x08 pRegions (byte[12]) = 文档 regions (vec<Region>) ✓
  - 0x14 pFilename (byte[4]) = 文档 filename (std::string) ✓
  - 0x18 bLoaded (byte) = 文档 bLoaded ✓
- 证据: decompile `Atlas::GetTextureHandle 0xa62a8` — `*(BYTE*)(this+24)=1`(bLoaded@0x18)、`*(this+1) = Load(..., *(this+5))`(nTextureHandle@0x04、filename@0x14 作加载 key)、`std::string::assign("", this+20, "")`(filename@0x14);decompile `Atlas::GetRegion 0xa6252`(regions@0x08, Region 24B)。所有字段偏移正确。
- 问题清单:
  1. Ghidra struct 为 alignment=1、25B,缺少尾部 3B 填充。真实 C++ 类型含 std::string 成员,对齐 4,`sizeof(Atlas)` 应为 28B(25 向上取整),与 `AtlasManager::DoLoad 0xa70f0` 的 `new 0x1C`(28B)分配一致。建议回写为 28B(补 0x1C 后 3B pad)。
  2. (文档侧,非 Ghidra 问题)types_common.h 字段列表本身只求和到 25B,却注释 0x1C=28B —— 文档与自身注释不一致,但分配证据(0x1C)支持 28B,故 Ghidra 25B 为唯一偏差。

## 4. AtlasManager

### AtlasManager
- 状态: PASS
- Ghidra 大小: 64B | 文档大小: 64B (0x40) | 匹配: yes
- 字段比对:
  - 0x00 pVtable (void*) = 文档 pVtable ✓
  - 0x04 nField_0x04 (int) = 文档 nField_0x04 ✓
  - 0x08 pResources (byte[12]) = 文档 resources (vec) ✓
  - 0x18 pHashMap (byte[20]) = 文档 hashMap (RBTree impl) ✓(0x14-0x18 的 4B 洞为 _Rb_tree 比较器,文档字段列表未显式列出但尺寸注释正确)
  - 0x2C pVec_2C (byte[12]) = 文档 vec_2C (vec) ✓
  - 0x38 pName (byte[4]) = 文档 name (std::string) ✓
  - 0x3C pRenderer (void*) = 文档 pRenderer (Renderer*) ✓
- 证据: decompile `AtlasManager::AtlasManager 0xa6fbc` — `this+2/3/4=0`(resources@0x08)、`this+6..10` 置 0 且 `this+8 = this+9 = this+24`(RBTree header@0x18, left/right 自指 0x18, 0x18..0x2C)、`this+11/12/13=0`(vec_2C@0x2C)、`this+14 = _S_empty_rep_storage+12`(name@0x38)、`*this = off_456138`(vtable@0x00)、`this+15 = a2`(pRenderer@0x3C)。最大使用偏移 this+15+4 = 0x40 = 64B 确认。
- 问题清单: 无(Ghidra 与报告字段表逐项一致,含 0x14 空洞的隐式处理)

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| VertexDescription | PASS | 无(仅命名前缀差异 wStride/nStride 等,不影响布局) |
| Region | PASS | 无 |
| Atlas | WARN | Ghidra 25B vs 文档 28B:缺尾部 3B 填充(对齐 4 应为 28B,与 alloc 0x1C 一致);字段偏移全部正确 |
| AtlasManager | PASS | 无(0x14-0x18 的 RBTree 比较器 4B 洞在 Ghidra 中正确保留;types_common.h 字段列表未显式列出该洞,属文档注释粒度问题) |

## 附带验证(同族回写类型)

| 类型名 | 状态 | 说明 |
|---|---|---|
| BaseVertexDescription | PASS | 24B,与文档一致 |
| Attribute | PASS | 12B,与文档一致 |
