# Slice 22 类型回写 Review — RenderTarget / HWRenderTarget / RenderTargetManager / BitmapFont

> 二进制:`dontstarve_steam`(macOS i386 32-bit, base 0x1000)
> 对照:`docs/superpowers/../../3rd/dst/game_decompiler/types_common.h`(Rendering 段)+ `tier3-a-rendering.md` 第 3/10/11 节
> 方法:get_struct_layout 读 Ghidra 布局 → 与 types_common.h / tier3-a 字段表比对 → ctor/使用函数 decompile 交叉验证 → vtable read_memory 核对
> IDA 会话 f9cdc808 不可达(idb_list 为空),交叉验证改用 Ghidra decompile_function(只读工具,允许)
> 状态:只读 review,未做任何写入

## 交叉验证用函数(decompile 证据)

| 函数 | 地址 | 用途 |
|---|---|---|
| HWRenderTarget::HWRenderTarget | 0x1cae02 | ctor:写 vtable + GenFramebuffers(@+0x04) + 清零 +0x08/+0x0C/+0x10 |
| Renderer::CreateRenderTarget | 0x1cd3f2 | `new 0x20`(32B),覆盖 vtable 为 RenderTarget vtable,写 +0x14/+0x18/+0x1C |
| BitmapFont::LoadFontDescription | 0xa8d4c | Load XML:写 name/lineHeight/base/scaleW/scaleH/flSize/pages/field_14/glyphMap/kerningMap/textureHandle |
| FrameDelayedResourceManager<RenderTarget>::ctor | 0x1d84ea | 写 cResourceManager 基类 + CS@0x40 + vec@0x78 + pRenderer@0x90 |
| ~RenderTarget (D1) | 0x1ce3b0 | vtable 0x463360 slot 2 指向确认 |

---

### RenderTarget
- 状态: **PASS**
- Ghidra 大小: 4B | 文档大小: 4B | 匹配: yes
- 字段比对: 无差异。Ghidra `{ void* pVtable @0x00 }` == types_common.h `{ void* pVtable; }`(4B 抽象)== tier3-a"无自有字段,仅 vtable"。
- 证据: vtable `0x463360` read_memory = `[0,0, 0x1ce3b0, 0x1ce3b6, ...]`;get_function_by_address(0x1ce3b0) = `~RenderTarget`(1B D1),与 tier3-a `D1=0x1ce3b0, D0=0x1ce3b6` 一致。
- 问题清单: 无。

### HWRenderTarget
- 状态: **PASS**
- Ghidra 大小: 32B | 文档大小: 32B | 匹配: yes
- 字段比对: 无差异。8 字段名称/偏移/类型全部一致:

| 偏移 | Ghidra | types_common.h / tier3-a |
|---|---|---|
| 0x00 | void* pVtable | void* pVtable |
| 0x04 | uint dwFramebufferId | GLuint dwFramebufferId |
| 0x08 | uint dwColorTexHandle | uint dwColorTexHandle |
| 0x0C | uint dwDepthTexHandle | uint dwDepthTexHandle |
| 0x10 | uint dwField_0x10 | uint dwField_0x10 |
| 0x14 | uint dwTextureHandle | uint dwTextureHandle |
| 0x18 | uint dwWidth | uint dwWidth |
| 0x1C | uint dwHeight | uint dwHeight |

- 证据:
  - ctor 0x1cae02:`pVtable = &PTR__HWRenderTarget_004577c0; GenFramebuffers(1, &dwFramebufferId@+0x04); dwColorTexHandle/dwDepthTexHandle/dwField_0x10 = 0` ✓ 与字段表逐项吻合
  - CreateRenderTarget 0x1cd3f2:`operator_new(0x20)`(32B 分配)→ 调 ctor → `pVtable = PTR_vtable_00450b00 + 8`(运行时覆盖为 RenderTarget vtable)→ `dwTextureHandle@+0x14 = param_1; dwWidth@+0x18 = param_2; dwHeight@+0x1C = param_3` ✓ 与 tier3-a 证据一致
  - vtable `0x4577b8` read_memory = `[0,0, 0x1caeba, 0x1caeea]` ✓ 与 tier3-a `D1=0x1caeba, D0=0x1caeea` 一致
- 问题清单: 无。

### RenderTargetManager
- 状态: **WARN**
- Ghidra 大小: 148B | 文档大小: 148B | 匹配: yes
- 字段比对: **大小正确,但 Ghidra 回写为 opaque `byte[148] pBase`,未拆分字段**。types_common.h 同为 opaque(`uint8_t base[148]`),故与 header 一致;但 tier3-a 已推导出完整布局(cResourceManager 基类 0x00-0x3C + CriticalSection@0x40 + vec@0x78 + pRenderer@0x90),Ghidra 未按该布局拆字段,属"回写不完整"而非"回写错误"。
- 证据:
  - ctor 0x1d84ea decompile:`*this = vtable`;+0x08..0x10 = 0(resources vec begin/end/cap);+0x18..0x28 = 0(RBTree header,left/right 自指 0x20/0x24);+0x2C..0x34 = 0(vec);+0x38 = empty string;+0x3C = 0;`CriticalSection::CriticalSection(this + 0x40)`;+0x78..0x90 循环清零(6 dword);`*(Renderer**)(this+0x90) = param_1` → 布局 = cResourceManager + CS@0x40 + vec@0x78 + pRenderer@0x90,总 0x94 = 148B ✓ 与 tier3-a 完全一致
  - vtable `0x463490` read_memory = `[0,0, 0x1d8624, 0x1d8632, 0x1d8636, ...]` ✓ 与 tier3-a `GetResourceNameType=0x1d8624, DoLoad=0x1d8632` 一致
- 问题清单:
  1. [WARN] Ghidra 内 RenderTargetManager 为 opaque 148B,未按 tier3-a 推导布局拆分字段(与 types_common.h opaque 声明一致,功能上 size/分配均正确,仅可读性/深度不及分片报告)。

### BitmapFont
- 状态: **PASS**
- Ghidra 大小: 68B | 文档大小: 68B | 匹配: yes
- 字段比对: 偏移/大小/类型全部一致,仅字段名前缀风格不同(p/w/dw/n 前缀差异,语义相同):

| 偏移 | Ghidra | types_common.h / tier3-a | 一致 |
|---|---|---|---|
| 0x00 | byte[4] pName | std::string name (4B) | ✓ |
| 0x04 | ushort wLineHeight | ushort nLineHeight | ✓ |
| 0x06 | ushort wBase | ushort nBase | ✓ |
| 0x08 | float flSize | float flSize | ✓ |
| 0x0C | float flScaleW | float flScaleW | ✓ |
| 0x10 | float flScaleH | float flScaleH | ✓ |
| 0x14 | uint dwField_0x14 | uint nField_0x14 | ✓ |
| 0x18 | uint dwPages | uint nPages | ✓ |
| 0x1C | byte[12] pGlyphMap | linear_map<uint,Glyph> (12B) | ✓ |
| 0x28 | byte[12] pKerningMap | linear_map<KerningPair,float> (12B) | ✓ |
| 0x34 | uint dwTextureHandle | uint dwTextureHandle | ✓ |
| 0x38 | byte[12] pFallbackFonts | vector<FallbackFontData> (12B) | ✓ |

- 证据: LoadFontDescription 0xa8d4c decompile 逐项吻合:
  - `std::string::assign(this, param_2)` → name@+0x00 ✓
  - `GetAttrShort(pxVar11,"lineHeight",&wLineHeight)` → +0x04;`"base",&wBase` → +0x06 ✓
  - `GetAttrFloat(pxVar13,"outline",&flSize)` → +0x08;`"scaleW"` → +0x0C;`"scaleH"` → +0x10 ✓
  - `dwPages = (flSize>0)+1` → +0x18;`dwField_0x14 = 0` → +0x14 ✓
  - `linear_map<uint,Glyph>::operator[]((uint)pGlyphMap)` → +0x1C;`linear_map<KerningPair,float>::operator[](pKerningMap, ...)` → +0x28 ✓
  - `dwTextureHandle = Renderer::CreateTexture(...)` → +0x34 ✓
  - Glyph 写入 `*(ushort*)(v+0x1C)=page; *(float*)(v+3)=xadvance; ...` → Glyph=32B、page@0x1C,与 tier3-a Glyph 布局一致
- 问题清单:
  1. [INFO] 字段命名前缀不一致(pName/wLineHeight/dwPages vs 文档 nLineHeight/nPages/name),仅风格差异,不影响布局;如追求与文档逐字一致可重命名。
  2. [INFO] glyphMap/kerningMap/fallbackFonts 在 Ghidra 内为 byte[12] opaque(与 types_common.h 一致),嵌套类型 Glyph(32B)/KerningPair(2B) 未建,属已知未完全验证项(tier3-a 已注明 FallbackFontData 语义未定)。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| RenderTarget | PASS | 无。4B 抽象,仅 vtable,vtable 0x463360 槽位与文档一致 |
| HWRenderTarget | PASS | 无。32B,8 字段偏移/类型全对,ctor 0x1cae02 + CreateRenderTarget 0x1cd3f2 双重验证 |
| RenderTargetManager | WARN | 148B 大小正确且 ctor 0x1d84ea 布局与文档吻合,但 Ghidra 内为 opaque byte[148],未按 tier3-a 拆分字段 |
| BitmapFont | PASS | 无布局问题;字段名前缀风格差异(INFO)+ 嵌套类型 Glyph/KerningPair 未建(INFO,与文档 opaque 声明一致) |

**总体结论**:4 个类型大小、偏移、类型均与 types_common.h / tier3-a 一致,无字段错位。唯一 WARN 为 RenderTargetManager 未拆分字段(回写不完整,非错误);无 FAIL。
