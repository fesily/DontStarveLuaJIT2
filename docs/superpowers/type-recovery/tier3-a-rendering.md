# Tier 3-A — Rendering 子系统类型恢复报告(只读调查)

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp(当前程序)+ idalib-mcp(会话 f9cdc808)
> 方法:cResourceManager 家族布局由 ctor/dtor 推导;每个类型 ≤3 次 decompile;vtable 用 ghidra read_memory 读 __ZTV 槽
> 约束:只读,不回写 Ghidra;本文件为分片报告,回写由主 agent 统一执行

## 关键前置知识(多类型共享)

- **std::string = 4 字节**(旧 ABI refcounted string, `_S_empty_rep_storage+12` 表示空串;dtor 经 `_M_destroy(_Rep)` 释放)。所有 `std::string` 字段按 4B 计。
- **cResourceManager<T,uint,FakeLock> 基类布局**(由 cResourceManager<BitmapFont>::~ 0xacd10 + AtlasManager ctor 0xa6fbc 推导):

| 偏移 | 大小 | 字段 |
|---|---|---|
| 0x00 | 4 | vtable |
| 0x04 | 4 | UNKNOWN(未在 ctor 初始化) |
| 0x08 | 12 | `std::vector<sResourceRecord>` (begin/end/cap) |
| 0x14 | 20 | `std::_Rb_tree<cHashedString,uint>` impl(header @ 0x18: color/parent/left/right/count;left/right 自指 0x18) |
| 0x2C | 12 | `std::vector<T*>` 或 flags(ctor 置 0;dtor `if (v1[11]) delete string` 复用) |
| 0x38 | 4 | `std::string` resourceNameType(空串) |
| 0x3C | 4 | pRenderer(各管理器各自存放位置不同,见下) |

- **FrameDelayedResourceManager<T>** = cResourceManager + CriticalSection(56B)@0x40 + 6 dword @0x78 + pRenderer @0x90;ctor 0x1d9844 把 FrameOver 回调节点 hook 到 `renderer+0x1B4(436)`。

---

## 1. BaseRenderer — 抽象基类,恢复完成 ✓(vtable 4B+)

- vtable `0x463700`(__data):`[0x00000000(offset-to-top), 0x00000000(typeinfo), D1=0x1db332, D0=0x1db334, 0x85203C, 0x85203C, 0,0,0, ...]`
- ctor 无独立符号(纯抽象);D1 0x1db332(1B)、D0 0x1db334(5B)
- 唯一成员 = vtable 指针;`CommitWriteMasks` 0x1cbd32、`ReleaseAll` 0x1d46bc 均为非虚或覆盖实现
- **回写建议:新建 4B(仅 vtable),或跳过(抽象接口无字段)**

## 2. BaseTexture — 20B,恢复完成 ✓

- vtable `0x457700`:`[0,0, D1=0x1c4926, D0=0x1c492c, Destroy=0x1c4902, Serialize?, HeaderSize?, ...]`
- ctor 0x1c4872(D1 默认)+ 0x1c4944(`BaseTexture(uint8 num_mips, uint8 pixel_format)`)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*thisa = &unk_457708` |
| 0x04 | sMipDescription* | pMipData | ctor(Ehh) `this+1 = new[]((flags>>9)&0x1F0); bzero(16*num_mips)` |
| 0x08 | uint | dwFlags | ctor(Ehh) `this+2 = old & 0xFFF01FFF \| (numMips<<13) \| (pixfmt<<18)`;Serialize 0x1c4a3c 写 `a1+8` |
| 0x0C | 4 | UNKNOWN_0x0C | ctor 未置位 |
| 0x10 | std::string | name | ctor `this+4 = _S_empty_rep_storage+12` |

- **sMipDescription = 16B**:`{ushort w@0, ushort h@2, ushort ?@4, uint dataSize@8, uint dataOffset@12}`(Serialize 0x1c4afa: 3×ushort + 1×dword,步长 16)
- 派生 HWTexture(0x1ce730, vtable 0x457868)补 +0x14..0x24(40B),不在本切片范围
- **回写建议:新建 20B**

## 3. BitmapFont — 68B,恢复完成 ✓(原 1B 占位)

- 无 vtable(首字段为 std::string);ctor 0xa8bea、dtor 0xa8cb2、LoadFontDescription 0xa8d4c

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | std::string | name | ctor `*thisa = empty`;Load `assign`;dtor `_M_destroy(*thisa-12)` |
| 0x04 | ushort | nLineHeight | Load `GetAttrShort((WORD*)thisa+2)`(common.lineHeight) |
| 0x06 | ushort | nBase | Load `GetAttrShort((WORD*)thisa+3)`(common.base) |
| 0x08 | float | flSize | Load `GetAttrFloat((float*)thisa+2)`(info.size) |
| 0x0C | float | flScaleW | Load `GetAttrFloat((float*)thisa+3)`(common.scaleW) |
| 0x10 | float | flScaleH | Load `GetAttrFloat((float*)thisa+4)`(common.scaleH) |
| 0x14 | uint | nField_14 | ctor `this+5 = 0` |
| 0x18 | uint | nPages | Load `this+6 = (flSize>0)+1 或 0` |
| 0x1C | linear_map<uint,Glyph> | glyphMap | Load `operator[](this+28)`;ctor/dtor 见 this+7/8/9 |
| 0x28 | linear_map<KerningPair,float> | kerningMap | Load `operator[]((int*)thisa+10)` |
| 0x34 | uint | dwTextureHandle | Load `this+13 = Renderer::CreateTexture(...)` |
| 0x38 | vector<FallbackFontData> | fallbackFonts | ctor `this+14/15/16 = 0`;dtor `delete this+14` |

- **Glyph = 32B(0x20)**:`{float x@0, float y@4, float w@8, float h@0xC, float xoffset@0x10, float yoffset@0x14, int xadvance@0x18, ushort page@0x1C}`(Load 写 `v26[0..3], v26[4..5], v26[6]=xadvance, (WORD*)v26[14]=page`)
- **KerningPair = 2B**:`{char first, char second}`(Load `LODWORD(v35)=(char)first; HIDWORD(v35)=(char)second`)
- **FallbackFontData** = cHashedString(8B)或 hash(4B),未完全验证 → UNKNOWN
- **回写建议:新建 68B**

## 4. BitmapFontManager — 88B,恢复完成 ✓(原 1B 占位)

- vtable `0x456160`:`[0,0, GetResourceNameType=0xad214, DoLoad=0xac9d2, ...]`;ctor 0xac7c6、dtor 0xac91a
- 布局 = cResourceManager<BitmapFont> 基类 + 扩展:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*this = &off_456168` |
| 0x08 | vec<sResourceRecord> | resources | ctor this+2/3/4 = 0 |
| 0x18 | RBTree<cHashedString,uint> | hashMap | ctor this+6..10;left/right 自指 0x18 |
| 0x2C | vec | vec_2C | ctor this+11/12/13 = 0 |
| 0x38 | std::string | name | ctor this+14 = empty |
| 0x3C | RBTree 基址 | — | dtor `_M_erase(thisa+60, this+17)` → root@0x44 |
| 0x40 | RBTree<cHashedString,uint> | registeredFonts | ctor this+16..20(left/right 自指 0x40);dtor 遍历 `this+18` 起,`Release(*(node+24))` |
| 0x54 | GameRenderer* | pRenderer | ctor `this+21 = a2` |

- 方法:RegisterFont 0xaca8a、GetRegisteredFont 0xacc4a、AppendFallbackFont 0xacb82(挂到 BitmapFont+0x38 fallback vec)
- **回写建议:新建 88B**

## 5. BitmapFontRenderer — 96B,恢复完成 ✓(原 1B 占位)

- vtable `0x456190`:`[0,0, D1=0xae096, D0=0xae09c, RenderText=0xae0c8, RenderText(Params)=0xae384, ...]`;ctor 0xade62
- 实现 ITextRenderer 接口

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*thisa = 4546968`(=0x456198) |
| 0x04 | 4 | UNKNOWN_0x04 | ctor 未置位 |
| 0x08 | WorkingVB (64B) | workingVB | ctor `WorkingVB::WorkingVB(this+8)` |
| 0x48 | GameRenderer* | pRenderer | ctor `this+18 = a3` |
| 0x4C | BitmapFontManager* | pFontManager | ctor `this+19 = a4` |
| 0x50 | uint | dwVertDescHandle | ctor `this+20 = cResourceManager<VertexDescription>::Add`(Add 0/10/1/2 四属性) |
| 0x54 | uint | dwEffectHandle_font | ctor Load "shaders/font.ksh" |
| 0x58 | uint | dwEffectHandle_packed | ctor Load "shaders/font_packed.ksh" |
| 0x5C | uint | dwEffectHandle_outline | ctor Load "shaders/font_packed_outline.ksh" |

- **WorkingVB = 64B**:ctor 0xadd32 分配 4×0x2580000 顶点缓冲(头 dword=0xF0000=983040, 每顶点 40B:`colour@+4(RGBA), +5/+6 dword`),布局:

| 偏移 | 名称 |
|---|---|
| 0x00 | pVertexData[4] |
| 0x10 | pCurVertex[4] |
| 0x20 | nVertCount[4](-1) |
| 0x30 | nVertCap[4](0) |

- Reset 0xaddc2:`pCur = pData; nCount=-1; nCap=0`;CalcNumVerts 0xade42
- **回写建议:新建 96B + WorkingVB 64B**

## 6. Batcher — 68B,插件先验已存在 ✓ 验证通过(无需重建)

- 无 vtable(ctor 0xa7fd0 首写 `*thisa = pRenderer`);插件 struct 68B 全部字段由 ctor+dtor+Flush 三重验证

| 偏移 | 插件名 | 验证证据 |
|---|---|---|
| 0x00 | dwRenderer | ctor `*thisa = a3`;Flush `SetEffect(*thisa,...)` |
| 0x04/0x08/0x0C | dwTexHandle0/1/2 | ctor 置 -1;Flush 循环 `if (this+i+1 != -1) SetTexture` |
| 0x10 | dwVertDescHandle | ctor `this+4 = Add(0,0,3)+Add(1,0,2)+Add(10,2,4)` |
| 0x14 | dwBlendMode | ctor `this+5 = 3`;Flush SetBlendMode |
| 0x18 | dwEffectHandle | ctor `this+6 = -1` |
| 0x1C/0x20 | flAlphaMin/Max | ctor `*(QWORD*)(this+28) = Vector2::Zero` |
| 0x24..0x30 | flEffectParam0..3 | ctor `*(QWORD*)(this+36)=Vector4::Zero; *(QWORD*)(this+44)=unk_46564C` |
| 0x34 | bHasEffectParams | ctor `*(BYTE*)(this+52)=0`;Flush 检查 |
| 0x38/0x3C/0x40 | dwVertBegin/End/Cap | ctor `reserve(this+56,1024)`;dtor `delete this+14` |

- **回写建议:已存在(68B),验证通过 ✓**

## 7. VertexDescription / BaseVertexDescription — 各 24B,恢复完成 ✓(原 1B 占位)

- BaseVertexDescription vtable `0x45f460`(实例 vtable ptr = 0x45f468);VertexDescription vtable `0x45f450`(实例 ptr = 0x45f458)
- BaseVertexDescription ctor 0x1c4d8e、Add 0x1c4dfe;VertexDescription D1 0x135750、D0 0xb3fd8

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*thisa = &unk_45F468` |
| 0x04 | ushort | nStride | Add `*(WORD*)(a1+4) = stride+size`;HWVertexDescription::Set 0x1cf034 读 `*((ushort*)thisa+2)` |
| 0x06 | ushort | pad | — |
| 0x08 | uint | dwAttributeMask | Add `*(a1+8) \|= 1<<a2`;Set 位测试 |
| 0x0C | vec<Attribute> | attributes | ctor this+3/4/5=0;Add push_back(a1+12);Set 遍历 `v11+=12` |
| 0x18 | — | (size) | 分配 0x18(Batcher/UIRenderAssetManager ctor `new 0x18`) |

- **Attribute = 12B**:`{uint type@0, uint elementType@4, ushort count@8, ushort offset@10}`(Set 读 `*(v11+4)`=GL类型索引≤5,`*(ushort)(v11+8)`=count,`*(ushort)(v11+10)`=offset)
- VertexDescription 仅 vtable 不同(无自有字段)
- **回写建议:新建 BaseVertexDescription 24B + VertexDescription 24B + Attribute 12B**

## 8. Atlas — 28B,恢复完成 ✓(原 1B 占位)

- 无 vtable(首字段 std::string);ctor 0xa571c、dtor 0xa57d6;AtlasManager::DoLoad 0xa70f0 分配 `new 0x1C`

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | std::string | name | ctor `string(this, a3)`;dtor `_M_destroy(*this-12)` |
| 0x04 | int | nTextureHandle | ctor `this+1 = -1`;GetTextureHandle 0xa62a8 `this+1 = Load` |
| 0x08 | vec<Region> | regions | GetRegion 0xa6252 二分 `this+2/+3`(Region=24B,stride 6 dword) |
| 0x14 | std::string | filename | ctor `string("", this+20)`;GetTextureHandle `this+5` 作加载 key |
| 0x18 | byte | bLoaded | GetTextureHandle `*(BYTE*)(this+24)=1` |

- **Region = 24B**:`{uint hash@0, ... 20B}`(GetRegion 比较 `v2[v5] < a2->hash`,6 dword 元素)
- **回写建议:新建 28B + Region 24B**

## 9. AtlasManager — 64B,恢复完成 ✓(原 1B 占位)

- vtable `0x456130`:`[0,0, GetResourceNameType=0xa76c2, DoLoad=0xa70f0, DoUnload=0xa725e, ...]`;ctor 0xa6fbc
- 布局 = cResourceManager<Atlas> 基类(同 BitmapFontManager 的前半)+ pRenderer@0x3C:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*this = &off_456138` |
| 0x08 | vec | resources | ctor this+2/3/4 = 0 |
| 0x18 | RBTree | hashMap | ctor this+6..10 |
| 0x2C | vec | vec_2C | ctor this+11/12/13 = 0 |
| 0x38 | std::string | name | ctor this+14 = empty |
| 0x3C | Renderer* | pRenderer | ctor `this+15 = a2` |

- **回写建议:新建 64B**

## 10. HWRenderTarget — 32B,恢复完成 ✓(原 1B 占位)

- vtable `0x4577b8`(`[0,0, D1=0x1caeba, D0=0x1caeea, ...]`);ctor 0x1cae02、dtor 0x1cae8a
- Renderer::CreateRenderTarget 0x1cd3f2 分配 `new 0x20`,运行时覆盖 vtable 为 `0x463368`(RenderTarget vtable)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*thisa = &unk_4577C0`;CreateRenderTarget 覆盖 0x463368 |
| 0x04 | GLuint | dwFramebufferId | ctor `__glewGenFramebuffers(1, this+4)`;dtor DeleteFramebuffers |
| 0x08 | uint | dwColorTexHandle | ctor `this+2 = 0` |
| 0x0C | uint | dwDepthTexHandle | ctor `this+3 = 0` |
| 0x10 | uint | dwField_10 | ctor `this+4 = 0` |
| 0x14 | uint | dwTextureHandle | CreateRenderTarget `v5+5 = a2` |
| 0x18 | uint | dwWidth | CreateRenderTarget `v5+6 = a3` |
| 0x1C | uint | dwHeight | CreateRenderTarget `v5+7 = a4` |

- RenderTarget(基类):vtable `0x463360`,`[0,0, D1=0x1ce3b0, D0=0x1ce3b6, ...]`,抽象接口,无自有字段
- **回写建议:新建 RenderTarget 4B(仅 vtable)+ HWRenderTarget 32B**

## 11. RenderTargetManager — 148B,恢复完成 ✓(原 1B 占位)

- vtable `0x463490`:`[0,0, GetResourceNameType=0x1d8624, DoLoad=0x1d8632, ...]`;FrameDelayed<RenderTarget> vtable `0x4634c0`
- 布局 = FrameDelayedResourceManager<RenderTarget>(ctor 0x1d84ea = FrameDelayed C2 0x1d9844 同型):cResourceManager 基类 + CS@0x40 + vec@0x78 + pRenderer@0x90 = **148B**
- **回写建议:新建 148B(可复用 cResourceManager + FrameDelayed 模板布局)**

## 12. RenderState — 372B,插件先验已存在 ✓ 验证通过(无需重建)

- 无 vtable(非多态);ctor 0x1db33a、CommonReset 0x1cacaa、Reset 0x1cab3c
- 插件 struct 372B 逐字段验证一致(纹理阶段、alpha、depth、stencil 全部对上),关键点:
  - TextureStage[8]@0x44,每阶段 24B:ctor 循环写 `{3,3,0,0,3,...}` 6 dword
  - `+0x110 bAlphaBlendSrc/dst/test, +0x113 bAlphaRef`;CommonReset `this+68 = -16777216(0xFF000000)`
  - `+0x114 dwActiveTexUnit=1`(CommonReset this+69)
  - `+0x124 bDepthWrite=1, +0x125 bDepthTest=0`;`+0x128 dwDepthFunc=8`
  - `+0x130 bStencilEnable=1, +0x131 bStencilEnableBack`;`+0x134 dwStencilRef=8, +0x138 dwStencilMask=0`
  - StencilState front@0x13C / back@0x158(各 28B,SetStencilOp/SetStencilFunc)
- **回写建议:已存在(372B),验证通过 ✓**

## 13. UIRenderAssetManager — 32B,插件先验已存在 ✓ 验证通过(无需重建)

- vtable `0x456300`:`[0,0, D1=0xbcd5a, D0=0xbce0e, ...]`;ctor 0xbca16、dtor 0xbcd5a
- 插件 struct 32B 逐字段验证:renderer@4、vertDesc@8(Add 3 属性)、effect_ui/yuv/anim@0xC/0x10/0x14(renderer+412 管理器 Load "shaders/ui*.ksh")、vb@0x18(CreateVB 10,6,24)、batcher@0x1C(`new Batcher(0x44)` → 与 Batcher 68B 一致)
- **回写建议:已存在(32B),验证通过 ✓**

## 14. TextureNode — 二进制中不存在,标记跳过

- IDA func_query `*TextureNode*` / `*TDataCacheTexture*` 均空;Ghidra 数据类型无 TextureNode
- 本版本(服务器构建)该节点已移除/改名,渲染树节点实际使用 ImageNode(0xc35b2)/VideoNode
- **回写建议:跳过(不存在)**

## 15. VideoNode — 276B,恢复完成 ✓(原 1B 占位)

- vtable `0x456550`:`[0,0, D1=0xc8c32, D0=0xc8c38, ...]`;ctor 0xc883a、dtor 0xc8a6c
- 继承 SceneGraphNode(cHashedString 构造),自有字段(相对对象头):

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*this = off_456558` |
| 0x50 | Vector2 | flSize | ctor `*(QWORD*)(this+20) = Vector2::Zero`;SetSize 0xc8a52 |
| 0x94/0x98/0x9C | uint | decoder handles ×3 | ctor `this+37/38/39 = v4[4]/[2]/[6]`(THEORAPLAY 解码器) |
| 0xA0/0xA4 | uint | nField_A0/A4 | ctor this+40/41 = 0 |
| 0xA8/0xAC | uint | nField_A8/AC | ctor this+42/43 = 0 |
| 0xB0 | uint | tint (Colour) | ctor `this+44 = Colour::White` |
| 0xB4 | uint | nField_B4 | ctor this+45 = 0 |
| 0xB8 | std::string | name | ctor this+46 = empty |
| 0xC0 | Timer (32B?) | timer | ctor `Timer::Timer(this+192)` |
| 0xD8/0xDC | fn ptr | IoFopenRead/Close | ctor this+54/55 = IoFopenRead/IoFopenClose |
| 0xEC/0xF0/0xF4 | uint | nField_EC/F0/F4 | ctor this+59/60/61 = -1 |
| 0xF8 | byte | bField_F8 | ctor = 1 |
| 0x100/0x104 | uint | nField_100/104 | ctor this+64/65 = 0 |
| 0x108/0x10C/0x110 | uint | nField_108..110 | ctor this+66/67/68 = 0 |

- TDataCacheVideoNode(0xc9df2)不属本切片
- **回写建议:新建 276B(SceneGraphNode 基类字段待验证)**

## 16. Effect / HWEffect / Shader — 164B / 160B / 24B,恢复完成 ✓(原 1B 占位)

- Effect vtable `0x457780`:`[0,0, D1=0x1c6b9e, D0=0x1c6ba4, Init=0x1c6c0c, Commit=0x1c77be, ...]`;ctor 0x1c6604(C2,调 HWEffect ctor + 置 vtable 0x457788 + string@+160)、dtor 0x1c6b4a
- HWEffect vtable `0x4577a0`:`[0,0, D1=0x1c6bda, D0=0x1c6be0, Init=0x1c6c0c, Commit=0x1c77be, ...]`;ctor 0x1c6662、dtor 0x1c6990
- EffectManager::DoLoad 0x1c54d4:`new 0xA4(164)` + `Effect::Effect` + `Renderer::InitializeEffect(renderer, effect)`;失败标志 `*(effect+0x9C)`

**HWEffect 字段**(ctor 0x1c6662 + dtor 0x1c6990):

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*thisa = &unk_4577A8` |
| 0x04 | Shader (24B) | vsShader | ctor vtable `&unk_463358`;dtor `Shader::~Shader(this+4)` |
| 0x1C | Shader (24B) | psShader | ctor vtable `&unk_463348`;dtor `Shader::~Shader(this+28)` |
| 0x34 | void* | pShaderData | ctor `this+13 = new[](fileSize); memcpy` |
| 0x38 | std::string | shaderName | ctor `assign(this+56, __s)`;dtor `_M_destroy(this+38)` |
| 0x3C | uint | nShaderDataSize | ctor `this+15 = GetSize` |
| 0x40 | GLuint | glProgram | dtor `__glewDeleteProgram(this+16)` |
| 0x48 | eastl::rbtree<cHashedString,uint> | paramMap1 | ctor header @0x48(自指 0x4C);dtor `DoNukeSubtree(this+72, root@0x54)` |
| 0x64 | eastl::rbtree | paramMap2 | dtor `DoNukeSubtree(this+100, root@0x70)` |
| 0x80 | vector<ShaderParameterData> | paramData | dtor `~vector(this+128)` |
| 0x8C | vector<ShaderParameterInfo> | paramInfo | dtor `~vector(this+140)` |
| 0x98 | std::string | UNKNOWN_str | ctor this+38 = empty;dtor `_M_destroy` |

**Effect** = HWEffect + `std::string name @0xA0`(ctor `string((char*)thisa+160)`;dtor `_M_destroy(this+40)`) = 164B(0xA4)✓

**Shader = 24B**:`{vtable@0, int nHandle@4(-1), std::string name@8, +0xC=0, +0x10=0, +0x14=0}`(ctor 内联子段 + Shader dtor 0x1c6520);VertexShader/PixelShader 派生

- **回写建议:新建 Shader 24B + HWEffect 160B + Effect 164B**

## 17. EffectManager — 148B,恢复完成 ✓(原 1B 占位)

- vtable `0x457720`:`[0,0, GetResourceNameType=0x1c55c4, DoLoad=0x1c54d4, ...]`;FrameDelayed<Effect> vtable `0x463520`
- 布局 = FrameDelayedResourceManager<Effect> 同 RenderTargetManager = **148B**;DoLoad 0x1c54d4 经 `renderer+0x90` 取 Renderer,`InitializeEffect`
- **回写建议:新建 148B(与 RenderTargetManager/VertexDescriptionManager 共用模板布局)**

## 18. VFXEffect — 28B,恢复完成 ✓(原 1B 占位)

- vtable `0x455fa0`:`[0,0, D1=0x85e3e, D0=0x85e44, Update=0x85f36, GetComponentID=0x866da, GetComponentName=0x866e2, ...]`;ctor 0x85d1c、dtor 0x85d80
- 继承 cEntityComponent(16B):

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*thisa = off_455FA8` |
| 0x04 | cEntityComponent base | (16B) | ctor 调 `cEntityComponent::cEntityComponent` |
| 0x10 | uint | nNumEmitters | ctor this+4=0;InitEmitters 0x85e70 `this+4 = a3` |
| 0x14 | uint* | pEmitterIds | InitEmitters `this+5 = new uint[n]`;dtor `delete[] this+5` |
| 0x18 | VFXEmitterManager* | pEmitterManager | InitEmitters `this+6 = *(*(*(this+3)+64)+92)+52`;dtor 经此 Stop/KillEmitter |

- **回写建议:新建 28B**

## 19. VFXEffectEmitter — 128B,恢复完成 ✓(原 1B 占位)

- vtable `0x456350`:`[0,0, D1=0xbd112, D0=0xbd118, ...]`;ctor 0xbcf3e、dtor 0xbd0aa;VFXEmitterManager::StartEmitter 分配 `new 0x80(128)`

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*thisa = off_456358` |
| 0x04 | VFXEffect* | pOwner | InitEmitters `*(GetEmitter()+1) = this` |
| 0x08 | float | flMaxLifetime | ctor this+2 = 1.0f;SetMaxLifetime 0xbd380 |
| 0x0C | float | flAge? | ctor this+3 = 0 |
| 0x10 | Vector3 | flAcceleration | ctor this+4/5/6 = Zero |
| 0x28 | uint | nField_28 | ctor this+10 = 0 |
| 0x2C | byte | bRotation | ctor byte+44 = 1;CompleteInit `ParticleBuffer(..., *(BYTE*)(this+46))` |
| 0x2D | uint/word | nField_2D | ctor dword+45=0, word+49=0 |
| 0x4C | Vector2 | flUVFrameSize | ctor this+19/20 = Vector2::One;SetUVFrameSize 0xbd9c6 |
| 0x54 | uint | nBlendMode | ctor this+21 = 3 |
| 0x58 | void* | pColourEnvelope | CompleteInit 0xbd144 `this+22 = EnvelopeManager::GetHandle` |
| 0x5C | void* | pScaleEnvelope | CompleteInit `this+23 = GetHandle` |
| 0x64 | uint | dwTextureHandle | ctor this+25 = 0 |
| 0x68 | uint | dwEffectHandle | ctor this+26 = 0 |
| 0x70 | uint | nField_70 | ctor this+28 = 0 |
| 0x74 | SceneGraphNode* | pNode | CompleteInit `this+29 = new SceneGraphNode(0x98)`(vtable 0x456318,node+37=emitter);dtor `(*(node->vtable+24))(node)` |
| 0x78 | ParticleBuffer* | pParticleBuffer | CompleteInit/ctor this+30 = new 0x28;dtor delete |
| 0x7C | uint | nMaxParticles | ctor this+31 = 32(word+62) |

- **回写建议:新建 128B**

## 20. VFXEmitterManager — 4100B,恢复完成 ✓(原 1B 占位)

- vtable `0x456374`:`[0,0, D1=0xbf460, D0=0xbf462, StartEmitter=0xbf468, ...]`;ctor 0xbf406
- ctor:`*thisa = off_45637C; bzero(this+4, 4096)` → 内联 512 槽数组

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor |
| 0x04 | sEmitterSlot[512] (8B×512) | emitters | StartEmitter 扫描 `*(BYTE*)(this+8*i+4)`;写 `*(WORD*)(this+8*i+4)=257(0x101)`;`*(DWORD*)(this+8*i+8) = new VFXEffectEmitter` |

- 槽 = `{u32 flags(0x101=running), VFXEffectEmitter* pEmitter}`;GetEmitter 0xbf568、KillEmitter 0xbf4ec
- **回写建议:新建 4100B + sEmitterSlot 8B**

## 21. ParticleEmitter — 136B,恢复完成 ✓(原 1B 占位)

- vtable `0x4556d0`:`[0,0, D1=0x5e358, D0=0x5e35e, GetComponentID=0x60676, GetComponentName=0x6067e, ...]`;ctor 0x5e1fc、dtor 0x5e2d2
- 继承 cEntityComponent(16B),与 VFXEffectEmitter 结构高度相似:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*thisa = off_4556D8` |
| 0x04 | cEntityComponent base | (16B) | ctor 调基类 |
| 0x10 | float | flMaxLifetime | ctor this+4 = 1.0f;SetMaxLifetime 0x5e658 |
| 0x14..0x20 | uint×4 | nField_14..20 | ctor this+5..8 = 0 |
| 0x24 | Vector3 | flAcceleration | ctor this+9/10/11 = Zero;SetAcceleration 0x5edc4 |
| 0x30 | byte | bRotation | ctor byte+48=1;SetMaxNumParticles `*(BYTE*)(this+51)` |
| 0x31 | dword | nField_31 | ctor dword+49=0, byte+53=0 |
| 0x50 | Vector2 | flUVFrameSize | ctor this+20/21 = One;SetUVFrameSize 0x5edae |
| 0x58 | uint | nBlendMode | ctor this+22 = 3 |
| 0x5C/0x60 | uint | nField_5C/60 | ctor this+23/24 = 0 |
| 0x64 | uint | dwTextureHandle | SetRenderResources 0x5e668 `this+25 = TextureManager::find(hash)` |
| 0x68/0x6C | float | flUVWidth/Height | SetRenderResources `this+26/27 = tex w/h` |
| 0x70 | uint | dwEffectHandle | SetRenderResources `this+28 = EffectManager::find` |
| 0x74 | uint | nField_74 | ctor this+29 = 0 |
| 0x78 | uint | nRenderLayer | ctor this+30 = 3;SetLayer 0x5ee02 `*(this+120) = layer` |
| 0x7C | SceneGraphNode* | pNode | dtor `(*(vtable+24))(this+31)`;SetLayer 写 `node+72` |
| 0x80 | ParticleBuffer* | pParticleBuffer | SetMaxNumParticles 0x5e55c `this+32 = new 0x28`;dtor delete |
| 0x84 | uint | nMaxParticles | ctor this+33 = 32;SetMaxNumParticles `this+33 = a3` |

- **回写建议:新建 136B**

## 22. PostProcessor — 136B,恢复完成 ✓(原 1B 占位)

- **无 vtable**(ctor 首写 `*(a1)=3`);ctor 0xb68ce、dtor 0xb702a、PostProcess 0xb71b8

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | uint | nField_00 | ctor = 3 |
| 0x04 | GameRenderer* | pRenderer | ctor `this+1 = a2` |
| 0x08 | uint | dwVertDescHandle | ctor `this+2 = Add(0,0,3)+Add(1,0,2)` |
| 0x0C | uint | dwVertexBufferHandle | ctor `this+3 = CreateVB(10,6,20)` |
| 0x10/0x14 | uint | nField_10/14 | ctor this+4/5 = -1 |
| 0x18/0x1C | uint | nField_18/1C | ctor this+6/7 = 0 |
| 0x20..0x2C | uint×4 | nField_20..2C | ctor this+8..11 = -1 |
| 0x30/0x34 | uint | dwEffectHandle_blurh/blurv | ctor Load "shaders/blurh.ksh"/"blurv.ksh" |
| 0x38 | uint | dwEffectHandle_colourcube | ctor Load "shaders/combine_colour_cubes.ksh" |
| 0x3C..0x48 | uint×4 | dwEffectHandle[4] | ctor off_4562B4 数组 Load |
| 0x4C..0x58 | uint×4 | bloom handles | ctor 循环 -1;CreateBloomResources 0xb6da0 填充 |
| 0x5C | uint | nField_5C | ctor this+23 = 0 |
| 0x60 | float | flField_60 | ctor this+24 = 1.0f |
| 0x64 | uint | nField_64 | ctor this+25 = 0 |
| 0x68 | Vector3 | flOffset | ctor this+26/27/28(Zero + MEMORY[0x465640]) |
| 0x74/0x78/0x7C | float | flField_74/78/7C | ctor this+29/30/31 = 1.0f |
| 0x80 | cEventDispatcher* | pEventDispatcher | ctor `this+32 = a3` |
| 0x84 | byte | bField_84 | ctor byte+132 = 0 |

- dtor 0xb702a:Release RT(+0x44 via renderer+416)、tex(+0x40 via +396)、vertdesc(+8)、vb(+0xC)、effects(+0x30..0x48 via renderer+412)
- **回写建议:新建 136B**

## 23. HWEffect — 见 #16(Effect/HWEffect/Shader)

## 24. AutoShaderConstant — 9B,插件先验已存在 ✓ 验证通过(无需重建)

- 无 vtable;ctor 0x1d500e/0x1d50a8、dtor 0x1d5164
- 插件 9B 验证:`+0 = value(Matrix4* 或 float* 数据)`,`+4 = Renderer*`,`+8 = bPushed(byte)`;ctor:`*(a1)=a4; *(a1+4)=a2; *(a1+8) = (a3==0)`(Condition:0=OnPush,2=CheckStack)
- **回写建议:已存在(9B),验证通过 ✓**

## 25. VertexElement — 枚举类型(无独立 struct)

- 仅枚举 `VertexElement::Type`(值 0..5,对应 GL 类型表 dword_3C8340;HWVertexDescription::Set 断言 `< 6`)
- 在 BaseVertexDescription::Attribute 中以 `uint elementType@+4` 出现
- **回写建议:新建枚举(0..5),无 struct**

## 26. Parameter — 枚举类型(无独立 struct)

- `Parameter::Type` 枚举,0x2A(42)项;GetNumRows 0x1cf2fe / GetNumColumns 0x1cf378 查表 dword_3C8360
- 用于 ShaderParameter/ShaderParameterData(Shader 参数系统)
- **回写建议:新建枚举(42 项,值未逐个枚举)**

## 27. ITextRenderer — 抽象接口(无 ctor)

- 接口,仅派生类(如 BitmapFontRenderer)有实现;嵌套类型:
  - `ITextRenderer::Params` = **88B**:`{uint dwFontHandle@0(-1), uint?@4, WorkingVB@8(64B), GameRenderer* pRenderer@0x48, BitmapFontManager* pFontManager@0x4C, uint dwVertDescHandle@0x50, uint dwEffectHandle@0x54}`(BitmapFontRenderer::RenderText 0xae384 证据)
  - `ITextRenderer::FontVBData` = **48B**:`{uint nVertCount[4]@0, uint dwVertexBufferHandle[4]@0x10, uint nVertCap[4]@0x20}`(GenerateVB 0xae8a2)
  - `ITextRenderer::FontEffectType` 枚举(0..2:normal/packed/outline)
- **回写建议:新建接口标记 + Params 88B + FontVBData 48B**

## 28. RenderLayer — 枚举类型

- `RenderLayer::Type` 枚举;GameRenderer 内嵌 `FixedStack<RenderLayer::Type,8> @ +0x744`(PushActiveLayer 0xb3878),每层 8B 状态数组 @+0x6B4/+0x6FC
- 枚举值未在二进制中直接枚举(ParticleEmitter::SetLayer / cAnimStateComponent::SetLayer 仅透传)
- **回写建议:新建枚举标记(值待查),FixedStack<Type,8> = 8×4B + count**

---

## 回写建议汇总表

| 类型名 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| BaseRenderer | 新建(仅 vtable)/跳过 | 4B | vtable 0x463700;D1 0x1db332 |
| BaseTexture | 新建 | 20B | ctor 0x1c4872/0x1c4944;Serialize 0x1c4a3c |
| BitmapFont | 新建 | 68B | ctor 0xa8bea;Load 0xa8d4c(字段全集) |
| BitmapFontManager | 新建 | 88B | ctor 0xac7c6;dtor 0xac91a;vtable 0x456160 |
| BitmapFontRenderer | 新建 | 96B(+WorkingVB 64B) | ctor 0xade62;RenderText 0xae384 |
| Batcher | 已存在 68B,验证通过 | 68B | ctor 0xa7fd0 + dtor 0xa8140 + Flush 0xa81ca |
| VertexDescription | 新建 | 24B | vtable 0x45f450;D1 0x135750 |
| BaseVertexDescription | 新建 | 24B | ctor 0x1c4d8e;Add 0x1c4dfe;vtable 0x45f460 |
| Atlas | 新建 | 28B(+Region 24B) | ctor 0xa571c;GetRegion 0xa6252;alloc 0x1C |
| AtlasManager | 新建 | 64B | ctor 0xa6fbc;vtable 0x456130 |
| HWRenderTarget | 新建 | 32B | ctor 0x1cae02;CreateRenderTarget alloc 0x20 |
| RenderTarget | 新建(抽象) | 4B | vtable 0x463360;D1 0x1ce3b0 |
| RenderTargetManager | 新建 | 148B | vtable 0x463490;FrameDelayed C2 0x1d84ea |
| RenderState | 已存在 372B,验证通过 | 372B | ctor 0x1db33a + CommonReset 0x1cacaa |
| UIRenderAssetManager | 已存在 32B,验证通过 | 32B | ctor 0xbca16;vtable 0x456300 |
| TextureNode | 跳过(二进制不存在) | — | func_query/type 全空 |
| VideoNode | 新建 | 276B | ctor 0xc883a;vtable 0x456550 |
| Effect | 新建 | 164B | ctor 0x1c6604;DoLoad alloc 0xA4 |
| EffectManager | 新建 | 148B | vtable 0x457720;DoLoad 0x1c54d4 |
| VFXEffect | 新建 | 28B | ctor 0x85d1c;InitEmitters 0x85e70 |
| VFXEffectEmitter | 新建 | 128B | ctor 0xbcf3e;StartEmitter alloc 0x80 |
| VFXEmitterManager | 新建 | 4100B | ctor 0xbf406;StartEmitter 0xbf468 |
| ParticleEmitter | 新建 | 136B | ctor 0x5e1fc;SetRenderResources 0x5e668 |
| PostProcessor | 新建 | 136B | ctor 0xb68ce;dtor 0xb702a |
| HWEffect | 新建 | 160B | ctor 0x1c6662;dtor 0x1c6990 |
| AutoShaderConstant | 已存在 9B,验证通过 | 9B | ctor 0x1d500e |
| VertexElement | 新建枚举 | — | HWVertexDescription::Set 0x1cf034 |
| Parameter | 新建枚举 | — | GetNumRows 0x1cf2fe |
| ITextRenderer | 新建接口+Params 88B | — | RenderText 0xae384;GenerateVB 0xae8a2 |
| RenderLayer | 新建枚举 | — | PushActiveLayer 0xb3878 |

## 遗留 / UNKNOWN 标注

- BaseTexture +0x0C(4B)未初始化,c语义未定
- BitmapFont +0x14、FallbackFontData 内部布局未完全验证
- BitmapFontManager 0x2C 处 vec 语义(可能是 FallbackFontData 列表)未定
- cResourceManager +0x04(4B)未初始化
- Atlas::Region 后 20B 字段未拆(x/y/w/h/flip 等猜测)
- HWEffect eastl::rbtree 精确 header 偏移(0x48/0x64)由 dtor DoNukeSubtree 反推
- VFXEffectEmitter 0x70、ParticleEmitter 0x74 等"0 初始化字段"语义未定
- PostProcessor bloom handles 精确语义由 CreateBloomResources 0xb6da0 决定(未深挖)
- RenderLayer::Type 枚举值未枚举(依赖 GameRenderer 层数组)
- std::string 为 4B 旧 ABI(重要前提,回写时需以 4B 计算偏移)
