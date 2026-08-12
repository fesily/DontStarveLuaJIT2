# 剩余渲染内部类恢复报告 — remaining-a-render.md (2026-08-08)

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp(get_struct_layout/read_memory/get_xrefs_to)+ idalib-mcp(func_query/decompile,会话 c1f3f184)
> 约束:只读,未回写 Ghidra;每类型 decompile ≤2 次
> 前置:cResourceManager<T,uint,FakeLock> 基类 = 64B(0x40,见 tier3-a-rendering.md);FrameDelayedResourceManager<T> = 148B(0x94)= cResourceManager + CS@0x40 + 6 dword@0x78 + pRenderer@0x90;SceneGraphNode = 0x94 (148B);std::string = 4B 旧 ABI;RenderState = 372B (0x174)

## 跨类型关键发现(Renderer 布局族)

Renderer::InitializeOffMainThread (0x1d4354) 一次性揭示 Renderer 的 7 个管理器指针 + 1 个大对象,与 Ghidra 现有 Renderer struct 完全吻合:

| Renderer 偏移 | 语义 | 证据 |
|---|---|---|
| 0x184 (+97) | ShaderConstantSet* | new(0x1B64) → 0x1d4354 |
| 0x18C (+99) | TextureManager* | new(0x94), vtable 0x4578C8 |
| 0x190 (+100) | VertexDescriptionManager* | new(0x94), vtable 0x4578F8 |
| 0x194 (+101) | VertexBufferManager* | new(0x94), vtable 0x463678;CreateVB 用 `renderer+404` |
| 0x198 (+102) | IndexBufferManager* | new(0x94), vtable 0x4635E8;CreateIB 用 `renderer+408` |
| 0x19C (+103) | EffectManager* | new(0x94), vtable 0x457728;所有 Effect Load 经 `renderer+412` vtable+32 |
| 0x1A0 (+104) | RenderTargetManager* | new(0x94), vtable 0x463498 |
| 0x1B4/0x1B8 | FrameOver 回调节点(自指 0x1B4) | Renderer C2 0x1d415a |

- **cGame+0x30 = Renderer*(GameRenderer)**:ShadowManagerComponent::OnSetEntity (0x713ec) `v3 = *(cGame+48)` 后传给 ShadowRenderer。GroundCreep/MiniMapComponent 同链:`*(entity+64)=cSimulation`,`*(cSimulation+92)=cGame`。
- **cGame+0x4C = AtlasManager***:MOTDImageLoader::UnloadMOTDImage (0x25c86) 用 `*(cGame+76)` 做 Atlas Release。
- 5 个 Buffer 管理器(Index/Vertex/Texture/VertexDescription)DoLoad 均为调试桩:`AssertFunc("BREAKPT:",20,".../IndexBufferManager.h")`,实际创建在 Renderer::CreateVB/CreateIB/TextureManager::DoLoad。
- 渲染子类大量继承 **SceneGraphNode (0x94)**:ShadowRenderer/ParticleBufferRenderer/VFXParticleBufferRenderer/TextNode 均在 0x94 之后放自有字段。

---

### VertexBuffer
- 状态: 待恢复(Ghidra 1B 占位)
- 大小: 0x14 = 20B(`Renderer::CreateVB` 0x1d476e `new(0x14)`)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x4578A8 | CreateVB `*(v6)=off_4578A8`(覆盖 HWBuffer vtable) |
| 0x04 | uint | nStride | HWBuffer C2 0x1c6260 `this+4 = a3` |
| 0x08 | uint | nCount | HWBuffer C2 `this+8 = a4` |
| 0x0C | uint | UNKNOWN_0x0C | ctor 未写 |
| 0x10 | uint | eUsage | HWBuffer C2 `this+16 = a2` |

- 证据: ctor 内联(经 CreateVB);D1 0x1cf2bc / D0 0x1cf2c2;TargetType 0x1cf2b6
- 回写建议: 新建 20B(注意与 HWBuffer 重叠,建议先建 HWBuffer)

### IndexBuffer
- 状态: 待恢复(1B 占位)
- 大小: 0x14 = 20B(`Renderer::CreateIB` 0x1d485e `new(0x14)`)
- 字段: 同 VertexBuffer(vtable → 0x457888;HWBuffer 基类同布局)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x457888 | CreateIB `*(v6)=&unk_457888` |
| 0x04 | uint | nStride | HWBuffer C2 |
| 0x08 | uint | nCount | HWBuffer C2 |
| 0x10 | uint | eUsage | HWBuffer C2 |

- 证据: D1 0x1cf284 / D0 0x1cf28a;TargetType 0x1cf27e
- 回写建议: 新建 20B

### HWBuffer
- 状态: 待恢复(1B 占位)
- 大小: 0x14 = 20B(VertexBuffer/IndexBuffer 基类,new 同 0x14)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x457758 | C2 `*(a1)=&unk_457758` |
| 0x04 | uint | nStride | C2 `*(a1+4)=a3` |
| 0x08 | uint | nCount | C2 `*(a1+8)=a4` |
| 0x0C | uint | UNKNOWN_0x0C | ctor 未写 |
| 0x10 | uint | eUsage | C2 `*(a1+16)=a2` |

- 证据: C2 0x1c6260(0x2c);D2 0x1c62bc / D1 0x1c62bc / D0 0x1c62ec;Init 0x1c6338;Lock(eUsageType,RenderLock::Type) 0x1c63be;Unlock 0x1c64ce
- 回写建议: 新建 20B(VertexBuffer/IndexBuffer 之基类)

### Texture
- 状态: 待恢复(1B 占位)
- 大小: 0x28 = 40B(`TextureManager::DoLoad` 0x1cf486 `new(0x28)`)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x460D88 | C2 `*(this)=&unk_460D88` |
| 0x04 | void* | pMipData | BaseTexture 基类(0x14,插件先验已建) |
| 0x08 | uint | dwFlags | BaseTexture |
| 0x0C | uint | nField_0x0C | BaseTexture |
| 0x10 | str4 | name(std::string) | C2 `std::string::assign(this+16,__s)` |
| 0x14 | uint | UNKNOWN_0x14 | C2 置 0 |
| 0x18 | uint | UNKNOWN_0x18 | C2 置 0 |
| 0x1C | uint | UNKNOWN_0x1C | C2 置 0 |
| 0x20 | uint | UNKNOWN_0x20 | C2 置 0 |
| 0x24 | uint | UNKNOWN_0x24 | C2 置 0 |

- 证据: C2 0x1d7a38(BaseTexture::BaseTexture + 5 dword 清零 + vtable);D0 0x5ad50;C2 经 `j___ZN7TextureC2EPKc` (0x341b6e) 被 DoLoad 调用
- 回写建议: 新建 40B(基类 BaseTexture 已存在 0x14,验证一致)

### HWTexture
- 状态: 待恢复(1B 占位)
- 大小: 0x28 = 40B(与 Texture 同尺寸,均 = BaseTexture + 5 dword 尾)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x457868 | C2 `*(a2)=&unk_457868` |
| 0x04 | void* | pMipData(16B/mip: w@0,h@2,size@8,pad@12) | C2 `new[](0x10)`;DeserializeData 步长 16 |
| 0x08 | uint | dwFlags(PF/type/mipCount 编码) | C2 `((a7&3)<<18)\|(16*(a5&0x1F))\|((a6&0xF)<<9)\|0x2000`;`(>>13)&0x1F`=mip 数 |
| 0x0C | uint | nField_0x0C | BaseTexture |
| 0x10 | str4 | name(std::string) | 日志 `%s` 取 `this+4*4` |
| 0x14 | GLuint | glTextureId | DeserializeData `glGenTextures(1,(GLuint*)this+5)` |
| 0x18 | GLint | wrapS = 33071 (GL_CLAMP_TO_EDGE) | `*(v27+6)=33071` |
| 0x1C | GLint | wrapT = 33071 | `*(v27+7)=33071` |
| 0x20 | GLint | filterMin(9729/9987) | `*(v27+8)=v26` |
| 0x24 | GLint | filterMag = 9729 | `*(v27+9)=9729` |

- 证据: C2 0x1ce730(0x1e4);D2 0x1ce4f0 / D0 0x1ce550;DeserializeData 0x1ce948(0x6db);Destroy 0x1ce91c
- 回写建议: 新建 40B(基类 BaseTexture 复用)

### Renderer
- 状态: 已存在/验证通过(Ghidra 564B,ctor 逐字段吻合)
- 大小: 0x234 = 564B(C2 0x1d415a 写入 +0..+444+CommandBuffer(120B))
- 字段(核对 ctor 0x1d415a + InitializeOffMainThread 0x1d4354):

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x457948 | C2 先设 0x463708(BaseRenderer 区)再覆盖 0x457948 |
| 0x04 | uint | dwField_04 | C2 置 0 |
| 0x08 | uint | dwField_08 | C2 置 0 |
| 0x0C | byte | bField_0C(创建即提交标志) | C2 置 0;CreateVB `if(*(a2+12))` 直接初始化 |
| 0x10 | RenderState(372B) | renderState | C2 `RenderState::RenderState(this+16)`;HWRenderer::Initialize `RenderState::Reset(this+4)` |
| 0x184 | ShaderConstantSet* | pShaderConstantSet | 0x1d4354 `this+97 = new(0x1B64)` |
| 0x188 | uint | dwShaderPushCount | C2 置 0 |
| 0x18C | TextureManager* | pTextureManager | 0x1d4354 `this+99 = new(0x94)` |
| 0x190 | VertexDescriptionManager* | pVertDescMgr | 0x1d4354 `this+100 = new(0x94)` |
| 0x194 | VertexBufferManager* | pVertexBufferMgr | 0x1d4354 `this+101`;CreateVB `*(a2+404)` |
| 0x198 | IndexBufferManager* | pIndexBufferMgr | 0x1d4354 `this+102`;CreateIB `*(a2+408)` |
| 0x19C | EffectManager* | pEffectMgr | 0x1d4354 `this+103 = new(0x94)`;各 ctor `renderer+412` Load |
| 0x1A0 | RenderTargetManager* | pRenderTargetMgr | 0x1d4354 `this+104 = new(0x94)` |
| 0x1A4 | uint | dwField_1A4 | C2 置 0 |
| 0x1A8 | byte[8] | p_gap1A8 | C2 未写 |
| 0x1B0 | uint | dwField_1B0 | C2 置 0 |
| 0x1B4 | uint | listSentinel(自指) | C2 `+109 = this+436` |
| 0x1B8 | uint | listNext(自指) | C2 `+110 = this+436` |
| 0x1BC | CommandBuffer(120B) | cmdBuf | C2 `CommandBuffer::CommandBuffer(this+444)` |

- 证据: C2 0x1d415a;D2 0x1d4262 / D0 0x1d4318;vtable 0x457948;CreateVB/CreateIB/InitializeTextureCmd 全部引用 `renderer+444` CommandBuffer
- 回写建议: 保留现有 struct(验证通过),仅建议重命名 dwField_194→pVertexBufferMgr、dwField_198→pIndexBufferMgr、dwResManager→pTextureManager、dwField_19C→pEffectMgr、dwField_1A0→pRenderTargetMgr

### HWRenderer
- 状态: 待恢复(1B 占位)
- 大小: 与 Renderer 同布局(RenderState@0x10);未发现额外成员(D1 = 1B 空实现),ctor 内联无符号
- 字段: 同 Renderer(见上);HWRenderer::Initialize (0x1cafd0) 仅触碰 Renderer 内字段(RenderState@0x10 及其内部 282/283/308/356/357 字节)
- 证据: vtable 0x457848(含 HWRenderer::D1 0x1cd7e0 / D0 0x1cd7e2,经 get_xrefs_to 定位);Initialize 0x1cafd0;BeginFrame 0x1cc824;EndFrame 0x1cc8b6;CommitRenderState 0x1cd486;BindVertexState 0x1cbdd6;BindIndexState 0x1cc2b2;ResetState 0x1cb9de;GetVendorString/GetRendererString 0x1cb9f4/0x1cba08
- 回写建议: 新建(可与 Renderer 同 0x234 布局),或标记为 Renderer 别名/跳过(无自有数据成员)

### MapRenderer
- 状态: 待恢复(1B 占位)
- 大小: 0x1C = 28B(`GroundCreep::OnInitializationComplete` 0x39b3e `new(0x1C)`)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | GameRenderer* | pGameRenderer | C2 `*(this)=a3` |
| 0x04 | MapLayerManagerComponent* | pLayerMgr | C2 置 0;GroundCreep `*(mapRenderer+4)=v6` |
| 0x08 | uint | dwVertDescHandle | C2 初始 -1 → `cResourceManager<VertexDescription>::Add(renderer+400)` |
| 0x0C | uint | dwEffectHandle_1 | C2 `renderer+412` Load(a4 = "shaders/creep.ksh" 等) |
| 0x10 | uint | dwEffectHandle_2 | C2 Load(a5) |
| 0x14 | uint | nField_0x14 | C2 置 -1 |
| 0x18 | uint | nField_0x18 | C2 置 0 |

- 证据: C2 0x98bfa(0x15b);D2 0x98d5c(0x52);SetOverlayTexture 0x99174;PushBlendFactor 0x98e08;创建者 GroundCreep(非 MapComponent)
- 回写建议: 新建 28B(非 SceneGraphNode,无 vtable 字段——首字段即 GameRenderer*)

### MiniMapRenderer
- 状态: 待恢复(1B 占位)
- 大小: 0xE4 = 228B(`MiniMapComponent::OnInitializationComplete` 0x4fe70 `new(0xE4)`,存于 component+0x3C)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | uint | nField_0x00 | C2 置 -1 |
| 0x04 | uint | dwEffectHandle_minimap | C2 Load("shaders/minimap.ksh",renderer+412) |
| 0x08 | uint | dwEffectHandle_blend | C2 Load("shaders/minimapblend.ksh") |
| 0x0C..0x28 | uint×8 | dwField_0C..(句柄,置 -1) | C2 +3..+10 = -1 |
| 0x2C | Vector2<uint> | vec2_0x2C = Zero | C2 `+11 = Vector2<uint>::Zero` |
| 0x34 | uint | nField_0x34 = unk_465660 | C2 `+12` |
| 0x38 | uint | dwVertDescHandle | C2 `+13 = cResourceManager<VertexDescription>::Add` |
| 0x3C | uint | nField_0x3C | C2 置 -1 |
| 0x40 | MiniMapComponent* | pComponent | C2 `+15 = a4` |
| 0x44 | GameRenderer* | pRenderer | C2 `+16 = *(comp+0x30)` |
| 0x48 | uint | nField_0x48 | C2 `+17 = *(comp+0x4C)` |
| 0x4C | uint | nField_0x4C | C2 `+18 = *(*(comp+0x20)+0x40)` |
| 0x50 | uint | nField_0x50 | C2 `+19 = *(comp+0x20)` |
| 0x54 | uint | nField_0x54 = 3 | C2 `+20 = 3` |
| 0x58 | Vector2<float> | vec2_0x58 = Zero | C2 `+21 = Vector2<float>::Zero` |
| 0x5C | uint | nField_0x5C = unk_465634 | C2 `+22` |
| 0x60 | word | wField_0x60 = 1 | C2 `+24(word)=1` |
| 0x62 | byte | bField_0x62 = 0 | C2 `+98` |
| 0x64 | vector<ShowAreaElement> | vecShowArea(12B) | C2 `+25..27 = 0`;`reserve(this+100, 100)` |
| 0x70 | uint | listSentinel(自指 0x70) | C2 `+28 = this+112` |
| 0x74 | uint | listNext(自指 0x70) | C2 `+29 = this+112` |
| 0x78 | Matrix4 | mat4(64B) = Zero | C2 `+120..+184` 4×OWORD Zero |
| 0xB8..0xD4 | uint | nField_0xB8..(0xE0) | C2 `+46..+55` 置 0 |
| 0xE0 | byte | bField_0xE0 | C2 置 0 |

- 证据: C2 0x52986(0x2f2);D2 0x52c7e(0x1e9);CacheRender 0x54ab0;InitializeResources 0x562d4;SetEffects 0x52e6e;AddAtlas 0x55362
- 回写建议: 新建 228B(注意:无 vtable 指针,首字段即数据;0x78 处 Matrix4 与 0x70 list 相邻)

### ShadowRenderer
- 状态: 待恢复(1B 占位)
- 大小: 0xA8 = 168B(`ShadowManagerComponent::OnSetEntity` 0x713ec `new(0xA8)`,存于 component+0x10)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | SceneGraphNode(0x94) | sgn 基类 | C2 `SceneGraphNode::SceneGraphNode(this,game,nameHash("ShadowRenderer"))` |
| 0x48 | uint | nField_0x48 = 1 | C2 `+18 = 1`(SGN 内) |
| 0x94 | uint | nField_0x94 | C2 `+37 = -1` |
| 0x98 | uint | dwVertDescHandle | C2 `+38 = cResourceManager<VertexDescription>::Add(renderer+400)` |
| 0x9C | uint | dwEffectHandle | C2 `+39 = Load("shaders/splat.ksh",renderer+412)` |
| 0xA0 | ShadowManagerComponent* | pManager | C2 `+40 = a4` |
| 0xA4 | Renderer* | pRenderer | C2 `+41 = a5`(即 cGame+0x30) |

- 证据: C2 0x715a4(0x13f);D2 0x714fa(0x77);vtable 0x455978;SetTexture 0x71484
- 回写建议: 新建 168B(基类 SceneGraphNode 0x94)

### DebugRenderer
- 状态: 待恢复(1B 占位)
- 大小: 0x58 = 88B(与 GraphRenderer 同尺寸;GameRenderer::InitializeOffMainThread 0xb3516 `new(0x58)` ×3,存于 GameRenderer+0x7A0/+0x7A8/+0x7B0)
- 字段: 继承 GraphRenderer(无新增成员;唯一区别 vtable + 虚覆盖)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x460D28 | 初始化时 `*(v11)=&unk_460D28`(GraphRenderer ctor 的 0x456258 被覆盖) |
| 0x04..0x3C | 见 GraphRenderer | 同基类 | — |
| 0x40 | vector<sDebugLineInfo> | vecDebugLines | `SubmitDebugLine_FromRenderCode` 0xb22a4 `push_back(a1+40)` |

- 证据: vtable 0x460D28 含 DebugRenderer::D1 0xb3f92 / D0 0xb3f98 + GraphRenderer::SubmitTriangle/Clear/SubmitString + DebugRenderer::SubmitDebugTriangle 0xb3fc4 / SubmitDebugLine 0xb3fc6 / SubmitCircle 0xb3fc8 → **DebugRenderer : GraphRenderer**(仅覆盖 D1/D0/三角/线/圆虚函数)
- 回写建议: 新建 88B(继承 GraphRenderer;D1/D0 用 DebugRenderer 的 0xb3f92/0xb3f98)

### GraphRenderer
- 状态: 待恢复(1B 占位)
- 大小: 0x58 = 88B(`new(0x58)`;GameRenderer 持 3 实例)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x456258 | C2 `*(this)=off_456258` |
| 0x04 | vector<sTriangleSubmission> | vecTriangles(12B) | C2 置 0;SubmitTriangle 0xb1644 `push_back(a1+4)` |
| 0x10 | uint | nField_0x10 | C2 置 0 |
| 0x14 | uint | nField_0x14 | C2 置 0 |
| 0x18 | uint | nField_0x18 | C2 置 0 |
| 0x1C | vector<sStringSubmission> | vecStrings(12B) | C2 置 0;SubmitString 0xb1626 `push_back(a1+28)` |
| 0x28 | vector<sDebugLineInfo> | vecDebugLines(12B) | C2 置 0(见 DebugRenderer) |
| 0x34 | uint | nField_0x34 | C2 置 0 |
| 0x38 | uint | nField_0x38 | C2 置 0 |
| 0x3C | GameRenderer* | pGameRenderer | C2 `+15 = a3` |
| 0x40 | uint | dwEffectHandle_1 | C2 `+16 = Load(renderer+412 vtable+32)`(debug_line.ksh) |
| 0x44 | uint | dwEffectHandle_2 | C2 `+17 = Load("shaders/debug_tri.ksh")` |
| 0x48 | uint | dwVertDescHandle_1 | C2 `+18 = VertexDescription::Add`(pos+uv+colour 等) |
| 0x4C | uint | dwVertDescHandle_2 | C2 `+19 = Add`(第二组属性) |
| 0x50 | uint | dwEffectHandle_3 | C2 `+20 = Load(renderer+412 vtable+36)` |
| 0x54 | uint | dwEffectHandle_4 | C2 `+21 = Load(...)` |

- 证据: C2 0xb0d76(0x2c6);D2 0xb1042(0x133);DrawTriangles 0xb1ace;DrawDebugLines 0xb1936;DrawStrings 0xb1662;DrawAxes 0xb1e70;Clear 0xb15fc
- 回写建议: 新建 88B

### VFXParticleBufferRenderer
- 状态: 待恢复(1B 占位)
- 大小: 0x98 = 152B(`VFXEffectEmitter::CompleteInit` 0xbd233 `new(0x98)`,存于 emitter+0x74)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | SceneGraphNode(0x94) | sgn 基类 | C2 `SceneGraphNode::SceneGraphNode(this)`(无参) |
| 0x94 | VFXEffectEmitter* | pEmitter | C2 `+37 = a3` |

- 证据: C2 0xbce3a(0x31);vtable 0x456318(CompleteInit `*(v4)=4547352`);D0 0xbceaa / D1 0xbcea4;RendersAlpha 0xbf13a;CalculateAABB 0xbced6;DoCacheForRender 0xbda26
- 回写建议: 新建 152B(基类 SceneGraphNode 0x94)

### ParticleBufferRenderer
- 状态: 待恢复(1B 占位)
- 大小: 0xA0 = 160B(`ParticleEmitter::OnSetEntity` 0x5e4a0 `new(0xA0)`,存于 emitter+0x7C)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | SceneGraphNode(0x94) | sgn 基类 | C2 `SceneGraphNode::SceneGraphNode(this)` |
| 0x48 | uint | nField_0x48 | C2 `+18 = *(emitter+120)`(SGN 内) |
| 0x94 | GameRenderer* | pRenderer | OnSetEntity `+37 = *(cGame+0x30)` |
| 0x98 | ParticleEmitter* | pEmitter | OnSetEntity `+38 = thisa` |
| 0x9C | uint | nField_0x9C | OnSetEntity `+39 = *(GameRenderer+0x7D8)` |

- 证据: C2 0x5e0b6(0x50);vtable 0x455698;D0 0x5e162;CalculateAABB 0x5e18e;DoCacheForRender 0x6025a;ManualSortOrder 0x60662;RendersAlpha 0x60658
- 回写建议: 新建 160B(基类 SceneGraphNode 0x94)

### TextNode
- 状态: 待恢复(1B 占位)
- 大小: 0x164 = 356B(`cLabelComponent::OnSetEntity` 0x40d98 `new(0x164)`,存于 component+0x10;cLabelComponent 后续再改 +72=3、+76=0xFF、+244=1)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | SceneGraphNode(0x94) | sgn 基类 | C2 `SceneGraphNode(this,game,nameHash)` |
| 0x94 | uint | dwVertDescHandle | C2 `+37 = -1`(两处) |
| 0x98 | float | flFontScale = 10.0 | C2 `+38 = 0x41200000` |
| 0x9C | float | flField_0x9C = 1.0 | C2 `+39 = 1065353216` |
| 0xA0 | float | flMax_0xA0 = FLT_MAX | C2 `+40` |
| 0xA4 | float | flMax_0xA4 = FLT_MAX | C2 `+41` |
| 0xA8 | uint | nField_0xA8 | C2 置 0 |
| 0xAC | byte | bField_0xAC | C2 置 0 |
| 0xB0 | uint | nField_0xB0 = 2 | C2 `+44 = 2` |
| 0xB4 | uint | nField_0xB4 = 2 | C2 `+45 = 2` |
| 0xB8 | Colour | colour = White | C2 `+46` |
| 0xBC..0xF0 | uint×13 | 句柄组(置 -1/-1/0 ×4) | C2 循环 `+49..+60` |
| 0xF4 | uint | nField_0xF4 | C2 `+61..+63`=0 |
| 0x100 | Vector3 | vec3_0x100 = Zero | C2 `+64/QWORD 31` |
| 0x10C | Vector3 | vec3_0x10C = Zero | C2 `+67/QWORD 260` |
| 0x110 | byte | bField_0x110 | C2 置 0 |
| 0x114 | byte | bField_0x114 = 1 | C2 `+145 = 1` |
| 0x118 | byte | bField_0x118 = 1 | C2 `+272 = 1` |
| 0x11C | str4 | strText(std::string,空串) | C2 `+69 = empty_rep+12` |
| 0x120 | byte | bField_0x120 | C2 置 0 |
| 0x121 | byte | bField_0x121 = 1 | C2 `+281` |
| 0x122 | byte | bField_0x122 = 1 | C2 `+282` |
| 0x124 | uint | nField_0x124 | C2 置 0 |
| 0x128 | uint | nField_0x128 | C2 置 0 |
| 0x12C | uint | nField_0x12C = -1 | C2 `+73 = -1` |
| 0x130 | float | flAABB_max ×3 = FLT_MAX | C2 `+74..+76` |
| 0x13C | float | flAABB_min ×3 = -FLT_MAX | C2 `+77..+79` |
| 0x148 | uint | nField_0x148 | C2 置 0 |
| 0x14C | uint | nField_0x14C | C2 置 0 |
| 0x150 | Colour | colour2 = White | C2 `+88` |
| 0x160 | uint | nField_0x160 | cLabelComponent 置 3(+72) |

- 证据: C2 0xc6626(0x1d1);D2 0xc67fe(0xcd);vtable 0x4564F8;SetString 0xc6ab4;SetFont 0xc696a;SetHAnchor/SetVAnchor 0xc68fe/0xc6934;EnableWordWrap 0xc6b9e;DoCacheForRender 0xc6dee;GetRegionSize 0xc6c3e
- 回写建议: 新建 356B(基类 SceneGraphNode 0x94;字符串字段为 4B 旧 ABI)

### LightBuffer
- 状态: 待恢复(1B 占位)
- 大小: 0x58 = 88B(`tRenderJobThread::InitializeOffMainThread` 0xb58a `new(0x58)`,存于 thread+0xA0)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x456428 | C2 `*(a1)=4547240` |
| 0x08 | uint×2 | listNode(置 0) | C2 `+2/+3 = 0` |
| 0x10 | uint | listSentinel(自指 0x08) | C2 `+4 = a1+8` |
| 0x14 | uint | listNext(自指 0x08) | C2 `+5 = a1+8` |
| 0x18 | uint | nField_0x18 | C2 置 0 |
| 0x1C | GameRenderer* | pRenderer | C2 `+7 = a2` |
| 0x20..0x34 | float×6 | ColourAABB(min/max) | C2 `+8..+13`(FLT_MAX/-FLT_MAX) |
| 0x38 | byte | bField_0x38 | C2 置 0 |
| 0x3C | uint | nField_0x3C | C2 置 0 |
| 0x40 | uint | nField_0x40 = -1 | C2 `+16` |
| 0x44 | uint | nField_0x44 = -1 | C2 `+17` |
| 0x48 | uint | dwVBHandle | C2 `+18 = Renderer::CreateVB(renderer,9,6,12,data)` |
| 0x4C | uint | dwVertDescHandle | C2 `+19 = VertexDescription::Add(renderer+400)` |
| 0x50 | uint | dwEffectHandle | C2 `+20 = Load(renderer+412)`("shaders/light.ksh") |
| 0x54 | cEventDispatcher* | pDispatcher | C2 `+21 = a3`;RegisterListener(a3,a1,1) |

- 证据: C2 0xb40b6(0x254);D2 0xb4482(0x8b);vtable 0x456428;CreateResources 0xb430a;CacheForRender 0xb46f0(0x9ce);DrawCache 0xb50be;HandleEvent 0xb4678
- 回写建议: 新建 88B

### ParticleBuffer
- 状态: 待恢复(1B 占位)
- 大小: 0x28 = 40B(`ParticleEmitter::SetMaxNumParticles` 0x5e5ba / `VFXEffectEmitter::CompleteInit` 0xbd233 / `OnPrefabConstructorComplete` 0x5e445 均 `new(0x28)`)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | uint | dwColour0 = 0xFF000000 | C2 循环写 2 dword |
| 0x04 | uint | dwColour1 = 0xFF000000 | C2 循环写 |
| 0x08 | ushort | wField_0x08 | C2 置 0 |
| 0x0C | void* | pParticleDataA(n×12B) | C2 `new[](12*n+4)` 头存 n,数据 +1 |
| 0x10 | void* | pParticleDataB(n×12B) | C2 同上 |
| 0x14 | void* | pRotationData(n×8B,可选) | C2 若 bRotations:`new[](8*n+4)` 并清零 |
| 0x18 | void* | pDataC(n×4B) | C2 `new[](4*n)` |
| 0x1C | void* | pDataD(n×4B) | C2 `new[](4*n)` |

- 证据: C2 0xb6096(0xbf);D2 0xb617c(0xb0);Update 0xb6462(0x46b);AddParticle 0xb626a;AddRotatingParticle 0xb6348;CreateRotationComponents 0xb623e;C1 签名 `C2Etb`(ushort 数量,bool 旋转)
- 回写建议: 新建 40B

### WallStencilBuffer
- 状态: 待恢复(1B 占位)
- 大小: 0x40 = 64B(`tRenderJobThread::InitializeOffMainThread` 0xb58a `new(0x40)`,存于 thread+0xA4)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x456398 | C2 `*(a1)=off_456398` |
| 0x08 | uint×2 | listNode(置 0) | C2 `+2/+3 = 0` |
| 0x10 | uint | listSentinel(自指 0x08) | C2 `+4 = a1+8` |
| 0x14 | uint | listNext(自指 0x08) | C2 `+5 = a1+8` |
| 0x18 | uint | nField_0x18 | C2 置 0 |
| 0x1C | GameRenderer* | pRenderer | C2 `+7 = a2` |
| 0x20 | uint | nField_0x20 = -1 | C2 `+8` |
| 0x24 | uint | nField_0x24 = -1 | C2 `+9` |
| 0x28 | uint | dwVBHandle | C2 `+10 = Renderer::CreateVB(renderer,9,stride,12,data)` |
| 0x2C | uint | dwVertDescHandle | C2 `+11 = VertexDescription::Add(renderer+400)` |
| 0x30 | uint | dwEffectHandle_depth | C2 `+12 = Load("shaders/render_depth.ksh")` |
| 0x34 | uint | dwEffectHandle_tri | C2 `+13 = Load("shaders/debug_tri.ksh")` |
| 0x38 | cEventDispatcher* | pDispatcher | C2 `+14 = a3`;RegisterListener(a3,a1,1) |
| 0x3C | byte | bField_0x3C | C2 置 0 |

- 证据: C2 0xbf7c6(0x50c);D2 0xbfdec(0xa3);vtable 0x456398;CreateResources 0xbfcd2;RenderToTexture 0xbff18;HandleEvent 0xc0254
- 回写建议: 新建 64B

### IndexBufferManager
- 状态: 待恢复(1B 占位)
- 大小: 0x94 = 148B(`Renderer::InitializeOffMainThread` 0x1d4354 `new(0x94)` 存 Renderer+0x198)
- 字段: FrameDelayedResourceManager<IndexBuffer,uint,FakeLock> 模板布局(见 tier3-a-rendering.md):

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x4635E8 | 0x1d4354 `*v3=&unk_4635E8` |
| 0x04..0x3C | cResourceManager 基类(64B) | 同模板 | C2 0x1da0d2(0x13a)= FrameDelayed 模板 C2 |
| 0x40 | CriticalSection(56B) | cs | 模板 |
| 0x78 | uint×6 | nField_0x78 | 模板 |
| 0x90 | Renderer* | pRenderer | 模板 |

- 证据: FrameDelayed<IndexBuffer> C2 0x1da0d2;D2 0x1da5c4;DoLoad 0x1da21a(调试桩);GetResourceNameType 0x1da20c
- 回写建议: 新建 148B(复用 cResourceManager + FrameDelayed 模板布局)

### VertexBufferManager
- 状态: 待恢复(1B 占位)
- 大小: 0x94 = 148B(`new(0x94)` 存 Renderer+0x194)
- 字段: 同 IndexBufferManager,模板 FrameDelayedResourceManager<VertexBuffer,uint,FakeLock>;vtable → 0x463678
- 证据: FrameDelayed<VertexBuffer> C2 0x1daa02;DoLoad 0x1dab4a(调试桩);GetResourceNameType 0x1dab3c
- 回写建议: 新建 148B

### TextureManager
- 状态: 待恢复(1B 占位)
- 大小: 0x94 = 148B(`new(0x94)` 存 Renderer+0x18C)
- 字段: FrameDelayedResourceManager<Texture,uint,FakeLock>;vtable → 0x4578C8;C2 0x1cf3f2 调 FrameDelayed<Texture> C2 0x1cf6e0 后换 vtable
- 附加证据: DoLoad 0x1cf486 创建 Texture(`new(0x28)`)并 `Renderer::InitializeTexture(thisa[36], ...)` — **thisa[36] = +0x90 = pRenderer** ✓ 模板布局
- 回写建议: 新建 148B

### VertexDescriptionManager
- 状态: 待恢复(1B 占位)
- 大小: 0x94 = 148B(`new(0x94)` 存 Renderer+0x190)
- 字段: FrameDelayedResourceManager<VertexDescription,uint,FakeLock>;vtable → 0x4578F8
- 证据: FrameDelayed<VertexDescription> C2 0x1d9844(0x13a);跨类型佐证:所有 renderer ctor 的 `cResourceManager<VertexDescription>::Add(renderer+400)`
- 回写建议: 新建 148B(与 EffectManager/RenderTargetManager 共用模板;可一次建 3 个)

### ShaderConstantSet
- 状态: 待恢复(1B 占位)
- 大小: 0x1B64 = 7012B(`Renderer::InitializeOffMainThread` 0x1d4354 `new(0x1B64)` 存 Renderer+0x184)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | uint | nField_0x00 | C2 置 0 |
| 0x04..0x1000 | StaticVector<Data,8> + eastl::vector<DataVecInfo> | 常量栈 | C2 前段;PushShaderConstant 0x1d702a 经 `StaticVector<Data,8>::push_back`;DataVecInfo 固定分配器 72B×32 |
| 0x1004 | eastl::fixed_hash_map<uint,uint,32> | hashToIndexMap | C2 `fixed_hash_map(...,(char*)this+4100,...)`;桶指针 +4104/+4108,计数 +4112 |
| 0x1250 | uint×4 | listSentinel(自指 0x1264) | C2 `+1172..1174 = this+4708` |
| 0x1264 | uint | listHead | C2 `+1176 = this+4708` |
| 0x1B64 | — | end | 总尺寸 0x1B64 |

- 证据: C2 0x1d81d2(0xbf);D2 0xbb80(0x35);SetShaderConstantDefaults 0x1d7bc4(0x608);PushShaderConstantHash 0x1d5912;PopShaderConstantHash 0x1d5abe;HWEffect::Commit 0x1c77be 引用
- 回写建议: 新建 7012B(大对象;内部容器建议用 StaticVector/fixed_hash_map 命名,数据区可留 UNKNOWN 段)

### ShaderParameterData
- 状态: 待恢复(1B 占位)
- 大小: ≈0x1C = 28B(D2 释放 +4 与 +16 两处指针)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | uint | dwHash | op=/D2 结构推断 |
| 0x04 | str4 | strName(std::string) | D2 `if(+1) delete` |
| 0x08 | uint | nField_0x08 | 推断 |
| 0x0C | uint | nField_0x0C | 推断 |
| 0x10 | vector<ArrayData> | vecArrayData(12B) | D2 `if(+4) delete`;ArrayData 内嵌类型(见 _Vector_base<ArrayData>) |

- 证据: D2 0x1caa7a(0x2b);op= 0x1ca536(0x3d);Shader::InitParameters 0x1c7b88 填充 `vector<ShaderParameterData>`;ShaderParameterInfo op= 0x1c9be8 同构
- 回写建议: 新建 28B(字段 0x08/0x0C 语义未定;若需精确可再查 Shader::SetParameters 0x1c7824)

### Parameter
- 状态: 跳过(枚举,非 struct)
- 证据: `N9Parameter4TypeE` = Parameter::Type 枚举;GetNumRows/GetNumColumns 0x1cf2fe/0x1cf378、ShouldSerializeDefaults 0x1cf2ed 均以 Type 为参;另见 ShaderConstant::Type(AutoShaderConstant 0x1d500e 使用)
- 回写建议: 跳过(Ghidra 无该名 struct 属正常)

### VertexElement
- 状态: 跳过(枚举,非 struct)
- 证据: `N15VertexElement4TypeE` = VertexElement::Type;`BaseVertexDescription::Add(0x1c4dfe)` 形参 `(VertexAttribute::Type, VertexElement::Type, ushort count)` — 与已建 `Attribute`(nType/nElementType/nCount/nOffset)对应
- 回写建议: 跳过(枚举;已建 Attribute/BaseVertexDescription 覆盖)

### MOTDImageLoader
- 状态: 待恢复(1B 占位)
- 大小: 0x10 = 16B(cGame ctor 0xf878 `mov [esp],0x10; call; mov esi,eax; ...; call MOTDImageLoader ctor`,结果存 **cGame+0x88**)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | cGame* | pGame | C2 `*(this)=a3` |
| 0x04 | uint | nField_0x04 | ctor 未写 |
| 0x08 | uint | dwAtlasHandle = -1 | C2 `+2 = -1`;UnloadMOTDImage 0x25c86 `cResourceManager<Atlas>::Release(*(cGame+0x4C), handle)` |
| 0x0C | str4 | strURL/std::string(空串) | C2 `+3 = empty_rep+12` |

- 证据: C2 0x25ba2(0x24);D2 0x25bea(0x9b);GetMOTDImage 0x25cba;LoadMOTDImage 0x2601c;GetMOTDImageComplete(回调) 0x26136
- 回写建议: 新建 16B

### SoundProjectManager
- 状态: 待恢复(1B 占位)
- 大小: 0x40 = 64B(= cResourceManager<FMOD::EventProject*,uint,FakeLock> 基类,非 FrameDelayed)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable(cResourceManager<EventProject*>) | cResourceManager<...EventProject*> 家族符号齐备 |
| 0x04..0x38 | cResourceManager 基类(64B) | 同模板 | DoLoad/OnUnload |
| 0x3C | cSoundSystem* | pSoundSystem | DoLoad `thisa[15]` = +0x3C 传入 `cSoundSystem::LoadFEV` |

- 证据: DoLoad 0x1828a:`new(4)` + `*v3 = cSoundSystem::LoadFEV(thisa[15], name)`(4B 对象 = FMOD::EventProject*);OnUnload 0x18428(FMOD::EventProject**);GetResourceNameType 0x1827c;D0 0x1844e;cResourceManager<EventProject*> Load 0x1847a / Release 0xeca4e / D2 0x18c5a
- 回写建议: 新建 64B(cResourceManager 基类,复用模板;pSoundSystem 覆盖 +0x3C)

### PixelShader
- 状态: 待恢复(1B 占位)
- 大小: 0x18 = 24B(= Shader 基类,无新增成员)
- 字段: 同已建 Shader(vtable, nHandle, name, +0xC/+0x10/+0x14)
- 证据: InitShader 0x1c82d0 → `Shader::InitShader(this, 0x8B30 /*GL_FRAGMENT_SHADER*/, ...)`;D0 0x1caae4 / D1 0x1c8304
- 回写建议: 新建 24B(继承 Shader;或跳过并在 HWEffect 中标注 vs/ps 为 PixelShader/VertexShader)

### VertexShader
- 状态: 待恢复(1B 占位)
- 大小: 0x18 = 24B(= Shader 基类)
- 字段: 同 Shader
- 证据: InitShader 0x1c8134 → `Shader::InitShader(this, 0x8B31 /*GL_VERTEX_SHADER*/, ...)`;D0 0x1cab10 / D1 0x1c830a
- 回写建议: 新建 24B(继承 Shader)

---

## 回写建议汇总

| 类型名 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| VertexBuffer | 新建 | 0x14 (20B) | CreateVB 0x1d476e new(0x14),vtable 0x4578A8,HWBuffer 基类 |
| IndexBuffer | 新建 | 0x14 (20B) | CreateIB 0x1d485e new(0x14),vtable 0x457888 |
| HWBuffer | 新建 | 0x14 (20B) | C2 0x1c6260:+4 stride/+8 count/+16 usage |
| Texture | 新建 | 0x28 (40B) | DoLoad 0x1cf486 new(0x28);BaseTexture(0x14)基类 + 5 dword |
| HWTexture | 新建 | 0x28 (40B) | C2 0x1ce730;+0x14 glTexId/+0x18..0x24 wrap/filter |
| Renderer | 保留(验证通过) | 0x234 (564B) | C2 0x1d415a 逐字段吻合;仅建议改名 0x194/0x198/0x18C/0x19C/0x1A0 |
| HWRenderer | 新建(同 Renderer 布局) | 0x234 | vtable 0x457848;Initialize 0x1cafd0 仅碰 Renderer 字段 |
| MapRenderer | 新建 | 0x1C (28B) | GroundCreep 0x39b3e new(0x1C);无 vtable |
| MiniMapRenderer | 新建 | 0xE4 (228B) | MiniMapComponent 0x4fe70 new(0xE4);无 vtable |
| ShadowRenderer | 新建 | 0xA8 (168B) | ShadowManagerComponent 0x713ec new(0xA8);SGN(0x94)基类 |
| DebugRenderer | 新建 | 0x58 (88B) | GameRenderer 0xb3516 new(0x58)×3;vtable 0x460D28;: GraphRenderer |
| GraphRenderer | 新建 | 0x58 (88B) | C2 0xb0d76;vtable 0x456258;3 向量 @+4/+28/+40 |
| VFXParticleBufferRenderer | 新建 | 0x98 (152B) | VFXEffectEmitter 0xbd233 new(0x98);SGN 基类 |
| ParticleBufferRenderer | 新建 | 0xA0 (160B) | ParticleEmitter 0x5e4a0 new(0xA0);SGN 基类 |
| TextNode | 新建 | 0x164 (356B) | cLabelComponent 0x40d98 new(0x164);SGN 基类 |
| LightBuffer | 新建 | 0x58 (88B) | tRenderJobThread 0xb58a new(0x58);vtable 0x456428 |
| ParticleBuffer | 新建 | 0x28 (40B) | 3 处 new(0x28);C2 0xb6096 |
| WallStencilBuffer | 新建 | 0x40 (64B) | tRenderJobThread 0xb58a new(0x40);vtable 0x456398 |
| IndexBufferManager | 新建 | 0x94 (148B) | Renderer 0x1d4354 new(0x94);FrameDelayed 模板 |
| VertexBufferManager | 新建 | 0x94 (148B) | 同上;vtable 0x463678 |
| TextureManager | 新建 | 0x94 (148B) | 同上;DoLoad 证 pRenderer@0x90 |
| VertexDescriptionManager | 新建 | 0x94 (148B) | 同上;vtable 0x4578F8 |
| ShaderConstantSet | 新建 | 0x1B64 (7012B) | Renderer 0x1d4354 new(0x1B64);C2 0x1d81d2 |
| ShaderParameterData | 新建 | ≈0x1C (28B) | D2 0x1caa7a;+4 字符串/+0x10 vec<ArrayData> |
| Parameter | 跳过 | — | 枚举 Parameter::Type |
| VertexElement | 跳过 | — | 枚举 VertexElement::Type |
| MOTDImageLoader | 新建 | 0x10 (16B) | cGame ctor 0xf878 new(0x10),存 cGame+0x88 |
| SoundProjectManager | 新建 | 0x40 (64B) | DoLoad 0x1828a;cResourceManager<EventProject*> 基类 |
| PixelShader | 新建 | 0x18 (24B) | InitShader 0x1c82d0 → Shader(GL_FRAGMENT) |
| VertexShader | 新建 | 0x18 (24B) | InitShader 0x1c8134 → Shader(GL_VERTEX) |

## 备注/未决

- Renderer+0x194/0x198 现名 dwField_194/dwField_198,语义为 VertexBufferManager/IndexBufferManager(回写时建议更名)
- HWRenderer 与 Renderer 的继承方向未完全确定(ctor 均内联;HWRenderer::D1 为 1B 空实现)。仅知共享 RenderState@0x10 布局
- ShaderConstantSet 0x04..0x1000 段内 StaticVector<Data,8> 与 vector<DataVecInfo>(72B×32)的精确切分未逐字节定界(Data ≈ 0xE0B);0x1004 fixed_hash_map 边界由 C2 直接给出
- ShaderParameterData 0x08/0x0C 两字段语义未定;TextNode 0xBC..0xF0 句柄组为 -1/-1/0 循环模式
- MiniMapRenderer 0x78 Matrix4 与 0x70 list 的先后以 ctor 顺序为准(+28/+29 自指 0x70)
- DebugRenderer 3 实例存于 GameRenderer+0x7A0/+0x7A8/+0x7B0;GetDebugRenderer(0xb3cf0) 读 +0x78C+4*layer 为旧路径,未在 ctor/初始化中填充(疑为失效代码)
