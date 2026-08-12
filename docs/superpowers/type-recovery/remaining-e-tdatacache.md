# Tier 3-E — 场景图缓存类型恢复报告(只读调查)

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp(程序 dontstarve_steam)+ idalib-mcp(会话 c1f3f184)
> 方法:每个类型 get_struct_layout 查现状 → func_query 定位 ctor/dtor/DoCacheForRender → decompile ≤2 次/类型(IDA 共享)→ 分配大小取自 CacheRenderAllocate/operator new 立即数
> 约束:只读,不回写 Ghidra;本文件为分片报告,回写由主 agent 统一执行

## 关键前置知识

- **TDataCache 系列 = SceneGraphNode 渲染缓存**:每帧由各节点 `DoCacheForRender` 经 `CacheRenderAllocate(size)` 分配,ctor 填入 vtable@0 + 渲染快照字段,再 push_back 进 `std::vector<SceneGraphNode::TDataCacheSceneNode*>`;渲染时 `CacheWorldRender` 遍历,按 `vtable+0x20`(slot 8)调用 DrawCacheRender 分发,清场按 `vtable+4`(slot 1 = D1)析构。
- **缓存对象通用头部**:`vtable@0x00`(TDataCache* 专属 vtable,slot 0=DrawCacheRender, slot 1=D1, slot 2=D0)+ `pOwner@0x04`(指向所属节点,即 DoCacheForRender 的 this)+ `Matrix4 matrix@0x08`(64B,来自传入矩阵)。DrawCacheRender 经 owner 的 vtable slot 8(`owner->vtable+0x20`)间接调用(TDataCacheImageNode ctor 在 CacheWorldRender 中的分发证实)。
- **分配大小即结构体大小**(CacheRenderAllocate 为帧缓存池按需分配,无对齐余量)。
- **std::string = 4B**(旧 ABI);**cHashedString = 4B**(仅 hash 指针,`mEmptyString` 表示空);**std::_Rb_tree 头 = 24B**(compat/color/parent/left/right/count,left/right 自指 header)。

---

## 1. TDataCacheBase — 抽象基类,待恢复(4B vtable)

- Ghidra:`/Demangler/SceneGraphNode/TDataCacheBase` Size 1(占位)
- 无独立 ctor/dtor 符号(纯抽象);所有 TDataCache* 的 vtable 均为 [DrawCacheRender@0, D1@4, D0@8, ...] 布局,共享同一基类接口
- DrawCacheRender 签名:`DrawCacheRender(GameRenderer*, Camera const&, TRenderCache*) const`(gamedata:TDataCacheShadowRenderer 0x71900、TDataCacheImageNode 0xc39ca 等)
- **回写建议:新建 4B(仅 vtable),或跳过(抽象接口无字段)**

## 2. TDataCacheSceneNode — 基类(缓存对象公共头),待恢复(8B)

- Ghidra:`/Demangler/SceneGraphNode/TDataCacheSceneNode` Size 1(占位);vector 模板 `vector<SceneGraphNode::TDataCacheSceneNode*>` 存在
- 公共头(所有具体 TDataCache* 共有的前 8B):

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | 各 ctor `*this = off_45xxxx` |
| 0x04 | void* | pOwner | 各 ctor `*(this+4) = a2`(DoCacheForRender 的 this) |

- CacheWorldRender 0x127a4 分发:`piVar2 = *(node+4)`;`(**(code **)(*piVar2 + 0x20))(piVar2, renderer, node, camera, ...)` → owner vtable slot 8 = SceneGraphNode::DrawCacheRender;清场 `(**(code **)(*node + 4))(node)` = 缓存 vtable slot 1 = D1
- **回写建议:新建 8B(或并入 TDataCacheBase 作为公共头注释)**

## 3. TDataCacheAnimNode — 248B,已存在 ✓ 验证通过

- Ghidra:`/TDataCacheAnimNode` Size 248,逐字段与 ctor 0xc2d1e 吻合(分配 0xF8=248, AnimNode::DoCacheForRender 0xc259c)
- vtable `0x4563F8`:[DrawCacheRender=0xc156a, D1=0xc2932, D0=0xc2938, ...];ctor 0xc2d1e、D2 0xc2cc6

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*a2 = &off_4563F8` |
| 0x04 | AnimNode* | pAnimNode | ctor `a2[1] = a3` |
| 0x08 | Matrix4 | matrix | ctor 拷贝 a4 4×OWORD |
| 0x48 | float | scaleX | ctor `a2[18] = 0` |
| 0x4C | float | scaleY | ctor `a2[19] = 0` |
| 0x50 | uint | facingMode | ctor `a2[20] = a3[45]` |
| 0x54 | int | billboardType | ctor QWORD a2+84 = a3+292 |
| 0x58 | float | rotation | 同上(高 4B) |
| 0x5C | float | lightOverride | ctor `a2[23] = a3[75]` |
| 0x60 | float | finalOffsetX | ctor QWORD a2+96 = a3+152 |
| 0x64 | float | finalOffsetY | 同上 |
| 0x68 | float | finalOffsetZ | ctor `a2[26] = a3[78]` |
| 0x6C | float | depthFogParam | ctor `a2[27] = a3[65]` |
| 0x70 | uint | unk_70 | ctor QWORD a2+112 = a3+148 |
| 0x74 | void* | pBuild | 同上 |
| 0x78 | uint | unk_78 | ctor QWORD a2+120 = a3+92 |
| 0x7C | uint | unk_7C | 同上 |
| 0x80 | uint | effectFallbackZ0 | ctor QWORD a2+128 = a3+204 |
| 0x84 | uint | effectFallbackZN | 同上 |
| 0x88 | float | effectOverride | ctor `a2[34] = a3[53]` |
| 0x8C | uint | dwAddColour | ctor QWORD a2+140 = a3+252 |
| 0x90 | uint | dwMultColour | 同上 |
| 0x94 | float | unk_94 | ctor `a2[37] = a3[66]` |
| 0x98 | AnimNode* | pAnimNodeRef | ctor `a2[38] = a3` |
| 0x9C | bool | bDepthWriteEnabled | ctor `a2[156] = a3[245]` |
| 0x9D | bool | bDepthTestEnabled | ctor `a2[157] = a3[244]` |
| 0xA0 | float | depthBias | ctor `a2[40] = a3[50]` |
| 0xA4 | uint | vertexDescHandle | ctor `a2[41] = a3[54]` |
| 0xA8 | vector<cHashedString> | hiddenLayers | ctor `vector::operator=(this+168, a3+220)` |
| 0xB4 | vector<cHashedString> | hiddenSymbols | ctor `=(this+180, a3+232)` |
| 0xC0 | _Rb_tree<cHashedString,sSymbolOverride> | symbolOverrides | ctor `=(this+192, a3+268)`(24B 头,left/right 自指 0xC0) |
| 0xD8 | (uint,cHashedString) 对 | overrideBank ×2 | ctor QWORD a2+216/224 = a3+316/324 |
| 0xE4 | (uint,cHashedString) 对 | overrideSymbol ×2 | ctor QWORD a2+232/240 = a3+332/340 |

- **回写建议:已存在(248B),验证通过 ✓(无需重建)**

## 4. TDataCacheGameRender — 1264B(0x4F0),待恢复(静态对象,无 ctor 符号)

- Ghidra:无该类型(仅 Demangler 占位)
- 证据:cGame::CreateCacheRender 0xfc20 返回静态 `s_data_cache`(0x469c8c);cGame::CacheRender 0x14ae8 / DrawCacheRender 0x1212e 读写;dtor 0x1544c(cache 重建时 `destroy` 调用,__GLOBAL__I_a 引用)
- 布局(cGame::CacheRender + DrawCacheRender + dtor):

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x000 | float | flTime | CacheRender `*(float*)param_1 = param_2` |
| 0x004 | TDataCacheWorld | world | CacheRender `CacheWorld(this, param_1+4)`(952B 内嵌) |
| 0x3BC | TDataCacheOrthoScene | orthoScene | CacheRender `CacheOrthoSceneGraph(this, param_1+0x3bc, ...)`;DrawCacheRender 读 +956 起矩阵 |
| 0x4DC | vector<TDataCacheSceneNode*> | orthoNodes | DrawCacheRender `v14 = *(a4+1244)` 遍历;dtor `if (thisa[311]) delete` |
| 0x4E8 | uint | nDebugLayer7 | DrawCacheRender `*(a4+1256)` RenderCacheDebugLayer(7) |
| 0x4EC | uint | nDebugLayer5 | DrawCacheRender `*(a4+1260)` RenderCacheDebugLayer(5) |

- dtor 0x1544c:`~vector<TDataCacheWorldNode>(thisa+940)`(= world+936)+ `if (thisa[127]) delete`(= world+504)+ `if (thisa[311]) delete`
- **回写建议:新建 1264B(0x4F0),TDataCacheWorld 内嵌 @0x04**

## 5. TDataCacheImageNode — 180B(0xB4),待恢复

- Ghidra:`/Demangler/TDataCacheImageNode` Size 1(占位)
- vtable `0x456458`:[DrawCacheRender=0xc39ca, D1=0xc40ea, D0=0xc40ec, ...];ctor 0xc40f8、D0 0xc40ec;分配 0xB4(ImageNode::DoCacheForRender 0xc4058)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*a1 = &off_456458` |
| 0x04 | ImageNode* | pImageNode | ctor `a1[1] = a2` |
| 0x08 | Matrix4 | matrix | ctor 拷贝 a3 4×OWORD |
| 0x48 | uint | nField_48 | ctor = a2+148 |
| 0x4C | uint | nField_4C | ctor = a2+184 |
| 0x50 | uint | nField_50 | ctor = a2+188 |
| 0x54 | uint | nField_54 | ctor QWORD a1+84 = a2+176 |
| 0x58 | uint | nField_58 | 同上 |
| 0x5C | uint | nField_5C | ctor = a2+152 |
| 0x60 | uint | nField_60 | ctor QWORD a1+96 = a2+196 |
| 0x64 | uint | nField_64 | 同上 |
| 0x68 | uint | nField_68 | ctor = a2+204 |
| 0x6C | uint | nField_6C | ctor = a2+156 |
| 0x70 | uint | nField_70 | ctor = a2+164 |
| 0x74 | uint | nField_74 | ctor QWORD a1+116 = a2+220 |
| 0x78 | uint | nField_78 | 同上 |
| 0x7C | uint | nField_7C | ctor = a2+160 |
| 0x80 | byte | bField_80 | ctor = a2+244(深度测试?) |
| 0x84 | uint | dwField_84 | ctor QWORD a1+132 = a2+228 |
| 0x88 | uint | dwField_88 | 同上 |
| 0x8C | uint | dwField_8C | ctor QWORD a1+140 = a2+236 |
| 0x90 | uint | dwField_90 | 同上 |
| 0x94 | byte | bField_94 | ctor = a2+245(深度写?) |
| 0x98 | uint | dwField_98 | ctor QWORD a1+152 = a2+248 |
| 0x9C | uint | dwField_9C | 同上 |
| 0xA0 | uint | dwField_A0 | ctor = a2+256 |
| 0xA4 | uint | dwField_A4 | ctor QWORD a1+164 = a2+208 |
| 0xA8 | uint | dwField_A8 | 同上 |
| 0xAC | uint | dwField_AC | ctor = a2+216 |
| 0xB0 | uint | dwField_B0 | ctor = a2+192 |

- **回写建议:新建 180B(0xB4)**

## 6. TDataCacheMapComponent — 168B(0xA8),待恢复

- Ghidra:`/Demangler/TDataCacheMapComponent` Size 1(占位)
- vtable `unk_4550D8`;ctor 0x46d0c、D0 0x46558;分配 0xA8(MapComponent::DoCacheForRender 0x45f20)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*a1 = &unk_4550D8` |
| 0x04 | SceneGraphNode* | pSGN | ctor `a1[1] = a2 + 20`(MapComponent 内嵌 SGN 子对象 @0x14) |
| 0x08 | Matrix4 | matrix | ctor 拷贝 a3 4×OWORD |
| 0x48 | uint | nField_48 | ctor QWORD a1+72 = a2+312 |
| 0x4C | uint | nField_4C | 同上 |
| 0x50 | uint | nField_50 | ctor QWORD a1+80 = a2+320 |
| 0x54 | uint | nField_54 | 同上 |
| 0x58 | uint | nField_58 | ctor QWORD a1+88 = a2+328 |
| 0x5C | uint | nField_5C | 同上 |
| 0x60 | uint | nField_60 | ctor QWORD a1+96 = a2+336 |
| 0x64 | uint | nField_64 | 同上 |
| 0x68 | uint | nField_68 | ctor QWORD a1+104 = a2+344 |
| 0x6C | uint | nField_6C | 同上 |
| 0x70 | uint | nField_70 | ctor QWORD a1+112 = a2+352 |
| 0x74 | uint | nField_74 | 同上 |
| 0x78 | uint | nField_78 | ctor = a2+276 |
| 0x7C | void* | pNavGrid | ctor = a2+260 |
| 0x80 | void* | pField_80 | ctor = a2+248 |
| 0x84 | void* | pField_84 | ctor = a2+236 |
| 0x88 | uint | nField_88 | ctor = a2+372 |
| 0x8C | uint | nField_8C | ctor = a2+376 |
| 0x90 | uint | nField_90 | ctor = a2+380 |
| 0x94 | _RebuildRequest | rebuildReq | ctor `CacheRebuildLayer(a2, a1+148)` |
| 0x98 | bool | bField_98 | ctor `= *(a2+360); *(a2+360)=0`(地下层转移标志) |
| 0x9C | uint | nField_9C | ctor = a2+232 |
| 0xA0 | uint | nField_A0 | ctor = a2+228 |
| 0xA4 | void* | pField_A4 | ctor = a2+280 |

- **回写建议:新建 168B(0xA8)**

## 7. TDataCacheMiniMapComponent — 104B(0x68),待恢复

- Ghidra:`/Demangler/TDataCacheMiniMapComponent` Size 1(占位)
- vtable `unk_45F268`;ctor 0x50b3a、D1 0x50bac / D0 0x50bd8;分配 0x68(MiniMapComponent::CacheForRender 0x504fc)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*a1 = &unk_45F268` |
| 0x4C | uint | nField_4C | ctor = 0 |
| 0x50 | uint | nField_50 | ctor = 0 |
| 0x54 | uint | nField_54 | ctor = 0 |
| 0x58 | MiniMapComponent* | pComponent | ctor `a1[22] = a2` |
| 0x5C | _RebuildRequest | rebuildReq | ctor `CacheRebuildLayer(a2, a1+92)`;CacheForRender 再调一次 |
| 0x60 | uint | nField_60 | CacheForRender `v4+96 = CacheInitializeResources/CacheForRender` 返回(pMiniMapRenderer) |
| 0x64 | bool | bField_64 | CacheForRender `if (a2+95) v4[100] = 1` |

- **回写建议:新建 104B(0x68)**

## 8. TDataCacheMiniMapRenderer — 296B(0x128),待恢复

- Ghidra:`/Demangler/TDataCacheMiniMapRenderer` Size 1(占位)
- vtable `off_455518`:[0x578e0, D1=0x59dee, D0=0x59df0, ...];ctor 0x57892(C1 0x550d4);分配 0x128(MiniMapRenderer::CacheRender 0x54ab0 内联构造)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*thisa = &off_455518` |
| 0x04 | void*[32] | queuedCommands | AddQueuedCommand 0x53488 `*(a1 + 4*count + 4) = cmd`(上限 32) |
| 0x84 | int | numQueuedCommands | ctor `thisa[33] = 0`;AddQueuedCommand 递增;DrawCacheRender 0x572e2 遍历后清零 |
| 0x88 | byte | bField_88 | ctor `*(thisa+136) = 0` |
| 0x8C | uint | nField_8C | ctor `thisa[35] = 0` |
| 0x94 | byte | bField_94 | ctor = 0 |
| 0x95 | byte | bField_95 | ctor = 0 |
| 0x96 | byte | bField_96 | ctor = 0 |
| 0x98 | MiniMapRenderer* | pRenderer | 未在 ctor 置位(DrawCacheRender 经此分发) |
| 0xD8 | uint | nField_D8 | ctor `thisa[54] = 0` |

- DrawCacheRender 0x572e2:遍历 queuedCommands 逐个 `Execute()`,然后 `(*(vtable+4))(this)`(D1 清场)
- **回写建议:新建 296B(0x128)**

## 9. TDataCacheParticleBufferRenderer — 108B(0x6C),待恢复

- Ghidra:`/Demangler/TDataCacheParticleBufferRenderer` Size 1(占位)
- vtable `off_455728`;ctor 0x60774、D0 0x60652;分配 0x6C(ParticleBufferRenderer::DoCacheForRender 0x6025a)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*a1 = &off_455728` |
| 0x04 | ParticleBufferRenderer* | pOwner | ctor `a1[1] = a2` |
| 0x08 | Matrix4 | matrix | ctor 拷贝 a3 4×OWORD |
| 0x48 | uint | nField_48 | ctor = a2[37] |
| 0x4C | uint | nField_4C | ctor = a2[38] |
| 0x50 | uint | nField_50 | ctor = a2[39] |
| 0x54 | uint | nNumVerts | ctor `= *(ushort*)(vertDesc+8)` |
| 0x58 | void* | pData0 | ctor CacheRenderAllocate 拷贝(4B/vert, 源 v4+32) |
| 0x5C | void* | pData1 | ctor 拷贝(4B/vert, 源 v4+36) |
| 0x60 | void* | pData2 | ctor 拷贝(12B/vert, 源 v4+12) |
| 0x64 | void* | pData3 | ctor 拷贝(8B/vert, 源 v4+20) |
| 0x68 | void* | pData4 | ctor 拷贝(4B/vert, 源 v4+24) |

- **回写建议:新建 108B(0x6C)**

## 10. TDataCacheRoadManagerNode — 待恢复(≥0x6C,无 ctor 符号)

- Ghidra:`/Demangler/TDataCacheRoadManagerNode` Size 1(占位)
- vtable `off_455908`:[DrawCacheRender=0x6dbda, D1=0x6ea44, D0=0x6ea4a, ...];D2 0x70d4a(释放两处数组);**无 ctor 符号**(RoadManagerComponent 直接渲染,未走缓存池;分配点未生成符号)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | D2 `*thisa = &off_455908` |
| 0x08 | Matrix4 | matrix | DrawCacheRender 0x6dbda `operator* (a1+8)` |
| 0x48 | void* | pStripData_begin | RenderRoads 0x6dca8 遍历;D2 `if (thisa[18]) delete` |
| 0x4C | void* | pStripData_end | RenderRoads `this+0x4c != this+0x48` |
| 0x54 | uint | vertDescHandle | RenderRoads `SetVertexDescription(this+0x54)` |
| 0x5C | void* | pAABB_begin | RenderRoads 遍历 AABB3F;D2 `if (thisa[23]) delete` |
| 0x60 | void* | pAABB_end | RenderRoads `pAVar10 != *(this+0x60)` |
| 0x68 | GameRenderer* | pRenderer | RenderRoads PopShaderConstantHash(renderer);DrawCacheRender 0x6dc98 校验 |

- DrawCacheRender 0x6dbda:层 2 判定 + 矩阵级联 + RenderRoads(0x6dca8, 0x40c)
- **回写建议:新建 112B(0x70 估计,关键字段已定,无分配证据标记),或跳过(组件直渲路径)**

## 11. TDataCacheShadowRenderer — 24B(0x18),待恢复

- Ghidra:`/Demangler/TDataCacheShadowRenderer` Size 1(占位)
- vtable `PTR_DrawCacheRender_00455a18` = 0x455A18:[DrawCacheRender=0x71900, D1=0x71b6c, D0=0x71b6e, ...];无 ctor 符号(内联于 ShadowRenderer::DoCacheForRender 0x719e0);分配 0x18

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | 内联 ctor `puVar1[0] = &PTR_DrawCacheRender_00455a18` |
| 0x04 | ShadowRenderer* | pShadowRenderer | 内联 `puVar1[1] = this` |
| 0x08 | uint | nField_08 | 内联 `puVar1[2] = this+0x98` |
| 0x0C | uint | nField_0C | 内联 `puVar1[3] = this+0x9c` |
| 0x10 | uint | nField_10 | 内联 `puVar1[4] = this+0x94` |
| 0x14 | uint | nField_14 | 内联 `puVar1[5] = this+0xa0` |

- **回写建议:新建 24B(0x18)**

## 12. TDataCacheTextNode — 236B(0xEC),待恢复

- Ghidra:`/Demangler/TDataCacheTextNode` Size 1(占位)
- vtable `off_456538`:[DrawCacheRender=0xc7d00, D1=0xc8698, D0=0xc869a, ...];ctor 0xc86b4;分配 0xEC(TextNode::DoCacheForRender 0xc6dee,disasm 见 CacheRenderAllocate(0xEC))

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*thisa = &off_456538` |
| 0x04 | TextNode* | pTextNode | ctor `thisa[1] = a3` |
| 0x08 | int | nMaxLines | ctor = -1 |
| 0x0C | float | flFontSize | ctor = 1092616192(10.0f) |
| 0x10 | float | flLineSpacing | ctor = 1065353216(1.0f) |
| 0x14 | float | flRegionMaxX | ctor = 2139095039(FLT_MAX) |
| 0x18 | float | flRegionMaxY | ctor = 2139095039 |
| 0x1C | uint | nField_1C | ctor = 0 |
| 0x20 | byte | bField_20 | ctor = 0 |
| 0x24 | int | hAnchor | ctor = 2 |
| 0x28 | int | vAnchor | ctor = 2 |
| 0x2C | uint | dwTint | ctor = Colour::White |
| 0x30 | uint | nField_30 | ctor = 0 |
| 0x34 | uint | nField_34 | ctor = 0 |
| 0x38..0x64 | int[12] | 编辑光标/换行组 | ctor 循环:3 组 × 4 dword(两个 -1 + 两个 0) |
| 0x68 | uint | nField_68 | ctor `thisa[26] = 0` |
| 0x6C | uint | nField_6C | ctor `thisa[27] = 0` |
| 0x70..0x84 | int[6] | 第二组 | ctor 循环(接 0x38 组,共 24 dword 0x38..0x94 覆盖) |
| 0x88 | uint | nField_88 | ctor = -1 组尾 |
| 0x8C | uint | nField_8C | ctor = -1 |
| 0x90 | uint | nField_90 | ctor = 0 |
| 0x94 | uint | nField_94 | ctor = 0 |
| 0xA8 | byte | bDepthTest | ctor `thisa[105] = a3[244]` |
| 0xB4 | uint | nField_B4 | ctor `thisa[45] = a3[64]` |
| 0xAC | uint | dwColour | ctor QWORD thisa+172 = a3+124 |
| 0xB0 | uint | dwColour2 | 同上 |
| 0xC0 | uint | nField_C0 | ctor `thisa[48] = a3[67]` |
| 0xB8 | std::string | fontName | ctor QWORD thisa+184 = a3+260 |
| 0xC4 | uint | nField_C4 | ctor `thisa[49] = a3[73]` |
| 0xE8 | byte | bField_E8 | ctor `thisa+232 = 0` |
| 0xE9 | word | wField_E9 | ctor `word+233 = 0` |
| 0xEB | byte | bField_EB | ctor `byte+235 = -1` |

- **回写建议:新建 236B(0xEC)**

## 13. TDataCacheVFXParticleBufferRenderer — 100B(0x64),待恢复

- Ghidra:`/Demangler/TDataCacheVFXParticleBufferRenderer` Size 1(占位)
- vtable `off_456368`;ctor 0xbf15c、D0 0xbf134;分配 100(VFXParticleBufferRenderer::DoCacheForRender 0xbda26)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*a1 = &off_456368` |
| 0x04 | VFXParticleBufferRenderer* | pOwner | ctor `a1[1] = a2` |
| 0x08 | uint | nField_08 | ctor = a2+148(pParticleBufferRenderer) |
| 0x0C | Matrix4 | matrix | ctor 写 Identity 4×OWORD(+12..+60) |
| 0x18 | float | flScaleX | ctor `a1[24] = a3[3]` |
| 0x28 | float | flScaleY | ctor `a1[40] = a3[7]` |
| 0x38 | float | flScaleZ | ctor `a1[56] = a3[11]` |
| 0x4C | uint | nNumVerts | ctor `= *(ushort*)(v6+8)`(v6 = a2+148 → +120) |
| 0x50 | void* | pData0 | ctor CacheRenderAllocate 拷贝(4B/vert) |
| 0x54 | void* | pData1 | 同上 |
| 0x58 | void* | pData2 | ctor 拷贝(12B/vert) |
| 0x5C | void* | pData3 | ctor 拷贝(8B/vert) |
| 0x60 | void* | pData4 | ctor 拷贝(4B/vert) |

- **回写建议:新建 100B(0x64)**

## 14. TDataCacheVideoNode — 124B(0x7C),待恢复

- Ghidra:`/Demangler/TDataCacheVideoNode` Size 1(占位)
- vtable `off_456598`:[DrawCacheRender=0xc9004, D1=0xc9dc6, D0=0xc9dc8, ...];ctor 0xc9df2;分配 0x7C(VideoNode::DoCacheForRender 0xc8f5c)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*a1 = &off_456598` |
| 0x04 | VideoNode* | pVideoNode | ctor `a1[1] = a2` |
| 0x08 | Matrix4 | matrix | ctor 拷贝 a3 4×OWORD |
| 0x48 | uint | nField_48 | ctor = a2+168 |
| 0x4C | uint | nField_4C | ctor = a2+172 |
| 0x50 | uint | nField_50 | ctor QWORD a1+80 = a2+160 |
| 0x54 | uint | nField_54 | 同上 |
| 0x58 | uint | nField_58 | ctor = a2+148 |
| 0x5C | uint | nField_5C | ctor = a2+176 |
| 0x60 | uint | nField_60 | ctor = a2+208 |
| 0x64 | uint | nField_64 | ctor = a2+212 |
| 0x68 | uint | nField_68 | DoCacheForRender `*(v6+104) = CacheVideoFrame()` |
| 0x6C | uint | nField_6C | ctor = a2+236 |
| 0x70 | uint | nField_70 | ctor = a2+240 |
| 0x74 | uint | nField_74 | ctor = a2+244 |
| 0x78 | bool | bField_78 | ctor `= (a2+248) \|\| (a2+180==1)` |

- **回写建议:新建 124B(0x7C)**

## 15. TDataCacheWorld — 952B(0x3B8),待恢复

- Ghidra:`/Demangler/TDataCacheWorld` Size 1(占位);`vector<TDataCacheWorldNode>` 存在
- ctor 0x180d2(无 vtable,纯数据);TDataCacheGameRender 内嵌 @+4;cGame::CacheWorld 0x145fa / CacheWorldSceneGraph 0x14204 / CacheWorldRender 0x127a4 读写

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x24 | int | nField_24 | ctor dword 9..12 = -1(4 dword) |
| 0x198 | Vector3[6] | flField_198 | ctor 6× 16B(Zero + 0) |
| 0x1F8 | uint[3] | nField_1F8 | ctor dword 126/127/128 = 0(dtor `if (thisa[127]) delete`) |
| 0x204 | Matrix4 | viewMatrix | CacheWorld `*(param_1+0x204)` 写 16 float |
| 0x244 | Matrix4 | projMatrix | CacheWorld `*(param_1+0x244)` |
| 0x284 | TDataCacheMiniMapComponent* | pMiniMapCache | CacheWorld `= MiniMapComponent::CacheForRender`;CacheWorldRender `if (*(param_1+0x284)) DrawCacheRender` |
| 0x288 | Matrix4 | frustumVP | CacheWorld 写 4×4;CacheWorldRender 以 +0x288 作相机信息传 DrawCacheRender |
| 0x348 | float[96] | frustumPlanes | CacheWorldRender 拷贝 0x18 dword 自 +0x348 |
| 0x3A8 | vector<TDataCacheWorldNode> | worldNodes | CacheWorldSceneGraph `resize(a4+234, n+100)`(24B 元素);dtor `~vector(+940)` |
| 0x3B4 | int | numNodes | CacheWorldSceneGraph `++a4[237]`;CacheWorldRender 遍历后清零 |

- **TDataCacheWorldNode = 24B(0x18)**:`{QWORD node@0, int nRenderLayer@8, vector<TDataCacheSceneNode*> nodes@12}`(CacheWorldSceneGraph `v20 = 24*a4[237]` 步长,QWORD@0、layer@8、vector@12;CacheWorldRender 按 layer 切换 PushActiveLayer)
- **回写建议:新建 952B(0x3B8)+ 子类型 TDataCacheWorldNode 24B**

## 16. SceneGraphNode — 145B(0x91),已存在 ✓ 验证通过

- Ghidra:`/SceneGraphNode` Size 145,与 ctor 0xc53d6 + SetAABBDirty 0xc54d0 逐字段吻合
- vtable `off_4564B8`:[RendersAlpha=0x48878, RendersOpaque=0x465f8, ManualSortOrder=0x48880, FinalOffset=0x46600, EmitsLight=0xc6040, D1=0xc56b6, D0=0xc56bc, DoCacheForRender=0x3b78c(assert), DrawCacheRender=0x48888(assert), CollectNodes=0xc59e8, AddChild=0xc575c, RemoveChild=0xc5810, CalculateAABB=0xc5dc8, DoRender=0xc6050, ...];ctor 0xc53d6、D2 0xc563e

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*thisa = off_4564B8` |
| 0x04 | byte | bFlags0 | ctor `byte+4 = 0` |
| 0x05 | byte | bFlags1 | ctor `byte+5 = 1`(mHidden 判定用 `(char)wFlags` + `(char)(wFlags+1)`) |
| 0x08 | Matrix4 | localMatrix | ctor = Identity |
| 0x48 | uint | dwRenderFlags | ctor `thisa[18] = 3` |
| 0x4C | byte | bField_4C | ctor `byte+76 = 0` |
| 0x4E | dword | nField_4E | ctor dword+78/82/86 = 0(children vec 区) |
| 0x50 | vector<SceneGraphNode*> | children | ctor 清零;AddChild/RemoveChild 0xc575c/0xc5810 |
| 0x5A | word | wField_5A | ctor `word+90 = 0` |
| 0x5C | cGame* | pGame | ctor `thisa[23] = 0`(C1 版本置 a2) |
| 0x60 | uint | dwNameHash0 | ctor `thisa[24] = 0`(cHashedString 低 4B) |
| 0x64 | uint | dwNameHash1 | ctor `thisa[25] = mEmptyString` |
| 0x68 | SceneGraphNode* | pParentNode | ctor `thisa[26] = 0`;SetAABBDirty 读 +104 |
| 0x6C | uint | dwField_6C | ctor `thisa[27] = 0`(QuadTreeNode 指针,SetAABBDirty 判空) |
| 0x70 | float | flSortDepth | ctor `thisa[28] = 0` |
| 0x74 | uint | dwField_74 | ctor `thisa[29] = 0` |
| 0x78 | float | aabb_min_x/y/z | ctor = 2139095039(+inf) |
| 0x84 | float | aabb_max_x/y/z | ctor = -8388609(-FLT_MAX) |
| 0x90 | bool | bAABBDirty | SetAABBDirty `byte+144 = 1` |

- 分配点(cImageComponent 0x3d3fd 0x104 含派生字段;ParticleEmitter 0x5e4d3 0xA0 + 自有字段 @0x94..):**基类纯 145B 确认**(Ghidra struct + ctor 一致)
- **回写建议:已存在(145B),验证通过 ✓**

## 17. ImageNode — 260B(0x104),待恢复

- Ghidra:无该类型(struct 缺失)
- vtable `off_456418`;ctor 0xc3416、D0 0xc38ac;分配 0x104(cImageComponent::OnSetEntity 0x3d3fd `operator new(0x104)`)
- 布局 = SceneGraphNode(145B) + 自有字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*this = off_456418`(覆盖 SGN vtable) |
| 0x91 | byte | bField_91 | ctor `byte+145 = 1`(cLabelComponent::SetColour 0x40d8f 写 +0x91) |
| 0x94 | int | nMaxLines | ctor `this[37] = -1` |
| 0x98 | int | nField_98 | ctor `this[38] = -1` |
| 0x9C | uint | nField_9C | ctor `this[39] = 0` |
| 0xA0 | uint | nBlendMode | ctor `this[40] = 3`;SetBlendMode 0xc386c |
| 0xA4 | uint | dwTextureHandle | ctor `this[41] = v3[3]`(AtlasManager 槽) |
| 0xA8 | uint | dwTextureHandle2 | ctor `this[42] = v3[2]` |
| 0xAC | uint | nField_AC | ctor `this[43] = v3[6]` |
| 0xB0 | Vector2 | flSize | ctor QWORD this+44 = Vector2::Zero;SetSize 0xc3856 |
| 0xB8 | uint | nField_B8 | ctor `this[46] = 0` |
| 0xBC | uint | nField_BC | ctor `this[47] = 0` |
| 0xC0 | uint | dwTint | ctor `this[48] = Colour::White`;SetTint 0xc3900 |
| 0xC4 | float | flAlphaMax | ctor `this[49] = 1.0f`;SetAlphaRange 0xc38e6 |
| 0xC8 | float | flAlphaMin | ctor `this[50] = 1.0f` |
| 0xCC | float | flField_CC | ctor `this[51] = 1.0f` |
| 0xD0 | Vector3 | vField_D0 | ctor QWORD this+52 = Vector3::Zero |
| 0xDC | uint | nField_DC | ctor `this[55] = 0` |
| 0xE0 | uint | nField_E0 | ctor `this[56] = 1.0f` |
| 0xE4 | Vector4 | vField_E4 | ctor QWORD this+57 = Vector4::Zero |
| 0xEC | uint | dwField_EC | ctor QWORD this+59 = unk_46564C |
| 0xF4 | byte | bDepthTest | ctor `byte+244 = 0` |
| 0xF5 | byte | bDepthWrite | ctor `byte+245 = 0` |
| 0xF8 | Vector3 | vField_F8 | ctor QWORD this+62 = Vector3::Zero |
| 0x100 | uint | nField_100 | ctor `this[64] = 0`(末尾) |

- **回写建议:新建 260B(0x104),SceneGraphNode 基类 145B 内嵌**

## 18. TextNode — 356B(0x164),待恢复

- Ghidra:无该类型(struct 缺失)
- vtable `off_4564F8`;ctor 0xc6626、D2 0xc67fe;分配 0x164(cTextWidget::OnSetEntity 0x7dc42 `operator_new(0x164)`)
- 布局 = SceneGraphNode(145B) + 自有字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*this = off_4564F8` |
| 0x91 | byte | bField_91 | ctor `byte+145 = 1` |
| 0x94 | int | nMaxLines | ctor `this[37] = -1`(重复置) |
| 0x98 | float | flFontSize | ctor = 10.0f |
| 0x9C | float | flLineSpacing | ctor = 1.0f |
| 0xA0 | float | flRegionW | ctor = FLT_MAX |
| 0xA4 | float | flRegionH | ctor = FLT_MAX |
| 0xA8 | uint | nField_A8 | ctor = 0 |
| 0xAC | byte | bField_AC | ctor = 0 |
| 0xB0 | int | hAnchor | ctor = 2 |
| 0xB4 | int | vAnchor | ctor = 2 |
| 0xB8 | uint | dwTint | ctor = Colour::White |
| 0xBC | uint | nField_BC | ctor = 0 |
| 0xC0 | uint | nField_C0 | ctor = 0 |
| 0xC4..0xF0 | int[12] | 编辑/换行组 | ctor 循环(3 组 × 4 dword) |
| 0xF4 | uint | nField_F4 | ctor `this[61] = 0` |
| 0xF8 | uint | nField_F8 | ctor `this[62] = 0` |
| 0x110 | byte | bField_110 | ctor `byte+272 = 1`(SetString/溢出?) |
| 0x114 | std::string | text | ctor `this[69] = empty_rep+12`;SetString 0xc6ab4 |
| 0x118 | byte | bField_118 | ctor `byte+280 = 0`(wordWrap?) |
| 0x119 | byte | bField_119 | ctor `byte+281 = 1` |
| 0x11A | byte | bField_11A | ctor `byte+282 = 1` |
| 0x11C | uint | nField_11C | ctor `this[71] = 0` |
| 0x120 | uint | nField_120 | ctor `this[72] = 0` |
| 0x128 | Vector3 | aabb_min | ctor = +inf×3 |
| 0x134 | Vector3 | aabb_max | ctor = -FLT_MAX×3 |
| 0x140 | uint | nField_140 | ctor `this[80] = 0` |
| 0x144 | uint | nField_144 | ctor `this[81] = 0` |
| 0x148 | uint | dwField_148 | ctor `this[82] = Colour::White` |
| 0x14C | uint | nField_14C | ctor `this[83] = 0` |
| 0x150 | uint | nField_150 | ctor `this[84] = 0` |
| 0x100 | Vector3 | vField_100 | ctor QWORD this+64 = Zero(+0x100..+0x10C) |
| 0x10C | Vector3 | vField_10C | ctor `this[67] = Zero[8]` |
| 0xF4 | byte | bDepthTest | ctor `byte+244 = 0` |
| 0x124 | int | nField_124 | ctor `this[73] = -1`(末尾) |

- **回写建议:新建 356B(0x164),SceneGraphNode 基类 145B 内嵌**

## 19. TileGrid — 28B(0x1C),待恢复

- Ghidra:`/TileGrid` Size 1(占位)
- ctor 0x9d266、dtor 0x9d43c、ResizeAndClear 0x9d2ba;分配 0x1C(MapComponent 等 `new TileGrid(0x1c, w, h)`)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | int | nWidth | ctor/Resize `= a3` |
| 0x04 | int | nHeight | ctor/Resize `= a4` |
| 0x08 | int | nRegionW | Resize `= ceil(w/16)` |
| 0x0C | int | nRegionH | Resize `= ceil(h/16)` |
| 0x10 | int | nTileSizeX | Resize `= 16` |
| 0x14 | int | nTileSizeY | Resize `= 16` |
| 0x18 | ushort* | pTileData | Resize `new[](2*16*16*regionW*regionH)` 填 255/rand;dtor `if (thisa[6]) delete[]` |

- **回写建议:新建 28B(0x1C)**

## 20. MapRenderer — 28B(0x1C),待恢复

- Ghidra:`/MapRenderer` Size 1(占位)
- ctor 0x98bfa、dtor 0x98d5c;分配 0x1C(MapComponent::OnSetEntity 0x4524e `operator new(0x1C)`,第二个实例 0x45255)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | GameRenderer* | pGameRenderer | ctor `*thisa = a3` |
| 0x04 | uint | nField_04 | ctor `thisa[1] = 0` |
| 0x08 | uint | dwVertDescHandle | ctor = -1 后 `Add(VertexDescription)`(4 属性 0/9/1/2) |
| 0x0C | uint | dwEffectHandle0 | ctor `Load(a4)`(shaders/ground.ksh) |
| 0x10 | uint | dwEffectHandle1 | ctor `Load(a5)`(shaders/ground_lights.ksh) |
| 0x14 | uint | nField_14 | ctor = -1 |
| 0x18 | uint | nField_18 | ctor = 0 |

- dtor 0x98d5c:Release 三个 handle(+8/+0xC/+0x10);GetMapStart 0x98db4、DrawMap 0x98ee2
- **回写建议:新建 28B(0x1C)**

## 21. cBBoxProvider — 4B(抽象接口),待恢复

- Ghidra:`/Demangler/cBBoxProvider` Size 1(占位)
- 无 ctor(纯抽象);仅 D1 0x48a88 / D0 0x48a8a;vtable `0x45ee88`:[D1, D0, GetLocalBBox(纯虚), GetWorldBBox(纯虚), ...]
- 实现者:cImageWidget/cVideoWidget/cTextEditWidget/MapComponentBase/cAnimStateComponent/cEntity 均实现 `GetLocalBBox`(thn16 派发)
- 布局 = 仅 vtable 指针 4B
- **回写建议:新建 4B(仅 vtable,抽象基类)**

## 22. MyMotionState — 80B(0x50),待恢复

- Ghidra:无该类型(仅 Demangler)
- vtable `0x45f808`:[D1=0x69c92, D0=0x69c94, getWorldTransform=0x69c9a, setWorldTransform=0x69cc2];无 ctor 符号(内联于 cPhysicsComponent::OnSetEntity 0x67830,分配 0x50)
- 继承 btMotionState(btTransform 内嵌)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | 内联 `mov [esi], ecx(vtable+8)` |
| 0x04 | cTransformComponent* | pTransformComponent | 内联 `mov [esi+4], eax`;setWorldTransform `*(thisa+1)` |
| 0x08 | btMatrix3x3 | basis | 内联 setRotation 写 +0x10 起 3×OWORD(btTransform.basis) |
| 0x10 | btTransform | transform | getWorldTransform 拷贝 this+16 4×OWORD(64B);OnSetEntity 写 +0x10/+0x20/+0x30/+0x40 |
| 0x50 | (结束) | | 分配 0x50 |

- setWorldTransform 0x69cc2:gUseThreadedPhysics 时入 `motionStates` 全局 vector(TPendingState 16B:pos 12B + pComp),否则直调 cTransformComponent::SetPosition
- **回写建议:新建 80B(0x50)**

## 23. Envelope(基类)— 4B(抽象接口),待恢复

- Ghidra:`/Demangler/Envelope` Size 1(占位)
- 无 ctor/dtor 符号(抽象基类);EnvelopeTemplate 派生,vtable slot 布局 [D1, D0, GetType, GetValue, ...]
- 基类成员 = 仅 vtable(EnvelopeManager::DeleteEnvelope 0x34a84 `(*(vtable+4))(env)` 经 vtable 析构;EnvelopeComponent::AddEnvelope 0x34a24 存 `const Envelope*`)
- **回写建议:新建 4B(仅 vtable,抽象基类)**

## 24. EnvelopeTemplate — 16B(0x10),待恢复

- Ghidra:`/Demangler/EnvelopeTemplate<...>` Size 1 占位 ×3 实例化
- 三种实例化共用布局(Colour/Type0、float/Type1、Vector2/Type2):
  - Colour:ctor 0x17fb4、D1 0x18026、D0 0x1805e、GetType 0x18090(返回 0)、GetValue 0x6034e、AddPoint 0x14f70;vtable `0x45db98`
  - float:ctor 内联(EnvelopeLuaProxy::AddEnvelope 0x3597e `operator new(0x10)`)、D1 0x35b9e、D0 0x35bd2、GetType 0x35c02(返回 1)、AddPoint 0x35b18;vtable `0x45e698`
  - Vector2:ctor 0x17ecc、D1 0x17f44、D0 0x17f7c、GetType 0x17fae(返回 2)、GetValue 0x6043a、AddPoint 0x15004;vtable `0x45db78`

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vtable* | pVtable | ctor `*a1 = &unk_45DB98` 等 |
| 0x04 | uint | mNumDataPoints | ctor `a1[1] = 0`;AddPoint 0x35b18 写 `a1[1]` 并 ++;GetValue 0x6034e 读 +4 |
| 0x08 | void* | pData | ctor `a1[2] = new[](8*n+4)`(Colour: 8B/点 {float t, Colour};float: 8B {t,v};Vector2: 12B {t, Vector2}) |
| 0x0C | uint | mMaxNumDataPoints | ctor `a1[3] = a2`;AddPoint `if (a1[1] >= a1[3]) Assert` |

- 数据区头部 dword = 容量(ctor `*v3 = a2`),元素从 v3+4 起
- **回写建议:新建 16B(0x10),三实例化共用**

---

## 回写建议汇总表

| 类型名 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| TDataCacheBase | 新建 4B(或跳过) | 4B | 抽象基类,仅 vtable |
| TDataCacheSceneNode | 新建 8B | 8B | vtable@0 + pOwner@4,vector 元素基类 |
| TDataCacheAnimNode | **已存在,验证通过** | 248B | ctor 0xc2d1e 与 Ghidra struct 逐字段吻合 |
| TDataCacheGameRender | 新建 | 1264B | CacheRender 0x14ae8 + dtor 0x1544c;s_data_cache 静态 |
| TDataCacheImageNode | 新建 | 180B | ctor 0xc40f8;分配 0xB4 |
| TDataCacheMapComponent | 新建 | 168B | ctor 0x46d0c;分配 0xA8 |
| TDataCacheMiniMapComponent | 新建 | 104B | ctor 0x50b3a;分配 0x68 |
| TDataCacheMiniMapRenderer | 新建 | 296B | ctor 0x57892;分配 0x128;AddQueuedCommand 0x53488 |
| TDataCacheParticleBufferRenderer | 新建 | 108B | ctor 0x60774;分配 0x6C |
| TDataCacheRoadManagerNode | 新建 0x70(估计)或跳过 | ≥0x6C | 无 ctor;DrawCacheRender 0x6dbda + D2 0x70d4a |
| TDataCacheShadowRenderer | 新建 | 24B | 内联 ctor(DoCacheForRender 0x719e0);分配 0x18 |
| TDataCacheTextNode | 新建 | 236B | ctor 0xc86b4;分配 0xEC |
| TDataCacheVFXParticleBufferRenderer | 新建 | 100B | ctor 0xbf15c;分配 100 |
| TDataCacheVideoNode | 新建 | 124B | ctor 0xc9df2;分配 0x7C |
| TDataCacheWorld | 新建(+WorldNode 24B) | 952B | ctor 0x180d2 + CacheWorldSceneGraph 0x14204 |
| SceneGraphNode | **已存在,验证通过** | 145B | ctor 0xc53d6 与 Ghidra struct 吻合 |
| ImageNode | 新建 | 260B | ctor 0xc3416;分配 0x104 |
| TextNode | 新建 | 356B | ctor 0xc6626;分配 0x164 |
| TileGrid | 新建 | 28B | ctor 0x9d266 + ResizeAndClear 0x9d2ba |
| MapRenderer | 新建 | 28B | ctor 0x98bfa;分配 0x1C |
| cBBoxProvider | 新建(抽象) | 4B | 仅 D1/D0,纯虚 GetLocalBBox/GetWorldBBox |
| MyMotionState | 新建 | 80B | 内联 ctor(0x67830 分配 0x50)+ get/setWorldTransform |
| Envelope(基类) | 新建(抽象) | 4B | 仅 vtable,EnvelopeTemplate 派生 |
| EnvelopeTemplate | 新建 | 16B | ctor 0x17fb4/0x17ecc/内联;AddPoint/GetValue 字段 |
