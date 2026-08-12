# Phase 0.5 — S3 render void* 纠正表

> 输入: `sync-s3-render.md` (exists:true=60) + `types_common.h` + `tier3-a-rendering.md` / `remaining-a-render.md` / `remaining-e-tdatacache.md`
> 规则: 只读审计,不写 Ghidra。跳过 vtable / vector 三件套 / rb-tree / pPad_* / pField_* / pUnknown*。
> 判定: **确定**=语义明确且 types_common.h 已有类型; **推断**=语义明确但头文件缺类型; **待定**=无足够证据。
> 特别: Renderer 七管理器指针在 dump 中为 `uint`(非 void*),按任务要求一并纠正。

## Renderer
size: 564 (0x234)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| dwShaderConstantSet | 0x184 | uint | ShaderConstantSet* | 确定 (evidence: remaining-a-render.md InitializeOffMainThread 0x1d4354 this+0x184=new(0x1B64); types_common.h ShaderConstantSet) |
| dwResManager | 0x18C | uint | TextureManager* | 确定 (evidence: remaining-a-render.md 0x18C TextureManager* new(0x94) vtable 0x4578C8; types_common.h) |
| dwVertDescMgr | 0x190 | uint | VertexDescriptionManager* | 确定 (evidence: remaining-a-render.md 0x190 VertexDescriptionManager* new(0x94); types_common.h) |
| dwField_194 | 0x194 | uint | VertexBufferManager* | 确定 (evidence: remaining-a-render.md 0x194 VertexBufferManager*; CreateVB renderer+404; types_common.h) |
| dwField_198 | 0x198 | uint | IndexBufferManager* | 确定 (evidence: remaining-a-render.md 0x198 IndexBufferManager*; CreateIB renderer+408; types_common.h) |
| dwField_19C | 0x19C | uint | EffectManager* | 确定 (evidence: remaining-a-render.md 0x19C EffectManager* new(0x94); Effect Load via renderer+412; types_common.h) |
| dwField_1A0 | 0x1A0 | uint | RenderTargetManager* | 确定 (evidence: remaining-a-render.md 0x1A0 RenderTargetManager* new(0x94); types_common.h) |

## GameRenderer
size: 2024 (0x7e8)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| dwPtr7A0 | 0x7A0 | uint | DebugRenderer* | 确定 (evidence: remaining-a-render.md GameRenderer::InitializeOffMainThread new(0x58)×3 存于 +0x7A0/+0x7A8/+0x7B0 DebugRenderer; types_common.h DebugRenderer/GraphRenderer) |
| dwPtr7A8 | 0x7A8 | uint | DebugRenderer* | 确定 (evidence: remaining-a-render.md +0x7A8 DebugRenderer*; types_common.h) |
| dwPtr7B0 | 0x7B0 | uint | DebugRenderer* | 确定 (evidence: remaining-a-render.md +0x7B0 DebugRenderer*; types_common.h) |
| dwUIRenderMgr | 0x7BC | uint | UIRenderAssetManager* | 确定 (evidence: dump 字段名 dwUIRenderMgr@0x7BC; types_common.h UIRenderAssetManager; tier3 UIRenderAssetManager 已恢复) |
| dwGame | 0x7C0 | uint | cGame* | 确定 (evidence: dump 字段名 dwGame@0x7C0; remaining-a cGame↔GameRenderer 互指(cGame+0x30=Renderer*); types_common.h cGame) |

## HWBuffer
size: 20 (0x14)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |

## BaseTexture
size: 20 (0x14)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pMipData | 0x4 | void * | sMipDescription* | 推断 (evidence: tier3-a-rendering.md BaseTexture+0x04 = sMipDescription* (ctor new[] 16B/mip); types_common.h 无 sMipDescription → 需建类型) |

## VertexDescription
size: 24 (0x18)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |

## BaseVertexDescription
size: 24 (0x18)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |

## Shader
size: 24 (0x18)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |

## RenderTarget
size: 4 (0x4)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |

## HWRenderTarget
size: 32 (0x20)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |

## ShadowRenderer
size: 168 (0xa8)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pManager | 0xA0 | void * | ShadowManagerComponent* | 确定 (evidence: remaining-a-render.md ShadowRenderer C2 +0xA0 = a4 ShadowManagerComponent*; types_common.h 已定义) |
| pRenderer | 0xA4 | void * | Renderer* | 确定 (evidence: remaining-a-render.md +0xA4 = a5 (cGame+0x30 Renderer*/GameRenderer*); types_common.h Renderer) |

## GraphRenderer
size: 88 (0x58)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pGameRenderer | 0x3C | void * | GameRenderer* | 确定 (evidence: remaining-a-render.md GraphRenderer C2 +0x3C = a3 GameRenderer*; types_common.h GameRenderer) |

## MapRenderer
size: 28 (0x1c)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pGameRenderer | 0x0 | void * | GameRenderer* | 确定 (evidence: remaining-a-render.md MapRenderer C2 *this = a3 GameRenderer*; types_common.h) |
| pLayerMgr | 0x4 | void * | MapLayerManagerComponent* | 推断 (evidence: remaining-a-render.md +0x04 MapLayerManagerComponent* (GroundCreep 写入); types_common.h 无此类型 → 需建类型) |

## ParticleBuffer
size: 32 (0x20)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pParticleDataA | 0xC | void * | void* (raw n×12B buf) | 待定 (evidence: remaining-a-render.md C2 new[](12*n+4) 原始粒子缓冲,无具名元素类型) |
| pParticleDataB | 0x10 | void * | void* (raw n×12B buf) | 待定 (evidence: remaining-a-render.md C2 new[](12*n+4) 原始缓冲) |
| pRotationData | 0x14 | void * | void* (raw n×8B buf) | 待定 (evidence: remaining-a-render.md C2 可选 new[](8*n+4) 旋转分量) |
| pDataC | 0x18 | void * | void* (raw n×4B buf) | 待定 (evidence: remaining-a-render.md C2 new[](4*n)) |
| pDataD | 0x1C | void * | void* (raw n×4B buf) | 待定 (evidence: remaining-a-render.md C2 new[](4*n)) |

## ParticleBufferRenderer
size: 160 (0xa0)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pRenderer | 0x94 | void * | GameRenderer* | 确定 (evidence: remaining-a-render.md OnSetEntity +0x94 = *(cGame+0x30) GameRenderer*; types_common.h) |
| pEmitter | 0x98 | void * | ParticleEmitter* | 确定 (evidence: remaining-a-render.md +0x98 = thisa ParticleEmitter*; types_common.h ParticleEmitter) |

## VFXParticleBufferRenderer
size: 152 (0x98)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pEmitter | 0x94 | void * | VFXEffectEmitter* | 确定 (evidence: remaining-a-render.md C2 +0x94 = a3 VFXEffectEmitter*; types_common.h) |

## WallStencilBuffer
size: 61 (0x3d)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pRenderer | 0x1C | void * | GameRenderer* | 确定 (evidence: remaining-a-render.md WallStencilBuffer C2 +0x1C = a2 GameRenderer*; types_common.h) |
| pDispatcher | 0x38 | void * | cEventDispatcher* | 推断 (evidence: remaining-a-render.md +0x38 = a3 cEventDispatcher* + RegisterListener; types_common.h 无 cEventDispatcher → 需建类型) |

## BitmapFontManager
size: 88 (0x58)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pRenderer | 0x54 | void * | GameRenderer* | 确定 (evidence: tier3-a-rendering.md BitmapFontManager +0x54 GameRenderer* ctor this+21=a2; types_common.h) |

## BitmapFontRenderer
size: 96 (0x60)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pRenderer | 0x48 | void * | GameRenderer* | 确定 (evidence: tier3-a-rendering.md BitmapFontRenderer +0x48 GameRenderer* ctor this+18=a3; types_common.h) |
| pFontManager | 0x4C | void * | BitmapFontManager* | 确定 (evidence: tier3-a-rendering.md +0x4C BitmapFontManager* ctor this+19=a4; types_common.h) |

## VideoNode
size: 276 (0x114)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |

## TDataCacheAnimNode
size: 248 (0xf8)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| vtable | 0x0 | void * | — | 跳过 (vtable) |
| pAnimNode | 0x4 | void * | AnimNode* | 确定 (evidence: remaining-e-tdatacache.md +0x04 AnimNode* ctor a2[1]=a3; types_common.h AnimNode) |
| pBuild | 0x74 | void * | sBuild* | 确定 (evidence: remaining-e-tdatacache.md +0x74 pBuild(来自 AnimNode); types_common.h sBuild / AnimNode::pBuild) |
| pAnimNodeRef | 0x98 | void * | AnimNode* | 确定 (evidence: remaining-e-tdatacache.md +0x98 AnimNode* ctor a2[38]=a3; types_common.h) |
| hiddenLayers_begin | 0xA8 | void * | — | 跳过 (vector 三件套) |
| hiddenLayers_end | 0xAC | void * | — | 跳过 (vector 三件套) |
| hiddenLayers_cap | 0xB0 | void * | — | 跳过 (vector 三件套) |
| hiddenSymbols_begin | 0xB4 | void * | — | 跳过 (vector 三件套) |
| hiddenSymbols_end | 0xB8 | void * | — | 跳过 (vector 三件套) |
| hiddenSymbols_cap | 0xBC | void * | — | 跳过 (vector 三件套) |
| rbTree_hdr_color | 0xC4 | void * | — | 跳过 (rb-tree 节点) |
| rbTree_hdr_parent | 0xC8 | void * | — | 跳过 (rb-tree 节点) |
| rbTree_hdr_left | 0xCC | void * | — | 跳过 (rb-tree 节点) |
| rbTree_hdr_right | 0xD0 | void * | — | 跳过 (rb-tree 节点) |

## TDataCacheBase
size: 4 (0x4)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |

## TDataCacheGameRender
size: 1264 (0x4f0)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | void* (layout mismatch) | 待定 (evidence: remaining-e: TDataCacheGameRender@0x04 为内嵌 TDataCacheWorld(非指针); dump 的 pOwner 与证据布局不一致) |

## TDataCacheWorld
size: 952 (0x3b8)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | void* | 待定 (evidence: remaining-e: TDataCacheWorld 为纯数据(无 vtable/pOwner 头); dump 字段命名与 CacheWorld 布局不符,无可靠指针语义) |

## TDataCacheImageNode
size: 180 (0xb4)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | ImageNode* | 确定 (evidence: remaining-e-tdatacache.md +0x04 ImageNode* ctor a1[1]=a2; types_common.h ImageNode) |

## TDataCacheMapComponent
size: 168 (0xa8)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | SceneGraphNode* | 确定 (evidence: remaining-e-tdatacache.md +0x04 = a2+20 (MapComponent 内嵌 SGN@0x14) → SceneGraphNode*; types_common.h SceneGraphNode) |

## TDataCacheMiniMapComponent
size: 104 (0x68)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | void* | 待定 (evidence: remaining-e: MiniMapComponent cache 布局 pComponent@0x58, dump 仅见 pOwner@0x04 与证据不符) |

## TDataCacheMiniMapRenderer
size: 296 (0x128)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | void* | 待定 (evidence: remaining-e: pRenderer(MiniMapRenderer*)@0x98; dump pOwner@0x04 无 ctor 置位证据) |

## TDataCacheParticleBufferRenderer
size: 108 (0x6c)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | ParticleBufferRenderer* | 确定 (evidence: remaining-e-tdatacache.md +0x04 ParticleBufferRenderer* ctor a1[1]=a2; types_common.h) |

## TDataCacheRoadManagerNode
size: 112 (0x70)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | void* | 待定 (evidence: remaining-e: 无 ctor; 字段从 0x08 matrix 起, dump pOwner@0x04 无明确 owner 类型证据) |

## TDataCacheSceneNode
size: 8 (0x8)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | SceneGraphNode* | 确定 (evidence: remaining-e-tdatacache.md 公共头 pOwner=DoCacheForRender this (SceneGraphNode 派生); types_common.h SceneGraphNode) |

## TDataCacheShadowRenderer
size: 72 (0x48)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | ShadowRenderer* | 确定 (evidence: remaining-e-tdatacache.md +0x04 ShadowRenderer* (内联 ctor puVar1[1]=this); types_common.h ShadowRenderer) |

## TDataCacheTextNode
size: 236 (0xec)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | TextNode* | 确定 (evidence: remaining-e-tdatacache.md +0x04 TextNode* ctor thisa[1]=a3; types_common.h TextNode) |

## TDataCacheVFXParticleBufferRenderer
size: 100 (0x64)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | VFXParticleBufferRenderer* | 确定 (evidence: remaining-e-tdatacache.md +0x04 VFXParticleBufferRenderer*; types_common.h) |

## TDataCacheVideoNode
size: 124 (0x7c)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pOwner | 0x4 | void * | VideoNode* | 确定 (evidence: remaining-e-tdatacache.md +0x04 VideoNode* ctor a1[1]=a2; types_common.h VideoNode) |

## AtlasManager
size: 64 (0x40)

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | — | 跳过 (vtable) |
| pRenderer | 0x3C | void * | Renderer* | 确定 (evidence: tier3-a-rendering / types_common.h AtlasManager +0x3C pRenderer (cResourceManager 模板字段); types_common.h Renderer) |

## 相关(不在 S3 dump 内,仅记录交叉证据)

| 结构 | 字段 | 偏移 | 目标 | 判定 |
|------|------|------|------|------|
| cGame | pRenderer | 0x30 | GameRenderer* / Renderer* | 确定 (evidence: remaining-a-render.md cGame+0x30=Renderer*(GameRenderer); ShadowManagerComponent::OnSetEntity 0x713ec; types_common.h cGame::pRenderer) |
| cGame | pAtlasManager | 0x4C | AtlasManager* | 确定 (evidence: remaining-a-render.md cGame+0x4C=AtlasManager*; MOTDImageLoader; types_common.h) |

> 注: cGame 属其他 shard,此处不计入下方汇总计数。

## 汇总

| 判定 | 数量 |
|------|------|
| 确定 | 35 |
| 推断 | 3 |
| 待定 | 10 |
| 跳过 | 38 |
| **合计(纠正表行)** | **86** |

### 重点纠正(Renderer 七管理器)

| 偏移 | 建议字段名 | 目标类型 |
|------|-----------|---------|
| 0x184 | pShaderConstantSet | ShaderConstantSet* |
| 0x18C | pTextureManager | TextureManager* |
| 0x190 | pVertDescMgr | VertexDescriptionManager* |
| 0x194 | pVertexBufferMgr | VertexBufferManager* |
| 0x198 | pIndexBufferMgr | IndexBufferManager* |
| 0x19C | pEffectMgr | EffectManager* |
| 0x1A0 | pRenderTargetMgr | RenderTargetManager* |

### 需建类型(推断项)

- `sMipDescription` — BaseTexture::pMipData 元素(16B/mip: w@0,h@2,size@8)
- `MapLayerManagerComponent` — MapRenderer::pLayerMgr
- `cEventDispatcher` — WallStencilBuffer::pDispatcher

生成时间: 2026-08-10 | 源 dump: sync-s3-render.md | 报告: audit-s3-render.md
