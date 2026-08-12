# Phase 1 S3 Retype — Render void* / uint-as-pointer 回写报告

> 输入: audit-s3-render.md 的「确定」判定(35 个)
> 操作: ghidra-mcp modify_struct_field 写回 dontstarve_steam(macOS i386)
> 验证: 全部 20 个涉及 struct 的 get_struct_layout 复核 — 类型已变、size 未变
> 注: modify_struct_field 单独调用(不带 new_name)会把字段名清空;本次采用同调用携带 new_name 的方式,字段名一次性保留/重命名。GameRenderer 的 dw* 字段改为指针类型时,工具自动按匈牙利命名规范将 dw→p 前缀(如 dwPtr7A0→pPtr7A0、dwGame→pGame),类型与偏移不受影响。

## 成功 (35/35)

### Renderer — 七管理器 uint→指针(7)
| 字段(改前→改后) | 新类型 | 偏移 |
|------|------|------|
| dwShaderConstantSet → pShaderConstantSet | ShaderConstantSet * | 0x184 |
| dwResManager → pTextureManager | TextureManager * | 0x18C |
| dwVertDescMgr → pVertDescMgr | VertexDescriptionManager * | 0x190 |
| dwField_194 → pVertexBufferMgr | VertexBufferManager * | 0x194 |
| dwField_198 → pIndexBufferMgr | IndexBufferManager * | 0x198 |
| dwField_19C → pEffectMgr | EffectManager * | 0x19C |
| dwField_1A0 → pRenderTargetMgr | RenderTargetManager * | 0x1A0 |

### GameRenderer — uint→指针(5)
| 字段(改前→改后) | 新类型 | 偏移 |
|------|------|------|
| dwPtr7A0 → pPtr7A0 | DebugRenderer * | 0x7A0 |
| dwPtr7A8 → pPtr7A8 | DebugRenderer * | 0x7A8 |
| dwPtr7B0 → pPtr7B0 | DebugRenderer * | 0x7B0 |
| dwUIRenderMgr → pUIRenderMgr | UIRenderAssetManager * | 0x7BC |
| dwGame → pGame | cGame * | 0x7C0 |

### 渲染器引用(12)
| struct.field | 新类型 | 偏移 |
|------|------|------|
| ShadowRenderer.pManager | ShadowManagerComponent * | 0xA0 |
| ShadowRenderer.pRenderer | Renderer * | 0xA4 |
| GraphRenderer.pGameRenderer | GameRenderer * | 0x3C |
| MapRenderer.pGameRenderer | GameRenderer * | 0x0 |
| ParticleBufferRenderer.pRenderer | GameRenderer * | 0x94 |
| ParticleBufferRenderer.pEmitter | ParticleEmitter * | 0x98 |
| VFXParticleBufferRenderer.pEmitter | VFXEffectEmitter * | 0x94 |
| WallStencilBuffer.pRenderer | GameRenderer * | 0x1C |
| BitmapFontManager.pRenderer | GameRenderer * | 0x54 |
| BitmapFontRenderer.pRenderer | GameRenderer * | 0x48 |
| BitmapFontRenderer.pFontManager | BitmapFontManager * | 0x4C |
| AtlasManager.pRenderer | Renderer * | 0x3C |

### TDataCache 族(11)
| struct.field | 新类型 | 偏移 |
|------|------|------|
| TDataCacheAnimNode.pAnimNode | AnimNode * | 0x4 |
| TDataCacheAnimNode.pBuild | sBuild * | 0x74 |
| TDataCacheAnimNode.pAnimNodeRef | AnimNode * | 0x98 |
| TDataCacheImageNode.pOwner | ImageNode * | 0x4 |
| TDataCacheMapComponent.pOwner | SceneGraphNode * | 0x4 |
| TDataCacheParticleBufferRenderer.pOwner | ParticleBufferRenderer * | 0x4 |
| TDataCacheSceneNode.pOwner | SceneGraphNode * | 0x4 |
| TDataCacheShadowRenderer.pOwner | ShadowRenderer * | 0x4 |
| TDataCacheTextNode.pOwner | TextNode * | 0x4 |
| TDataCacheVFXParticleBufferRenderer.pOwner | VFXParticleBufferRenderer * | 0x4 |
| TDataCacheVideoNode.pOwner | VideoNode * | 0x4 |

## 失败清单

无(SKIP_NEED_TYPE: 0 / FAIL_SPACE: 0 / FAIL_FIELD: 0)

## 类型预检

写前 search_data_types 确认全部 25 个目标类型已存在于 dontstarve_steam(/ 根类别, 非仅 /Demangler 占位):
ShaderConstantSet(4136B), TextureManager(148B), VertexDescriptionManager(148B), VertexBufferManager(148B), IndexBufferManager(148B), EffectManager(148B), RenderTargetManager(148B), DebugRenderer(88B), UIRenderAssetManager(32B), cGame(304B), ShadowManagerComponent(32B), Renderer(564B), GameRenderer(2024B), ParticleEmitter(136B), VFXEffectEmitter(128B), BitmapFontManager(88B), AnimNode(348B), sBuild(76B), ImageNode(260B), SceneGraphNode(145B), ParticleBufferRenderer(160B), ShadowRenderer(168B), TextNode(356B), VFXParticleBufferRenderer(152B), VideoNode(276B)

## 抽查结果(20 struct, 全部 get_struct_layout 复核)

| struct | size(改前/改后) | 关键字段确认 |
|------|------|------|
| Renderer | 564 / 564 | 七管理器全部 uint→具体指针类型,重命名 p* 成功 |
| GameRenderer | 2024 / 2024 | pPtr7A0/pPtr7A8/pPtr7B0 = DebugRenderer *;pUIRenderMgr = UIRenderAssetManager *;pGame = cGame * |
| ShadowRenderer | 168 / 168 | pManager = ShadowManagerComponent *;pRenderer = Renderer * |
| GraphRenderer | 88 / 88 | pGameRenderer = GameRenderer * |
| MapRenderer | 28 / 28 | pGameRenderer = GameRenderer *;pLayerMgr(推断)未动 |
| ParticleBufferRenderer | 160 / 160 | pRenderer = GameRenderer *;pEmitter = ParticleEmitter * |
| VFXParticleBufferRenderer | 152 / 152 | pEmitter = VFXEffectEmitter * |
| WallStencilBuffer | 61 / 61 | pRenderer = GameRenderer *;pDispatcher(推断)未动 |
| BitmapFontManager | 88 / 88 | pRenderer = GameRenderer * |
| BitmapFontRenderer | 96 / 96 | pRenderer = GameRenderer *;pFontManager = BitmapFontManager * |
| AtlasManager | 64 / 64 | pRenderer = Renderer * |
| TDataCacheAnimNode | 248 / 248 | pAnimNode/pAnimNodeRef = AnimNode *;pBuild = sBuild * |
| TDataCacheImageNode | 180 / 180 | pOwner = ImageNode * |
| TDataCacheMapComponent | 168 / 168 | pOwner = SceneGraphNode * |
| TDataCacheParticleBufferRenderer | 108 / 108 | pOwner = ParticleBufferRenderer * |
| TDataCacheSceneNode | 8 / 8 | pOwner = SceneGraphNode * |
| TDataCacheShadowRenderer | 72 / 72 | pOwner = ShadowRenderer * |
| TDataCacheTextNode | 236 / 236 | pOwner = TextNode * |
| TDataCacheVFXParticleBufferRenderer | 100 / 100 | pOwner = VFXParticleBufferRenderer * |
| TDataCacheVideoNode | 124 / 124 | pOwner = VideoNode * |

结论:35 个「确定」字段全部成功回写(0 失败、0 类型缺失);「推断(3)/待定(10)/跳过(38)」未触碰。已 save_program。
