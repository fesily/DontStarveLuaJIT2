# Phase 0 sync — S3 render layout dump

> program: `dontstarve_steam` (macOS i386)
> tool: ghidra-mcp `get_struct_layout` (read-only)
> shard: S3 render
> summary: processed=71 exists=60 missing=11

Rule: Size=1 placeholder / not found / not a structure → `exists: false` (no fields).

### Renderer
size: 564 (hex 0x234)
exists: true
layout:
  0 | uint | dwVtable
  4 | uint | dwField_04
  8 | uint | dwField_08
  12 | byte | bField_0C
  13 | byte[3] | p_pad0D
  16 | RenderState | renderState
  388 | uint | dwShaderConstantSet
  392 | uint | dwShaderPushCount
  396 | uint | dwResManager
  400 | uint | dwVertDescMgr
  404 | uint | dwField_194
  408 | uint | dwField_198
  412 | uint | dwField_19C
  416 | uint | dwField_1A0
  420 | uint | dwField_1A4
  424 | byte[8] | p_gap1A8
  432 | uint | dwField_1B0
  436 | uint | dwListSentinel
  440 | uint | dwListNext
  444 | CommandBuffer | cmdBuf

### GameRenderer
size: 2024 (hex 0x7e8)
exists: true
layout:
  0 | Renderer | base
  564 | Matrix4[18] | pMatrices
  1716 | uint[18] | pMatrices
  1788 | byte[72] | p_pad6FC
  1860 | uint | dwField_744
  1864 | byte[32] | p_gap748
  1896 | uint | dwField_768
  1900 | byte[32] | p_gap76C
  1932 | uint | dwPtr78C
  1936 | uint | dwPtr790
  1940 | uint | dwPtr794
  1944 | uint | dwPtr798
  1948 | uint | dwPtr79C
  1952 | uint | dwPtr7A0
  1956 | uint | dwPtr7A4
  1960 | uint | dwPtr7A8
  1964 | uint | dwPtr7AC
  1968 | uint | dwPtr7B0
  1972 | uint | dwPtr7B4
  1976 | uint | dwPtr7B8
  1980 | uint | dwUIRenderMgr
  1984 | uint | dwGame
  1988 | uint | dwErosionMode
  1992 | uint | dwEffectH_7C8
  1996 | uint | dwEffectH_7CC
  2000 | uint | dw_gap7D0
  2004 | uint | dwEffectH_7D4
  2008 | uint | dwEffectH_7D8
  2012 | uint | dwEffectH_7DC
  2016 | uint | dw_gap7E0
  2020 | uint | dwEffectH_7E4

### BaseRenderer
size: 1 (hex 0x1)
exists: false

### HWBuffer
size: 20 (hex 0x14)
exists: true
layout:
  0 | void * | pVtable
  4 | uint | dwStride
  8 | uint | dwCount
  12 | uint | dwField_0x0C
  16 | uint | dwEUsage

### Texture
size: 40 (hex 0x28)
exists: true
layout:
  0 | BaseTexture | base
  20 | uint | dwField_0x14
  24 | uint | dwField_0x18
  28 | uint | dwField_0x1C
  32 | uint | dwField_0x20
  36 | uint | dwField_0x24

### HWTexture
size: 40 (hex 0x28)
exists: true
layout:
  0 | BaseTexture | base
  20 | uint | dwGlTextureId
  24 | int | nWrapS
  28 | int | nWrapT
  32 | int | nFilterMin
  36 | int | nFilterMag

### BaseTexture
size: 20 (hex 0x14)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pMipData
  8 | uint | dwFlags
  12 | int | nField_0x0C
  16 | byte[4] | pName

### VertexBuffer
size: 20 (hex 0x14)
exists: true
layout:
  0 | HWBuffer | base

### IndexBuffer
size: 20 (hex 0x14)
exists: true
layout:
  0 | HWBuffer | base

### VertexDescription
size: 24 (hex 0x18)
exists: true
layout:
  0 | void * | pVtable
  4 | ushort | wStride
  6 | ushort | wPad
  8 | uint | dwAttributeMask
  12 | byte[12] | pAttributes

### BaseVertexDescription
size: 24 (hex 0x18)
exists: true
layout:
  0 | void * | pVtable
  4 | ushort | wStride
  6 | ushort | wPad
  8 | uint | dwAttributeMask
  12 | byte[12] | pAttributes

### ShaderConstantSet
size: 4136 (hex 0x1028)
exists: true
layout:
  0 | uint | dwField_0x00
  4 | byte[4096] | pDataStack
  4100 | byte[16] | pHashToIndexMap
  4116 | byte[16] | pListSentinel
  4132 | uint | dwListHead

### Shader
size: 24 (hex 0x18)
exists: true
layout:
  0 | void * | pVtable
  4 | int | nHandle
  8 | byte[4] | pName
  12 | int | nField_0x0C
  16 | int | nField_0x10
  20 | int | nField_0x14

### Effect
size: 164 (hex 0xa4)
exists: true
note: base field type is -BAD- in Ghidra
layout:
  0 | -BAD- | base
  160 | byte[4] | pName

### EffectManager
size: 148 (hex 0x94)
exists: true
layout:
  0 | byte[148] | pBase

### TextureManager
size: 148 (hex 0x94)
exists: true
layout:
  0 | byte[148] | pBase

### VertexBufferManager
size: 148 (hex 0x94)
exists: true
layout:
  0 | byte[148] | pBase

### IndexBufferManager
size: 148 (hex 0x94)
exists: true
layout:
  0 | byte[148] | pBase

### VertexDescriptionManager
size: 148 (hex 0x94)
exists: true
layout:
  0 | byte[148] | pBase

### RenderTarget
size: 4 (hex 0x4)
exists: true
layout:
  0 | void * | pVtable

### HWRenderTarget
size: 32 (hex 0x20)
exists: true
layout:
  0 | void * | pVtable
  4 | uint | dwFramebufferId
  8 | uint | dwColorTexHandle
  12 | uint | dwDepthTexHandle
  16 | uint | dwField_0x10
  20 | uint | dwTextureHandle
  24 | uint | dwWidth
  28 | uint | dwHeight

### RenderTargetManager
size: 148 (hex 0x94)
exists: true
layout:
  0 | byte[148] | pBase

### ShadowRenderer
size: 168 (hex 0xa8)
exists: true
layout:
  0 | byte[148] | pSgn
  148 | uint | dwField_0x94
  152 | uint | dwVertDescHandle
  156 | uint | dwEffectHandle
  160 | void * | pManager
  164 | void * | pRenderer

### GraphRenderer
size: 88 (hex 0x58)
exists: true
layout:
  0 | void * | pVtable
  4 | byte[12] | pVecTriangles
  16 | uint | dwField_0x10
  20 | uint | dwField_0x14
  24 | uint | dwField_0x18
  28 | byte[12] | pVecStrings
  40 | byte[12] | pVecDebugLines
  52 | uint | dwField_0x34
  56 | uint | dwField_0x38
  60 | void * | pGameRenderer
  64 | uint | dwEffectHandle_1
  68 | uint | dwEffectHandle_2
  72 | uint | dwVertDescHandle_1
  76 | uint | dwVertDescHandle_2
  80 | uint | dwEffectHandle_3
  84 | uint | dwEffectHandle_4

### DebugRenderer
size: 88 (hex 0x58)
exists: true
note: Ghidra layout incomplete; only one field defined at 64
layout:
  64 | byte[12] | pVecDebugLines

### MiniMapRenderer
size: 1 (hex 0x1)
exists: false

### MapRenderer
size: 28 (hex 0x1c)
exists: true
layout:
  0 | void * | pGameRenderer
  4 | void * | pLayerMgr
  8 | uint | dwVertDescHandle
  12 | uint | dwEffectHandle_1
  16 | uint | dwEffectHandle_2
  20 | uint | dwField_0x14
  24 | uint | dwField_0x18

### Batcher
size: 68 (hex 0x44)
exists: true
layout:
  0 | uint | dwRenderer
  4 | uint | dwTexHandle0
  8 | uint | dwTexHandle1
  12 | uint | dwTexHandle2
  16 | uint | dwVertDescHandle
  20 | uint | dwBlendMode
  24 | uint | dwEffectHandle
  28 | float | flAlphaMin
  32 | float | flAlphaMax
  36 | float | flEffectParam0
  40 | float | flEffectParam1
  44 | float | flEffectParam2
  48 | float | flEffectParam3
  52 | byte | bHasEffectParams
  53 | byte | b_pad35
  54 | byte | b_pad36
  55 | byte | b_pad37
  56 | uint | dwVertBegin
  60 | uint | dwVertEnd
  64 | uint | dwVertCap

### ParticleBuffer
size: 32 (hex 0x20)
exists: true
layout:
  0 | uint | dwColour0
  4 | uint | dwColour1
  8 | ushort | wField_0x08
  12 | void * | pParticleDataA
  16 | void * | pParticleDataB
  20 | void * | pRotationData
  24 | void * | pDataC
  28 | void * | pDataD

### ParticleBufferRenderer
size: 160 (hex 0xa0)
exists: true
layout:
  0 | byte[148] | pSgn
  148 | void * | pRenderer
  152 | void * | pEmitter
  156 | uint | dwField_0x9C

### VFXParticleBufferRenderer
size: 152 (hex 0x98)
exists: true
layout:
  0 | byte[148] | pSgn
  148 | void * | pEmitter

### WallStencilBuffer
size: 61 (hex 0x3d)
exists: true
layout:
  0 | void * | pVtable
  8 | byte[8] | pListNode
  16 | uint | dwListSentinel
  20 | uint | dwListNext
  24 | uint | dwField_0x18
  28 | void * | pRenderer
  32 | uint | dwField_0x20
  36 | uint | dwField_0x24
  40 | uint | dwVBHandle
  44 | uint | dwVertDescHandle
  48 | uint | dwEffectHandle_depth
  52 | uint | dwEffectHandle_tri
  56 | void * | pDispatcher
  60 | byte | bField_0x3C

### UIRenderAssetManager
size: 32 (hex 0x20)
exists: true
layout:
  0 | uint | dwVtable
  4 | uint | dwRenderer
  8 | uint | dwVertDescHandle
  12 | uint | dwEffectHandle_ui
  16 | uint | dwEffectHandle_yuv
  20 | uint | dwEffectHandle_anim
  24 | uint | dwVbHandle
  28 | uint | dwBatcher

### BitmapFont
size: 68 (hex 0x44)
exists: true
layout:
  0 | byte[4] | pName
  4 | ushort | wLineHeight
  6 | ushort | wBase
  8 | float | flSize
  12 | float | flScaleW
  16 | float | flScaleH
  20 | uint | dwField_0x14
  24 | uint | dwPages
  28 | byte[12] | pGlyphMap
  40 | byte[12] | pKerningMap
  52 | uint | dwTextureHandle
  56 | byte[12] | pFallbackFonts

### BitmapFontManager
size: 88 (hex 0x58)
exists: true
layout:
  0 | void * | pVtable
  4 | int | nField_0x04
  8 | byte[12] | pResources
  24 | byte[20] | pHashMap
  44 | byte[12] | pVec_2C
  56 | byte[4] | pName
  60 | byte[20] | pRegisteredFonts
  84 | void * | pRenderer

### BitmapFontRenderer
size: 96 (hex 0x60)
exists: true
layout:
  0 | void * | pVtable
  4 | int | nField_0x04
  8 | WorkingVB | workingVB
  72 | void * | pRenderer
  76 | void * | pFontManager
  80 | uint | dwVertDescHandle
  84 | uint | dwEffectHandle_font
  88 | uint | dwEffectHandle_packed
  92 | uint | dwEffectHandle_outline

### ITextRenderer
size: n/a (not found)
exists: false
note: Structure not found; only nested demangler types (FontEffectType/FontVBData/Params)

### TextNode
size: 356 (hex 0x164)
exists: true
layout:
  0 | byte[148] | pSgn
  148 | uint | dwVertDescHandle
  152 | float | flFontScale
  156 | float | flField_0x9C
  160 | float | flMax_0xA0
  164 | float | flMax_0xA4
  168 | uint | dwField_0xA8
  172 | byte | bField_0xAC
  176 | uint | dwField_0xB0
  180 | uint | dwField_0xB4
  184 | byte[4] | pColour
  188 | byte[56] | pHandles_0xBC
  244 | uint | dwField_0xF4
  256 | byte[12] | pVec3_0x100
  272 | byte | bField_0x110
  276 | byte | bField_0x114
  280 | byte | bField_0x118
  284 | byte[4] | pStrText
  288 | byte | bField_0x120
  289 | byte | bField_0x121
  290 | byte | bField_0x122
  292 | uint | dwField_0x124
  296 | uint | dwField_0x128
  300 | uint | dwField_0x12C
  304 | float[3] | pAABB_max
  316 | float[3] | pAABB_min
  328 | uint | dwField_0x148
  332 | uint | dwField_0x14C
  336 | byte[4] | pColour2
  352 | uint | dwField_0x160

### ImageNode
size: 260 (hex 0x104)
exists: true
layout:
  0 | byte[148] | pSgn
  148 | byte[112] | pUNKNOWN_0x94

### VideoNode
size: 276 (hex 0x114)
exists: true
layout:
  0 | void * | pVtable
  4 | byte[76] | pBase_0x04
  80 | byte[8] | pSize
  88 | byte[68] | pUNKNOWN_0x58
  160 | uint | dwField_0xA0
  164 | uint | dwField_0xA4
  168 | uint | dwField_0xA8
  172 | uint | dwField_0xAC
  176 | uint | dwTint
  180 | uint | dwField_0xB4
  184 | byte[4] | pName
  192 | Timer | timer
  200 | byte[8] | pIoCallbacks
  236 | uint | dwField_0xEC
  240 | uint | dwField_0xF0
  244 | uint | dwField_0xF4
  248 | byte | bField_0xF8
  256 | uint | dwField_0x100
  260 | uint | dwField_0x104
  264 | uint | dwField_0x108
  268 | uint | dwField_0x10C
  272 | uint | dwField_0x110

### TDataCacheAnimNode
size: 248 (hex 0xf8)
exists: true
layout:
  0 | void * | vtable
  4 | void * | pAnimNode
  8 | float | matrix_0
  12 | float | matrix_1
  16 | float | matrix_2
  20 | float | matrix_3
  24 | float | matrix_4
  28 | float | matrix_5
  32 | float | matrix_6
  36 | float | matrix_7
  40 | float | matrix_8
  44 | float | matrix_9
  48 | float | matrix_10
  52 | float | matrix_11
  56 | float | matrix_12
  60 | float | matrix_13
  64 | float | matrix_14
  68 | float | matrix_15
  72 | float | scaleX
  76 | float | scaleY
  80 | uint | facingMode
  84 | int | billboardType
  88 | float | rotation
  92 | float | lightOverride
  96 | float | finalOffsetX
  100 | float | finalOffsetY
  104 | float | finalOffsetZ
  108 | float | depthFogParam
  112 | undefined4 | unk_70
  116 | void * | pBuild
  120 | undefined4 | unk_78
  124 | undefined4 | unk_7C
  128 | undefined4 | effectFallbackZ0
  132 | undefined4 | effectFallbackZN
  136 | float | effectOverride
  140 | undefined4 | dwAddColour
  144 | undefined4 | dwMultColour
  148 | float | unk_94
  152 | void * | pAnimNodeRef
  156 | undefined1 | bDepthWriteEnabled
  157 | undefined1 | bDepthTestEnabled
  158 | undefined1 | pad_9E
  159 | undefined1 | pad_9F
  160 | float | depthBias
  164 | undefined4 | vertexDescHandle
  168 | void * | hiddenLayers_begin
  172 | void * | hiddenLayers_end
  176 | void * | hiddenLayers_cap
  180 | void * | hiddenSymbols_begin
  184 | void * | hiddenSymbols_end
  188 | void * | hiddenSymbols_cap
  192 | undefined4 | rbTree_comparator
  196 | void * | rbTree_hdr_color
  200 | void * | rbTree_hdr_parent
  204 | void * | rbTree_hdr_left
  208 | void * | rbTree_hdr_right
  212 | undefined4 | rbTree_nodeCount
  216 | int | overrideBankHandle1
  220 | undefined4 | overrideBankHash1
  224 | int | overrideBankHandle2
  228 | undefined4 | overrideBankHash2
  232 | int | overrideSymbolHandle1
  236 | undefined4 | overrideSymbolHash1
  240 | int | overrideSymbolHandle2
  244 | undefined4 | overrideSymbolHash2

### TDataCacheBase
size: 4 (hex 0x4)
exists: true
layout:
  0 | void * | pVtable

### TDataCacheGameRender
size: 1264 (hex 0x4f0)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix
  72 | byte[1192] | pUNKNOWN_0x48

### TDataCacheWorld
size: 952 (hex 0x3b8)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix
  72 | byte[880] | pUNKNOWN_0x48

### TDataCacheImageNode
size: 180 (hex 0xb4)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix
  72 | byte[108] | pUNKNOWN_0x48

### TDataCacheLight
size: 1 (hex 0x1)
exists: false
note: Demangler placeholder Size=1; get_struct_layout says not a structure

### TDataCacheLightBuffer
size: 1 (hex 0x1)
exists: false

### TDataCacheMapComponent
size: 168 (hex 0xa8)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix
  72 | byte[96] | pUNKNOWN_0x48

### TDataCacheMiniMapComponent
size: 104 (hex 0x68)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix
  72 | byte[32] | pUNKNOWN_0x48

### TDataCacheMiniMapRenderer
size: 296 (hex 0x128)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix
  72 | byte[224] | pUNKNOWN_0x48

### TDataCacheOrthoScene
size: 1 (hex 0x1)
exists: false

### TDataCacheParticleBufferRenderer
size: 108 (hex 0x6c)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix
  72 | byte[36] | pUNKNOWN_0x48

### TDataCachePostProcessor
size: 1 (hex 0x1)
exists: false

### TDataCacheRoadManagerNode
size: 112 (hex 0x70)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix
  72 | byte[40] | pUNKNOWN_0x48

### TDataCacheSceneNode
size: 8 (hex 0x8)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner

### TDataCacheShadowRenderer
size: 72 (hex 0x48)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix

### TDataCacheTextNode
size: 236 (hex 0xec)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix
  72 | byte[164] | pUNKNOWN_0x48

### TDataCacheVFXParticleBufferRenderer
size: 100 (hex 0x64)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix
  72 | byte[28] | pUNKNOWN_0x48

### TDataCacheVideoNode
size: 124 (hex 0x7c)
exists: true
layout:
  0 | void * | pVtable
  4 | void * | pOwner
  8 | byte[64] | pMatrix
  72 | byte[52] | pUNKNOWN_0x48

### TDataCacheWorldNode
size: 1 (hex 0x1)
exists: false
note: Demangler placeholder Size=1; get_struct_layout says not a structure

### TRenderCache
size: 1 (hex 0x1)
exists: false

### RenderBuffer
size: n/a (not found)
exists: false
note: Structure not found as standalone type; only nested demangler RenderBuffer/* cmd types

### Atlas
size: 28 (hex 0x1c)
exists: true
layout:
  0 | byte[4] | pName
  4 | int | nTextureHandle
  8 | byte[12] | pRegions
  20 | byte[4] | pFilename
  24 | byte | bLoaded
  25 | byte[3] | p_pad

### AtlasManager
size: 64 (hex 0x40)
exists: true
layout:
  0 | void * | pVtable
  4 | int | nField_0x04
  8 | byte[12] | pResources
  24 | byte[20] | pHashMap
  44 | byte[12] | pVec_2C
  56 | byte[4] | pName
  60 | void * | pRenderer

### AnimationFile
size: 40 (hex 0x28)
exists: true
layout:
  0 | char * | filename_str_ptr
  4 | pointer | pAnimArray
  8 | pointer | pAnimElemArray
  12 | pointer | pFrameArray
  16 | pointer | pElemHashArray
  20 | uint | numElements
  24 | uint | numAnims
  28 | uint | numFrames
  32 | uint | numAnimElems
  36 | pointer | pBuild

### AnimManager
size: 116 (hex 0x74)
exists: true
layout:
  0 | pointer | vtable
  4 | uint | dwBase_04
  8 | uint | dwBase_08
  12 | uint | dwBase_0C
  16 | uint | dwBase_10
  20 | uint | dwPad14
  24 | pointer | vec_begin
  28 | uint | dwField_1C
  32 | pointer | vec_end
  36 | pointer | vec_cap
  40 | uint | dwField_28
  44 | uint | dwField_2C
  48 | uint | dwField_30
  52 | uint | dwField_34
  56 | pointer | strField38
  60 | pointer | pRenderer
  64 | pointer | bankMap_begin
  68 | pointer | bankMap_end
  72 | pointer | bankMap_cap
  76 | pointer | buildMap_begin
  80 | pointer | buildMap_end
  84 | uint | dwField_54
  88 | uint | dwShader_anim
  92 | uint | dwShader_anim_fade
  96 | uint | dwShader_anim_haunted
  100 | uint | dwShader_bloom
  104 | uint | dwShader_fade_haunted
  108 | uint | dwVertexDesc
  112 | uint | dwErosionTexture

### AnimNode
size: 348 (hex 0x15c)
exists: true
layout:
  0 | SceneGraphNode | base
  148 | pointer | pAnimFile
  152 | pointer | pBuild
  156 | uint | dwBankHash0
  160 | uint | dwBankHash1
  164 | uint | dwAnimHash0
  168 | uint | dwAnimHash1
  172 | uint | dwBuildHash0
  176 | uint | dwBuildHash1
  180 | uint | dwFacingMode
  184 | uint | dwPlayMode
  188 | float | flTime
  192 | float | flScaleX
  196 | float | flScaleY
  200 | float | flDepthBias
  204 | uint | dwEffectFallbackZ0
  208 | uint | dwEffectFallbackZN
  212 | float | flEffectOverride
  216 | uint | dwVertexDescHandle
  220 | pointer | hiddenLayers_begin
  224 | pointer | hiddenLayers_end
  228 | pointer | hiddenLayers_cap
  232 | pointer | hiddenSymbols_begin
  236 | pointer | hiddenSymbols_end
  240 | pointer | hiddenSymbols_cap
  244 | byte | bDepthTestEnabled
  245 | byte | bDepthWriteEnabled
  246 | ushort | wPad_F6
  248 | float | flSortOrder
  252 | uint | dwAddColour
  256 | uint | dwMultColour
  260 | float | flDepthFogParam
  264 | float | flRandSeed
  268 | uint | dwRbTree_comparator
  272 | uint | dwRbTree_hdr_color
  276 | pointer | rbTree_hdr_parent
  280 | pointer | rbTree_hdr_left
  284 | pointer | rbTree_hdr_right
  288 | int | nRbTree_nodeCount
  292 | int | nBillboardType
  296 | float | flRotation
  300 | float | flLightOverride
  304 | float | flFinalOffsetX
  308 | float | flFinalOffsetY
  312 | float | flFinalOffsetZ
  316 | int | nOverrideBankHandle1
  320 | uint | dwOverrideBankHash1
  324 | int | nOverrideBankHandle2
  328 | uint | dwOverrideBankHash2
  332 | int | nOverrideSymbolHandle1
  336 | uint | dwOverrideSymbolHash1
  340 | int | nOverrideSymbolHandle2
  344 | uint | dwOverrideSymbolHash2

### sPrefabAsset
size: 1 (hex 0x1)
exists: false

### sAnim
size: 36 (hex 0x24)
exists: true
layout:
  0 | pointer | pParent
  4 | pointer | pFrames
  8 | float | flFps
  12 | uint | dwBankHash0
  16 | uint | dwBankHash1
  20 | uint | dwNumFrames
  24 | pointer | name
  28 | uchar | bFacingByte
  29 | uchar | bPad1D
  30 | uchar | bPad1E
  31 | uchar | bPad1F
  32 | float | flDuration

### sBuild
size: 76 (hex 0x4c)
exists: true
layout:
  0 | pointer | pParent
  4 | dword | dwName_cow
  8 | pointer | pTexturesVec_begin
  12 | pointer | pTexturesVec_end
  16 | pointer | pTexturesVec_cap
  20 | pointer | pTextureHandles_begin
  24 | pointer | pTextureHandles_end
  28 | undefined4 | dw_pad28
  32 | pointer | pSymbols
  36 | pointer | pSymbolFrames
  40 | dword | dwVbHandle
  44 | dword | dwVbHandle2
  48 | pointer | pVertexData
  52 | pointer | pVertexData2
  56 | uint | dwNumVerts
  60 | uint | dwNumVerts2
  64 | uint | dwNumSymbolFrames
  68 | uint | dwNumSymbols
  72 | bool | fTexturesLoaded
  73 | byte[3] | p_pad49

### sBuildSymbolFrame
size: 52 (hex 0x34)
exists: true
layout:
  0 | uint | frameStart
  4 | uint | frameCount
  8 | uint | dwVertexStart
  12 | uint | dwVertexCount
  16 | uint | dwVertexStart2
  20 | uint | dwVertexCount2
  24 | float | bb_min_x
  28 | float | bb_min_y
  32 | float | bb_min_z
  36 | float | bb_max_x
  40 | float | bb_max_y
  44 | float | bb_max_z
  48 | float | radius

## Missing / placeholder
- BaseRenderer
- MiniMapRenderer
- ITextRenderer
- TDataCacheLight
- TDataCacheLightBuffer
- TDataCacheOrthoScene
- TDataCachePostProcessor
- TDataCacheWorldNode
- TRenderCache
- RenderBuffer
- sPrefabAsset
