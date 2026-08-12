# Blob Split C — Field Evidence Report

> program=`dontstarve_steam` (macOS i386)
> method: get_struct_layout + decompile ctor/DoCacheForRender/DrawCacheRender (read-only)
> (scout EPERM, 主 agent 物化)

## TDataCacheParticleBufferRenderer.pUNKNOWN_0x48 @ 0x48 (36B)

Ctor 0x60774; DoCacheForRender 0x6025a (alloc 0x6C)。

### 拆分建议
| offset | size | type | name | evidence |
|--------|------|------|------|----------|
| +0x00 (0x48) | 4 | uint | nField_48 | ctor `*(this+0x48)=param_1+0x94` (pRenderer) |
| +0x04 (0x4C) | 4 | ParticleEmitter* | pEmitter | ctor `=param_1+0x98` |
| +0x08 (0x50) | 4 | uint | nField_50 | ctor `=param_1+0x9c` (dwField_0x9C) |
| +0x0C (0x54) | 4 | uint | nNumVerts | ctor `=(uint)*(ushort*)(vertDesc+8)` |
| +0x10 (0x58) | 4 | void* | pData0 | CacheRenderAllocate(n*4) from vertDesc+0x20 |
| +0x14 (0x5C) | 4 | void* | pData1 | CacheRenderAllocate(n*4) from vertDesc+0x24 |
| +0x18 (0x60) | 4 | void* | pData2 | CacheRenderAllocate(n*12) from vertDesc+0x0c |
| +0x1C (0x64) | 4 | void* | pData3 | CacheRenderAllocate(n*8) from vertDesc+0x14 |
| +0x20 (0x68) | 4 | void* | pData4 | CacheRenderAllocate(n*4) from vertDesc+0x18 |

**status: 可拆** (9 fields)

---

## TDataCacheVideoNode.pUNKNOWN_0x48 @ 0x48 (52B)

Ctor 0xc9df2; DoCacheForRender 0xc8f5c (alloc 0x7C); DrawCacheRender 0xc9004。

### 拆分建议
| offset | size | type | name | evidence |
|--------|------|------|------|----------|
| +0x00 (0x48) | 4 | int | nHAnchor | ctor `=VideoNode+0xa8` |
| +0x04 (0x4C) | 4 | int | nVAnchor | ctor `=VideoNode+0xac` |
| +0x08 (0x50) | 8 | Vector2 | flSizeXY | ctor QWORD `=VideoNode+0xa0` |
| +0x10 (0x58) | 4 | uint | nEffectHandle | ctor `=VideoNode+0x94`; Batcher::SetEffect |
| +0x14 (0x5C) | 4 | Colour/uint | dwTint | ctor `=VideoNode+0xb0` |
| +0x18 (0x60) | 4 | int | nFrameW | ctor `=VideoNode+0xd0` |
| +0x1C (0x64) | 4 | int | nFrameH | ctor `=VideoNode+0xd4` |
| +0x20 (0x68) | 4 | void* | pFramePixels | DoCache `=CacheVideoFrame(this)` |
| +0x24 (0x6C) | 4 | uint | dwTexY | ctor `=VideoNode+0xec` |
| +0x28 (0x70) | 4 | uint | dwTexU | ctor `=VideoNode+0xf0` |
| +0x2C (0x74) | 4 | uint | dwTexV | ctor `=VideoNode+0xf4` |
| +0x30 (0x78) | 1 | bool | bUseTransTex | ctor `=(bLoopOrFlag)||(dwPlayState==1)` |
| +0x31..0x33 | 3 | pad | — | end of 52B |

**status: 可拆** (12 fields + pad)

---

## ImageNode.pUNKNOWN_0x94 @ 0x94 (112B)

Ctor 0xc3416 (alloc 0x104); DoCacheForRender 0xc4058 → TDataCacheImageNode 0xc40f8。

### 拆分建议
| offset | size | type | name | evidence |
|--------|------|------|------|----------|
| +0x00 (0x94) | 4 | int | nMaxLines | ctor = -1 |
| +0x04 (0x98) | 4 | int | nField_98 | ctor = -1 |
| +0x08 (0x9C) | 4 | uint | nField_9C | ctor = 0 |
| +0x0C (0xA0) | 4 | uint | nBlendMode | ctor = 3; SetBlendMode |
| +0x10 (0xA4) | 4 | uint | dwTextureHandle | ctor from AtlasManager+0xc |
| +0x14 (0xA8) | 4 | uint | dwTextureHandle2 | ctor from AtlasManager+0x8 |
| +0x18 (0xAC) | 4 | uint | nField_AC | ctor from AtlasManager+0x18 |
| +0x1C (0xB0) | 8 | Vector2 | flSize | ctor Zero; SetSize |
| +0x24 (0xB8) | 4 | uint | nField_B8 | ctor 0 |
| +0x28 (0xBC) | 4 | uint | nField_BC | ctor 0 |
| +0x2C (0xC0) | 4 | Colour/uint | dwTint | ctor White; SetTint |
| +0x30 (0xC4) | 4 | float | flAlphaMax | ctor 1.0f; SetAlphaRange param1 |
| +0x34 (0xC8) | 4 | float | flAlphaMin | ctor 1.0f; SetAlphaRange param2 |
| +0x38 (0xCC) | 4 | float | flField_CC | ctor 1.0f |
| +0x3C (0xD0) | 12 | Vector3 | vOffset | ctor Zero |
| +0x48 (0xDC) | 4 | uint | nField_DC | ctor 0 |
| +0x4C (0xE0) | 4 | float | flField_E0 | ctor 1.0f |
| +0x50 (0xE4) | 8 | Vector2 | vEffectParams | ctor from Zero |
| +0x58 (0xEC) | 8 | — | vField_EC | ctor from unk_46564C |
| +0x60 (0xF4) | 1 | bool | bDepthTest | ctor 0 |
| +0x61 (0xF5) | 1 | bool | bDepthWrite | ctor 0 |
| +0x64 (0xF8) | 12 | Vector3 | vField_F8 | ctor Zero |
| +0x70 (0x100) | 4 | uint | nField_100 | ctor 0 |

**status: 可拆** (~24 fields)

---

## TDataCacheRoadManagerNode.pUNKNOWN_0x48 @ 0x48 (40B)

D2 0x70d4a; DrawCacheRender 0x6dbda; RenderRoads 0x6dca8。

### 拆分建议
| offset | size | type | name | evidence |
|--------|------|------|------|----------|
| +0x00 (0x48) | 4 | void* | pStripData_begin | RenderRoads gate; D2 delete |
| +0x04 (0x4C) | 4 | void* | pStripData_end | strip count (end-begin)/0xB0 |
| +0x08 (0x50) | 4 | void* | pStripData_cap | (inferred) |
| +0x0C (0x54) | 4 | uint | dwVertDescHandle | SetVertexDescription |
| +0x10 (0x58) | 4 | — | nField_58 | unused/gap |
| +0x14 (0x5C) | 4 | AABB3F* | pAABB_begin | frustum loop step 0x18; D2 delete |
| +0x18 (0x60) | 4 | AABB3F* | pAABB_end | loop end |
| +0x1C (0x64) | 4 | AABB3F* | pAABB_cap | (inferred) |
| +0x20 (0x68) | 4 | GameRenderer* | pRenderer | PopShaderConstantHash |

**status: 可拆** (9 fields; caps inferred)

---

## cNetworkClientObject2.pUNKNOWN_0x1BC @ 0x1BC (60B)

**Layout note:** ctor 0x162dea disasm:
```
LEA EDI,[EBX+0x17c]
CALL cPlayerListingData::cPlayerListingData  ; 0x19ab16
LEA EAX,[EBX+0x1fc]
CALL Timer::Timer
```
真实 embed 是 **cPlayerListingData @ 0x17C, size 0x80 (128B)** 到 0x1FC; pUNKNOWN_0x1BC 是错位窗口(内部 colour@0x1B8)。

### cPlayerListingData layout (relative to 0x17C)
| offset | abs | size | type | name | evidence |
|--------|-----|------|------|------|----------|
| +0x00 | 0x17C | 4 | std::string | strName | ctor empty_rep |
| +0x04 | 0x180 | 44 | cNetID2 | netId | cNetID2::Clear; SetNetID |
| +0x28 | 0x1A4 | 4 | uint | nField_28 | ctor 0 |
| +0x2C | 0x1A8 | 4 | uint | nField_2C | ctor 0 |
| +0x30 | 0x1AC | 4 | RakString | rakStr | RakString ctor; GetName |
| +0x34 | 0x1B0 | 4 | uint | nHash0 | ctor 0 |
| +0x38 | 0x1B4 | 4 | cHashedString | hash1 | mEmptyString |
| +0x3C | 0x1B8 | 4 | Colour | colour | UNASSIGNED_COLOUR; SetColour |
| +0x40 | 0x1BC | 4 | uint | nUserFlags | ctor 0 |
| +0x44 | 0x1C0 | 1 | byte | bAdmin | ctor 0 |
| +0x48 | 0x1C4 | 4 | uint | nField_48 | ctor 0 |
| +0x4C | 0x1C8 | 4 | cHashedString | hashPrefab | mEmptyString |
| +0x50 | 0x1CC | 4 | uint | nField_50 | 0 |
| +0x54 | 0x1D0 | 4 | cHashedString | hashSkin1 | mEmptyString |
| +0x5C | 0x1D8 | 4 | cHashedString | hashSkin2 | mEmptyString |
| +0x64 | 0x1E0 | 4 | cHashedString | hashSkin3 | mEmptyString |
| +0x6C | 0x1E8 | 4 | cHashedString | hashSkin4 | mEmptyString |
| +0x70 | 0x1EC | 4 | void* | pEquipBegin | ctor 0; dtor free |
| +0x74 | 0x1F0 | 4 | void* | pEquipEnd | ctor 0 |
| +0x7C | 0x1F8 | 2 | ushort | wAgeOrScore | 0 |

**status: 可拆** — replace pColour@0x1B8 + pUNKNOWN_0x1BC@0x1BC with embedded `cPlayerListingData listing @ 0x17C` (128B)。

---

## 汇总

| blob | size | 可拆? | fields |
|------|------|-------|--------|
| TDataCacheParticleBufferRenderer.pUNKNOWN_0x48 | 36 | 可拆 | 9 |
| TDataCacheVideoNode.pUNKNOWN_0x48 | 52 | 可拆 | 12+pad |
| ImageNode.pUNKNOWN_0x94 | 112 | 可拆 | ~24 |
| TDataCacheRoadManagerNode.pUNKNOWN_0x48 | 40 | 可拆 | 9 |
| cNetworkClientObject2.pUNKNOWN_0x1BC | 60 (misaligned) | 可拆 | embed cPlayerListingData 128B @0x17C |

**可拆 N = 5 / 需更多调查 M = 0**
