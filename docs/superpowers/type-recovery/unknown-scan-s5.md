# UNKNOWN field scan — Slice5

> program: `dontstarve_steam` (macOS i386)
> mode: read-only (decompile + xrefs only; no Ghidra writes)
> generated: 2026-08-10
> scope: tServerListing(17) VideoNode(15) ControlMapper(8) FollowerComponent(6) StaticShadowComponent(5) DontStarveSystemService(4) EnvelopeTemplate(4) MigrationInfo(3) cTwitchManager(2) cLightEmitterComponent(2) SimplexNoise(2) GameServiceImpl(2) cPrefab(1) cGiftingManager(1) BaseTexture(1) BitmapFontManager(1) PostProcessor(1) cShardClientComponent(1) cNatTraversal(1) TDataCacheVFXParticleBufferRenderer(1) TDataCacheMapComponent(1) TDataCacheMiniMapRenderer(1) ShadowRenderer(1)

## Method

1. `get_struct_layout` for current field names/types.
2. Locate ctor / Deserialize / Serialize / Lua export via mangled-string xrefs + `search_functions_enhanced`.
3. Decompile 1–3 representative accessors per struct.
4. Name by access pattern; keep `UNKNOWN` only when no evidence.

Naming: `p<Name>` pointer, `n<Name>` int, `b<Name>` bool/byte, `dw<Name>` uint, `fl<Name>` float, `w<Name>` ushort.

---

## tServerListing (deep)

Evidence: ctor `0019a630`, Deserialize `0019f81a`, Serialize `0019f254`, WriteServerListingTable `00177141`.

### tServerListing.pStrs @ 0x00
semantic: pStrBlock (std::string[13]: name/ip/row/session/host/desc/tags/mode/data/worldgen/players/season/intent)
evidence: Deserialize assigns JSON keys into 0x00..0x30; WriteServerListingTable exports name/ip/description/session/tags/mode/game_data/intention/world_gen_data/players_data/season
confidence: high

### tServerListing.pM_mods @ 0x34
semantic: listModsInfo (std::list<tServerModInfo>)
evidence: ctor empty list; Deserialize fills from mods_info; Serialize emits mods_info array
confidence: high

### tServerListing.wField_0x3C @ 0x3C
semantic: wPort
evidence: JSON "port"; Lua "port"
confidence: high

### tServerListing.wField_0x3E @ 0x3E
semantic: wMaxConnections
evidence: JSON "maxconnections"; Lua "max_players"
confidence: high

### tServerListing.wField_0x40 @ 0x40
semantic: wConnected
evidence: JSON "connected"; Lua "current_players"
confidence: high

### tServerListing.nField_0x44 @ 0x44
semantic: nPing
evidence: WriteServerListingTable param_3[0x11] as "ping"; ctor -1
confidence: high

### tServerListing.nField_0x48 @ 0x48
semantic: nVersion
evidence: JSON "v"; Lua "version"
confidence: high

### tServerListing.nField_0x4C @ 0x4C
semantic: nSteamRoomLo
evidence: Deserialize base64::Decode_uint64("steamroom") → 0x4C/0x50
confidence: high

### tServerListing.nField_0x50 @ 0x50
semantic: nSteamRoomHi
evidence: same as 0x4C
confidence: high

### tServerListing.nField_0xAC @ 0xAC
semantic: nTick
evidence: JSON "tick"; ctor default 0xF
confidence: high

### tServerListing.bField_0xB0 @ 0xB0
semantic: bDedicated
evidence: JSON "dedicated"
confidence: high

### tServerListing.bField_0xB1 @ 0xB1
semantic: bClientHosted
evidence: JSON "clienthosted"; ctor 1
confidence: high

### tServerListing.nField_0xB2 @ 0xB2
semantic: flagsBoolPack (bPvp@+0, bPassword@+1, bMods@+2, bFriendsOnly@+3)
evidence: Deserialize pvp/password/mods/fo; Lua has_password/mods_enabled/friends_only/pvp
confidence: high

### tServerListing.nField_0xEC @ 0xEC
semantic: UNKNOWN (保持)
evidence: ctor DAT_00470268 only; no JSON/Lua key in Deserialize/WriteServerListingTable
confidence: low

### tServerListing.nField_0xF0 @ 0xF0
semantic: nNat
evidence: JSON "nat"; Lua "nat"; ctor 5
confidence: high

### tServerListing.nField_0xF4 @ 0xF4
semantic: flagsPost (offline@+0, bClanOnly@+1, bLanOnly@+2)
evidence: JSON clanonly/lanonly; Lua offline/clan_only/lan_only
confidence: high

### tServerListing.pStr_0xF8 @ 0xF8
semantic: pStrModsConfigData
evidence: WriteServerListingTable → "mods_config_data"
confidence: high

### tServerListing.nField_0xFC @ 0xFC
semantic: flagsClient (bHasDetails@0, bFriend@+1, bFriendPlaying@+2, bModsFailedDeser@+3)
evidence: WriteServerListingTable has_details/friend/friend_playing/mods_failed_deserialization
confidence: high

### tServerListing.bField_0x100 @ 0x100
semantic: bOffline
evidence: ctor 0; offline flag storage sibling of 0xF4 pack
confidence: medium

### tServerListing.pStr_0x104 @ 0x104
semantic: UNKNOWN (保持)
evidence: ctor empty string; not written in Deserialize/WriteServerListingTable
confidence: low

### tServerListing.wField_0x108 @ 0x108
semantic: UNKNOWN (保持)
evidence: ctor 0; has_details mapped to 0xFC not 0x108
confidence: low

---

## VideoNode (deep)

Evidence: ctor `000c883a`, Load `000c960c`, CacheVideoFrame `000c8c76`, dtor `000c8a6c`.

### VideoNode.pBase_0x04 @ 0x04
semantic: sgnBase (SceneGraphNode body after vtable)
evidence: ctor SceneGraphNode::SceneGraphNode; dtor ~SceneGraphNode
confidence: high

### VideoNode.pSize @ 0x50
semantic: flSizeXY
evidence: SetSizeEff mangled; layout already pSize
confidence: medium

### VideoNode.pUNKNOWN_0x58 @ 0x58
semantic: pSgnTailAndGame
evidence: ctor pulls game renderer resources into +0x58 region; Load uses *(+0x58+4) as game
confidence: medium

### VideoNode.dwField_0xA0 @ 0xA0
semantic: flWidth
evidence: ctor Zero pair with 0xA4
confidence: high

### VideoNode.dwField_0xA4 @ 0xA4
semantic: flHeight
evidence: same
confidence: high

### VideoNode.dwField_0xA8 @ 0xA8
semantic: UNKNOWN (保持)
evidence: ctor 0; no Load/CacheVideoFrame use
confidence: low

### VideoNode.dwField_0xAC @ 0xAC
semantic: UNKNOWN (保持)
evidence: ctor 0; no use observed
confidence: low

### VideoNode.dwTint @ 0xB0
semantic: dwTint (already named)
evidence: ctor White; SetTint
confidence: high

### VideoNode.dwField_0xB4 @ 0xB4
semantic: nPlayState
evidence: Load sets 3; CacheVideoFrame 1=stop countdown, 2=playing
confidence: high

### VideoNode.pName @ 0xB8
semantic: pStrPath (already named)
evidence: Load string::assign path
confidence: high

### VideoNode.timer @ 0xC0
semantic: timer (already named)
evidence: Timer::Reset/GetElapsedSeconds
confidence: high

### VideoNode.pIoCallbacks @ 0xC8
semantic: ioAndPlayback (IoFopen @+0x10, elapsed/frameMs, framebufs @+0x40)
evidence: ctor IoFopen*; Load frame duration; CacheVideoFrame double-buffer copy
confidence: high

### VideoNode.dwField_0xEC @ 0xEC
semantic: dwTexY
evidence: Load Y plane HWTexture handle; init -1
confidence: high

### VideoNode.dwField_0xF0 @ 0xF0
semantic: dwTexU
evidence: Load U plane handle
confidence: high

### VideoNode.dwField_0xF4 @ 0xF4
semantic: dwTexV
evidence: Load V plane handle
confidence: high

### VideoNode.bField_0xF8 @ 0xF8
semantic: bLoopOrFlag
evidence: ctor 1; field_0xf9 = hasAudio
confidence: medium

### VideoNode.dwField_0x100 @ 0x100
semantic: UNKNOWN (保持)
evidence: ctor 0; no access
confidence: low

### VideoNode.dwField_0x104 @ 0x104
semantic: UNKNOWN (保持)
evidence: ctor 0; no access
confidence: low

### VideoNode.dwField_0x108 @ 0x108
semantic: pFrameBuf0
evidence: Load operator_new__ into 0x108/0x10C
confidence: high

### VideoNode.dwField_0x10C @ 0x10C
semantic: pFrameBuf1
evidence: same
confidence: high

### VideoNode.dwField_0x110 @ 0x110
semantic: nFrameBufIndex
evidence: CacheVideoFrame toggles ~index&1
confidence: high

---

## ControlMapper

Evidence: ctor `000208c4`, OnControlMapped `00020a6f`.

### ControlMapper.wField @ 0x04
semantic: wIsMapping
evidence: assert mIsMapping at this+4; set 0x100 when mapping completes
confidence: high

### ControlMapper.pGlobal @ 0x08
semantic: nMappingDeviceId
evidence: ctor MaxDeviceId; used as device index into mapping table
confidence: high

### ControlMapper.nField_0x10 @ 0x10
semantic: nControlType
evidence: 1=DigitalControl, 2=AnalogControl
confidence: high

### ControlMapper.pMappingStorage2 @ 0x14
semantic: mappingScratch
evidence: this+0x14/0x18 control slot indices during map
confidence: medium

### ControlMapper.nField_0x24 @ 0x24
semantic: nLastInputId
evidence: stores BaseInput+8; ctor -1
confidence: high

### ControlMapper.bField_0x28 @ 0x28
semantic: bMappingChanged
evidence: OnControlMapped writes change flag
confidence: high

### ControlMapper.nField_0x34 @ 0x34
semantic: nCallbackUser
evidence: ctor 0 next to OnControlMapped functor at +0x30
confidence: medium

### ControlMapper.nField_0x38 @ 0x38
semantic: pInputMappings
evidence: mapping base = deviceId*0x268 + *(this+0x38)
confidence: high

### ControlMapper.nField_0x3C @ 0x3C
semantic: pDeviceDirtyFlags
evidence: OR dirty byte at *(this+0x3c)+deviceId
confidence: high

### ControlMapper.nField_0x40 @ 0x40
semantic: nNumDevices
evidence: assert mNumDevices > mMapping.mDeviceId
confidence: high

### ControlMapper.pUNKNOWN_0x44 @ 0x44
semantic: pMappingTableBlob
evidence: 452B residual device mapping storage
confidence: medium

---

## FollowerComponent

Evidence: ctor `00035ebc`, Serialize `000363b0`, Deserialize `000365d0`, FollowSymbol `00036040`.

### FollowerComponent.nField_0x10 @ 0x10
semantic: nSymbolHash
evidence: FollowSymbol cHashedString; Deserialize "symbol"
confidence: high

### FollowerComponent.pSName @ 0x14
semantic: pSymbolCstr
evidence: hashed-string cstr half with 0x10
confidence: high

### FollowerComponent.pVec_0x18 @ 0x18
semantic: flOffset
evidence: SerializeVector; Deserialize copies from 0x24
confidence: high

### FollowerComponent.pVec_0x24 @ 0x24
semantic: flOffsetNet
evidence: DeserializeVector into 0x24
confidence: high

### FollowerComponent.nField_0x30 @ 0x30
semantic: nLeaderGuid
evidence: ConvertGUIDToNetworkID; Deserialize "leader"
confidence: high

### FollowerComponent.nField_0x34 @ 0x34
semantic: UNKNOWN (保持)
evidence: ctor 0; not in Serialize/Deserialize/FollowSymbol
confidence: low

### FollowerComponent.bField_0x38 @ 0x38
semantic: UNKNOWN (保持)
evidence: ctor 0; no access
confidence: low

### FollowerComponent.nField_0x3C @ 0x3C
semantic: pTransform
evidence: caches entity transform; SetFollower
confidence: high

### FollowerComponent.wField_0x40 @ 0x40
semantic: wDirtyFlags
evidence: bits leader/symbol/offset axes gate Serialize
confidence: high

---

## StaticShadowComponent

### StaticShadowComponent.nField_0x10 @ 0x10
semantic: UNKNOWN (保持)
evidence: 已扫描无证据 (factory only; no ctor/method body)
confidence: low

### StaticShadowComponent.nField_0x14 @ 0x14
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### StaticShadowComponent.nField_0x18 @ 0x18
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### StaticShadowComponent.nField_0x1C @ 0x1C
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### StaticShadowComponent.nField_0x20 @ 0x20
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

---

## DontStarveSystemService

Evidence: ctor `00024116`.

### DontStarveSystemService.nField_0x04 @ 0x04
semantic: UNKNOWN (保持)
evidence: ctor 0 only
confidence: low

### DontStarveSystemService.nField_0x08 @ 0x08
semantic: UNKNOWN (保持)
evidence: ctor 0 only
confidence: low

### DontStarveSystemService.pCacheMap @ 0x0C
semantic: pCacheMap (already named)
evidence: ctor new 0x18 map root
confidence: high

### DontStarveSystemService.nField_0x38 @ 0x38
semantic: nStorageStateA
evidence: ctor = 4 after storage callbacks
confidence: medium

### DontStarveSystemService.nField_0x3C @ 0x3C
semantic: nStorageStateB
evidence: ctor = 7
confidence: medium

---

## EnvelopeTemplate

Evidence: ctors `00017ecc`, `00017fb4`.

### EnvelopeTemplate.dwField_0x00 @ 0x00
semantic: pVtable
evidence: ctor PTR_vtable+8
confidence: high

### EnvelopeTemplate.dwField_0x04 @ 0x04
semantic: nCount
evidence: ctor 0
confidence: high

### EnvelopeTemplate.dwField_0x08 @ 0x08
semantic: pEntries
evidence: ctor allocates entry array; stores at +8
confidence: high

### EnvelopeTemplate.dwField_0x0C @ 0x0C
semantic: nCapacity
evidence: ctor stores param_1
confidence: high

---

## MigrationInfo

Evidence: ctor `00165838`.

### MigrationInfo.nField_0x00 @ 0x00
semantic: nState
evidence: ctor 0
confidence: medium

### MigrationInfo.wField_0x08 @ 0x08
semantic: wPort
evidence: ctor 0 between target and steam id strings
confidence: medium

### MigrationInfo.nField_0x18 @ 0x18
semantic: UNKNOWN (保持)
evidence: ctor DAT_0046f5a0; semantics unclear from ctor alone
confidence: low

---

## cTwitchManager

Evidence: ctor `000b9f8c`.

### cTwitchManager.bField_0x1C @ 0x1C
semantic: bEnabled
evidence: ctor 1 after username
confidence: medium

### cTwitchManager.nField_0x20 @ 0x20
semantic: nState
evidence: ctor 0
confidence: medium

---

## cLightEmitterComponent

Evidence: ctor `00041e5c`, Serialize `0004232c`, Deserialize `000425f6`.

### cLightEmitterComponent.pVecColour_0x10 @ 0x10
semantic: flLightParams (derivedRadius, falloff, intensity, controlRadius)
evidence: Deserialize names control radius/intensity/falloff
confidence: high

### cLightEmitterComponent.nColour_0x20 @ 0x20
semantic: dwColour
evidence: SerializeColour/DeserializeColour
confidence: high

### cLightEmitterComponent.nField_0x24 @ 0x24
semantic: flagsEnabled (bEnabled@0, flags@1..2, bPristine@3); ctor 0x101
evidence: Serialize enabled bit0 + pristine OR into dirty
confidence: high

### cLightEmitterComponent.bField_0x28 @ 0x28
semantic: bDirtyFlags
evidence: Serialize gated by dirty bits
confidence: high

---

## SimplexNoise

Evidence: ctor `0012a9e0`.

### SimplexNoise.pUNKNOWN_0x104 @ 0x104
semantic: pGrad3
evidence: ctor bulk-copies DAT_003c7a10 into perm+grad tables (classic simplex layout)
confidence: high

### SimplexNoise.pUNKNOWN_0x504 @ 0x504
semantic: pGrad3B
evidence: same 0x400-dword copy covers both UNKNOWN blobs
confidence: high

---

## GameServiceImpl

Evidence: ctor `001c37b6`.

### GameServiceImpl.nField_0x04 @ 0x04
semantic: nNumSimultaneousPlayers
evidence: ctor stores param_1; assert MaxSimultaneousPlayers
confidence: high

### GameServiceImpl.nField_0x08 @ 0x08
semantic: nActivePlayerCount
evidence: ctor 0
confidence: medium

---

## cPrefab

Evidence: ctor `000f5bf6`.

### cPrefab.nField_0x20 @ 0x20
semantic: UNKNOWN (保持)
evidence: ctor 0 only; no further access
confidence: low

---

## cGiftingManager

Evidence: ctor `0014c2ca`.

### cGiftingManager.nField_0x04 @ 0x04
semantic: nState
evidence: ctor 0 next to vtable
confidence: medium

---

## BaseTexture

Evidence: ctor `001c4872`.

### BaseTexture.nField_0x0C @ 0x0C
semantic: UNKNOWN (保持)
evidence: base ctor does not init 0x0C
confidence: low

---

## BitmapFontManager

Evidence: ctor `000ac7c6`.

### BitmapFontManager.nField_0x04 @ 0x04
semantic: UNKNOWN (保持)
evidence: ctor does not touch +4
confidence: low

---

## PostProcessor

Evidence: ctor `000b68ce`, PostProcess `000b71be`.

### PostProcessor.pUNKNOWN_0x04 @ 0x04
semantic: postState (pRenderer@+0, vertDesc/VB, bloom/RT, blurh/blurv/combine/postprocess effects, colour-cubes, event dispatcher@+0x7c)
evidence: ctor stores Renderer*, creates effects/shaders; PostProcess uses offsets for SetEffect/SetTexture/BeginRenderTarget
confidence: high

note: field named pVtable@0 is actually nMode/flags (ctor writes 3)

---

## cShardClientComponent

### cShardClientComponent.wField_0x1C @ 0x1C
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

---

## cNatTraversal

### cNatTraversal.nField_0x194 @ 0x194
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

---

## TDataCacheVFXParticleBufferRenderer

### TDataCacheVFXParticleBufferRenderer.pUNKNOWN_0x48 @ 0x48
semantic: pCachedState
evidence: sibling TDataCache* pattern: owner render-state after matrix
confidence: medium

---

## TDataCacheMapComponent

Evidence: ctor `00046d0c`.

### TDataCacheMapComponent.pUNKNOWN_0x48 @ 0x48
semantic: pMapCache
evidence: copies MapComponent layer ptrs/rebuild request/fog handles into +0x48
confidence: high

---

## TDataCacheMiniMapRenderer

Evidence: ctor `000550d4`.

### TDataCacheMiniMapRenderer.pUNKNOWN_0x48 @ 0x48
semantic: pMiniMapCache
evidence: ctor zeros command/state slots in 0x48 blob
confidence: medium

---

## ShadowRenderer

### ShadowRenderer.dwField_0x94 @ 0x94
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

---

## Summary

| result | count |
|--------|------:|
| named (semantic assigned) | **72** |
| UNKNOWN kept | **18** |
| total fields scanned | **90** |

Priority deep dives:
- **tServerListing**: nearly all placeholders named high (3 UNKNOWN kept)
- **VideoNode**: 12 named / 3 UNKNOWN pad

Report path: `docs/superpowers/type-recovery/unknown-scan-s5.md`
