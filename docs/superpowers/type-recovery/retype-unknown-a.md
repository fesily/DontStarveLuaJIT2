# Phase A Unknown 字段回写 — 纯重命名报告

> 输入: docs/superpowers/type-recovery/unknown-naming-table.md(227 行)
> 操作: ghidra-mcp modify_struct_field(new_name) 写回 `dontstarve_steam`(macOS i386),program 参数全程显式
> 范围: 只改名,不改类型、不拆字段;含「拆分/应拆/建议拆/打包区/类型签名(* [ {)/非标识符首词」的行跳过(Phase B)
> 注1: 该 MCP 服务按字段当前声明类型强制 Hungarian 前缀归一(int→n, uint→dw, byte→b, bool→f, float→fl, ushort→w, byte[N>1]/void*→p)。请求名与当前类型前缀不一致时前缀被调整,语义名保留;类型/布局未动。
> 注2: TextNode 两字段有重名依赖,先 `pStrText→nEditCursorPos` 再 `bField_0x114→pStrText`,顺序已保证。

## 成功 (209 字段)

| struct | 字段(→语义名) | 数 |
|------|------|------|
| WaveComponent | nField_0x60→Time, nField_0x78→WaveTextureHandle, nField_0x7C→WaveEffectHandle, nField_0x80→VertexBufferHandle, nField_0x84→VertexDescHandle, bField_0x88→bEnabled, nField_0x8C→GameRenderer | 7 |
| RoadManagerComponent | nField_0xD0→GameRenderer, nField_0xD4→VertexDescHandle, nField_0xD8→QuadTreeRoot, nField_0xDC→SpCountedBase | 4 |
| cLightWatcherComponent | bField_0x10→bIsInLight, nField_0x14→LightAlpha, nField_0x18→LightValue, flField_0x34→LightThresh, flField_0x38→DarkThresh, wField_0x3C→Flags | 6 |
| cPController | flField_0x00→flCurrent, flField_0x04→flTarget, flField_0x08→flRate, flField_0x14→flDeadzone, fField_0x18→Clamp | 5 |
| MiniMapEntityComponent | nField_0x10→nPriority, nField_0x14→IconHash, pSName→StrName, nField_0x1C→Flags | 4 |
| WallStencilBuffer | dwField_0x20→DepthTextureHandle, dwField_0x24→RenderTargetHandle, bField_0x3C→bRenderEnabled | 3 |
| cSteamPunchthroughPlugin | nField_0x88→MinAddress, nField_0x8C→MaxAddress, nField_0x90→NextAddress | 3 |
| cCachedPingResults | nField_0x00→RbTreeHeader, nField_0x14→MapNodeCount | 2 |
| cShardNetworkComponent | nField_0x10→nLastSerializedState, bField_0x14→SerializeRetry | 2 |
| MapRenderer | dwField_0x14→BlendTextureHandle, dwField_0x18→BlendFactor | 2 |
| cNetworkManager | nField_0x70→nWhitelistSlots, nField_0x74→nConnectionTimeoutMs, nField_0x98→ServerGameplayFlags, nField_0xC0→SteamGroupIdLo, nField_0xC4→SteamGroupIdHi, nRakString→MRakString, bField_0x108→bEnableFrameDeserialize, wField_0x118→wUnassignedSystemIndex, pStrField_0x1A0→Str_0x1A0, pStrField_0x1B0→Str_0x1B0, pStrField_0x1B4→Str_0x1B4, pStrField_0x1F8→Str_0x1F8, pUnknown2FC→VtableObject_0x2FC | 13 |
| cUITransformComponent | nField_0x4C→nHAnchor, nField_0x50→nVAnchor, flField_0x70→flScaleX, flField_0x74→flScaleY, flField_0x78→flScaleZ, flField_0x180→flMaxScale | 6 |
| cSteamPunchthrough | pField_0x2C→VecPendingClanGUID_begin, nField_0x30→VecPendingClanGUID_end, nField_0x34→VecPendingClanGUID_cap, bField_0x3E→bGameConnectionInitiated, nField_0x40→AuthTargetIP, wField_0x44→wAuthTargetPort | 6 |
| GraphRenderer | dwField_0x10→ExtraVertBuffer | 1 |
| WindowManager | pField_0x7C→oCurrentModeFlags | 1 |
| cLuaNetworkVariable | bField_0x04→bDirty | 1 |
| TextNode | dwVertDescHandle→dwFontHandle, flFontScale→flFontSize, flField_0x9C→flLineSpacing, flMax_0xA0→flRegionW, flMax_0xA4→flRegionH, dwField_0xA8→WordWrap, bField_0xAC→bWhitespaceWrap, dwField_0xB0→HAnchor, dwField_0xB4→VAnchor, pHandles_0xBC→EditLineHandles, dwField_0xF4→DepthTest, pVec3_0x100→Offset, bField_0x110→bAutoRegion, bField_0x114→StrText, bField_0x118→bShowEditCursor, pStrText→EditCursorPos, dwField_0x124→dwTexHandle | 17 |
| DebugRenderComponent | nField_0xA4→Y, nField_0xAC→VecStrings_begin, nField_0xB0→VecStrings_end, nField_0xB4→VecStrings_cap, nField_0xB8→VecLines_begin, nField_0xBC→VecLines_end, nField_0xC0→VecLines_cap, nField_0xC4→VecCircles_begin, nField_0xC8→VecCircles_end, nField_0xCC→VecCircles_cap, nField_0xD0→VecBoxes_begin, nField_0xD4→VecBoxes_end, nField_0xD8→VecBoxes_cap, nField_0xDC→VecTriangles_begin, nField_0xE0→VecTriangles_end, nField_0xE4→VecTriangles_cap | 16 |
| cSoundEmitterComponent | pVtable→Events_begin, nField_0x14→Events_end, nField_0x18→Events_cap, nField_0x1C→VecSoundNames_begin, nField_0x20→VecSoundNames_end, nField_0x24→VecSoundNames_cap, nField_0x28→MapNamedEvents, nField_0x2C→MapHeader_color, nField_0x30→MapHeader_parent, nField_0x34→MapHeader_left, nField_0x38→MapHeader_right, nField_0x3C→MapNodeCount, nField_0x40→Active, nField_0x44→VecDirtyEvents, nField_0x48→VecDirtyEventsPrev, nField_0x4C→Volume | 16 |
| cShardManager | nField_0x40→nDefaultFlag, bField_0x5C→bIncomingMigrationActive, bField_0x98→bFlag_0x98, bField_0x99→bFlag_0x99 | 4 |
| cAccountCommunication | bField_0x30→bConnected, bField_0xC0→bBusy | 2 |
| DynamicShadowComponent | nField_0x10→SizeX, nField_0x14→SizeY | 2 |
| cAccountManager | bField_0x04→bInitialized, bField_0x40→bOnlineCapable | 2 |
| MapComponent | flField_0x188→flOverlayScale | 1 |
| cMasterServer | nField_0x8C→ProtocolFlags, bField_0x90→bEnabled | 2 |
| cSteamRichPresence | bField_0x1C→bDirty, bField_0x52→bHasConnectString | 2 |
| cNetworkComponent | bField_0x170→bIsSleeping | 1 |
| BitmapFont | dwField_0x14→nOutline | 1 |
| ParticleBuffer | wField_0x08→wActiveCount | 1 |
| TDataCacheImageNode | pUNKNOWN_0x48→ImageCacheState | 1 |
| TDataCacheTextNode | pUNKNOWN_0x48→TextCacheState | 1 |
| cMasterServerRequest | bField_0x04→bInFlight | 1 |
| tServerListing | pM_mods→ListModsInfo, wField_0x3C→wPort, wField_0x3E→wMaxConnections, wField_0x40→wConnected, nField_0x44→nPing, nField_0x48→nVersion, nField_0x4C→nSteamRoomLo, nField_0x50→nSteamRoomHi, nField_0xAC→nTick, bField_0xB0→bDedicated, bField_0xB1→bClientHosted, nField_0xB2→FlagsBoolPack, nField_0xF0→nNat, nField_0xF4→FlagsPost, pStr_0xF8→StrModsConfigData, nField_0xFC→FlagsClient, bField_0x100→bOffline | 17 |
| VideoNode | pBase_0x04→SgnBase, pSize→SizeXY, pUNKNOWN_0x58→SgnTailAndGame, dwField_0xA0→Width, dwField_0xA4→Height, dwField_0xB4→PlayState, pName→StrPath, pIoCallbacks→IoAndPlayback, dwField_0xEC→dwTexY, dwField_0xF0→dwTexU, dwField_0xF4→dwTexV, bField_0xF8→bLoopOrFlag, dwField_0x108→FrameBuf0, dwField_0x10C→FrameBuf1, dwField_0x110→FrameBufIndex | 15 |
| ControlMapper | wField→wIsMapping, pGlobal→MappingDeviceId, nField_0x10→nControlType, pMappingStorage2→MappingScratch, nField_0x24→nLastInputId, bField_0x28→bMappingChanged, nField_0x34→nCallbackUser, nField_0x38→InputMappings, nField_0x3C→DeviceDirtyFlags, nField_0x40→nNumDevices, pUNKNOWN_0x44→MappingTableBlob | 11 |
| FollowerComponent | nField_0x10→nSymbolHash, pSName→SymbolCstr, pVec_0x18→Offset, pVec_0x24→OffsetNet, nField_0x30→nLeaderGuid, nField_0x3C→Transform, wField_0x40→wDirtyFlags | 7 |
| DontStarveSystemService | nField_0x38→nStorageStateA, nField_0x3C→nStorageStateB | 2 |
| EnvelopeTemplate | dwField_0x00→Vtable, dwField_0x04→Count, dwField_0x08→Entries, dwField_0x0C→Capacity | 4 |
| MigrationInfo | nField_0x00→nState, wField_0x08→wPort | 2 |
| cTwitchManager | bField_0x1C→bEnabled, nField_0x20→nState | 2 |
| cLightEmitterComponent | pVecColour_0x10→LightParams, nColour_0x20→Colour, nField_0x24→FlagsEnabled, bField_0x28→bDirtyFlags | 4 |
| SimplexNoise | pUNKNOWN_0x104→Grad3, pUNKNOWN_0x504→Grad3B | 2 |
| GameServiceImpl | nField_0x04→nNumSimultaneousPlayers, nField_0x08→nActivePlayerCount | 2 |
| cGiftingManager | nField_0x04→nState | 1 |
| PostProcessor | pUNKNOWN_0x04→postState | 1 |
| TDataCacheVFXParticleBufferRenderer | pUNKNOWN_0x48→CachedState | 1 |
| TDataCacheMapComponent | pUNKNOWN_0x48→MapCache | 1 |
| TDataCacheMiniMapRenderer | pUNKNOWN_0x48→MiniMapCache | 1 |

## 跳过 (16)

拆分/改类型 → Phase B (13):
| struct.field | new_name | 原因 |
|------|------|------|
| WaveComponent.pVec_0x64 | 拆分为 flWidth@0x64 + flHeight@0x68 + nNumWaves@0x6C | 拆分 |
| cNetworkManager.wField_0x8E | bPad_0x8E + bAutosaverEnabled | ushort 打包,需拆 |
| WindowManager.pField_0x04 | oWindowState | 建议拆字段,非单 blob |
| TDataCacheParticleBufferRenderer.pUNKNOWN_0x48 | 应拆为粒子缓存快照 | 应拆 |
| TDataCacheVideoNode.pUNKNOWN_0x48 | 应拆为视频节点渲染快照 | 应拆 |
| ImageNode.pUNKNOWN_0x94 | 应拆为 Image 渲染状态 | 应拆 |
| GameLibConfig.pField_0x00 | 应拆(非单 68B blob) | 应拆 |
| GameLibConfig.pStrs | 8×std::string | 拆分(8 个 string) |
| GameLibConfig.pNetIds | 尾部 cNetID2 + 标志 | 拆分 |
| cShardManager.pField_0x00 | pVtable + 前置状态块 | 建议拆(名含 +) |
| DynamicShadowComponent.nField_0x18 | bEnabled/bPristine/bFlags 打包区 | 打包区需拆 |
| ParticleEmitter.pUNKNOWN_0x04 | pEmitterState | 建议后续拆分(混合块) |
| tServerListing.pStrs | pStrBlock (std::string[13]) | 类型签名含 [ |

已命名/无操作 (3):
| struct.field | 说明 |
|------|------|
| VideoNode.dwTint | 已是 dwTint |
| VideoNode.timer | 已是 timer |
| DontStarveSystemService.pCacheMap | 已是 pCacheMap |

## 失败 (2)

| struct.field | 目标名 | 原因 |
|------|------|------|
| TextNode.field_0x119 | bEditCursorState | Ghidra 布局无此字段:0x119–0x11B 是 bField_0x118(0x118)与 pStrText/pEditCursorPos(0x11C)之间的未定义 gap,无独立字段可改名 |
| TextNode.field_0x11a | bScrollEditWindow | 同上 |

> 备注: 表中 TextNode.bField_0x114→pStrText 与 pStrText→nEditCursorPos 两行已按顺序执行,布局中现为 bStrText(0x114, byte)与 pEditCursorPos(0x11C, byte[4])——语义名保留,前缀按类型归一。

## 抽查验证(13 struct, get_struct_layout 复核)

| struct | size(改前/改后) | 新名生效确认 |
|------|------|------|
| WaveComponent | 144 / 144 | Time@0x60, WaveTextureHandle@0x78, bEnabled@0x88, GameRenderer@0x8C |
| cPController | 25 / 25 | flCurrent@0x00, flTarget, flRate, flDeadzone@0x14, fClamp@0x18 |
| TextNode | 356 / 356 | dwFontHandle, flFontSize, flLineSpacing, flRegionW/H, pEditLineHandles, pOffset, bAutoRegion, bStrText@0x114, bShowEditCursor, pEditCursorPos@0x11C, dwTexHandle |
| DebugRenderComponent | 232 / 232 | nY@0xA4, nVecStrings/Lines/Circles/Boxes/Triangles begin/end/cap 全组 |
| cSoundEmitterComponent | 84 / 84 | pEvents_begin@0x10, MapNamedEvents, MapHeader_*, nMapNodeCount, nVecDirtyEvents, nVolume@0x4C |
| tServerListing | 266 / 266 | pListModsInfo, wPort, wMaxConnections, wConnected, nPing, nVersion, nSteamRoomLo/Hi, nTick, bDedicated, bClientHosted, nFlagsBoolPack, nNat, nFlagsPost, pStrModsConfigData, nFlagsClient, bOffline |
| VideoNode | 276 / 276 | pSgnBase, pSizeXY, dwWidth/Height, dwPlayState, pStrPath, pIoAndPlayback, dwTexY/U/V, bLoopOrFlag, dwFrameBuf0/1, dwFrameBufIndex |
| ControlMapper | 520 / 520 | wIsMapping, pMappingDeviceId, nControlType, pMappingScratch, nLastInputId, bMappingChanged, nCallbackUser, nInputMappings, nDeviceDirtyFlags, nNumDevices, pMappingTableBlob |
| FollowerComponent | 66 / 66 | nSymbolHash, pSymbolCstr, pOffset, pOffsetNet, nLeaderGuid, nTransform, wDirtyFlags |
| cLightEmitterComponent | 41 / 41 | pLightParams, nColour, nFlagsEnabled, bDirtyFlags |
| EnvelopeTemplate | 16 / 16 | dwVtable, dwCount, dwEntries, dwCapacity |
| cShardManager | 168 / 168 | nDefaultFlag@0x40, bIncomingMigrationActive@0x5C, bFlag_0x98, bFlag_0x99 |
| cNetworkManager | 5048 / 5048 | nWhitelistSlots, nConnectionTimeoutMs, nServerGameplayFlags, nSteamGroupIdLo/Hi, nMRakString, bEnableFrameDeserialize, wUnassignedSystemIndex, pStr_0x1A0/1B0/1B4/1F8, pVtableObject_0x2FC |

全部字段名已生效且 struct size 与改前一致(类型未动)。已 save_program。

结论:209 成功 / 16 跳过(13 拆分+3 已命名)/ 2 失败(TextNode 0x119/0x11A 无字段)。
