# 同步 types_common.h 字段名 ← Ghidra (Unknown 字段修复后)

> 输入: docs/superpowers/type-recovery/retype-unknown-a.md(Phase A 纯重命名报告,209 成功字段)
> 操作: 对 48 个 struct 调 ghidra-mcp `get_struct_layout(program=dontstarve_steam)` 取当前布局,把 Ghidra 新字段名同步到 `3rd/dst/game_decompiler/types_common.h`
> 范围: 只改字段名;类型/size/字段顺序不动;已命名字段、vector 三件套、_pad 等保留
> 注: Ghidra 名带 Hungarian 前缀(int→n、uint→dw、byte→b、bool→f、float→fl、ushort→w、byte[N>1]/void*→p),同步以 Ghidra 实际名为准

## 汇总

- 更新 struct 数: **48** / 276(总数不变)
- 更新字段数: **209** / 209(全部 Phase A 成功字段均已同步)
- 未涉及 struct: 228(未动)

## 各 struct 同步明细

| struct | 改名字段数 | 说明 |
|------|------|------|
| WaveComponent | 7 | nField_0x60→nTime, nField_0x78→nWaveTextureHandle, nField_0x7C→nWaveEffectHandle, nField_0x80→nVertexBufferHandle, nField_0x84→nVertexDescHandle, bField_0x88→bEnabled, nField_0x8C→nGameRenderer |
| RoadManagerComponent | 4 | nField_0xD0→nGameRenderer, nField_0xD4→nVertexDescHandle, nField_0xD8→nQuadTreeRoot, nField_0xDC→nSpCountedBase |
| cLightWatcherComponent | 6 | bField_0x10→bIsInLight, nField_0x14→nLightAlpha, nField_0x18→nLightValue, flField_0x34→flLightThresh, flField_0x38→flDarkThresh, wField_0x3C→wFlags |
| cPController | 5 | flField_0x00→flCurrent, flField_0x04→flTarget, flField_0x08→flRate, flField_0x14→flDeadzone, fField_0x18→fClamp |
| MiniMapEntityComponent | 4 | nField_0x10→nPriority, nField_0x14→nIconHash, sName→pStrName, nField_0x1C→nFlags |
| WallStencilBuffer | 3 | dwField_0x20→dwDepthTextureHandle, dwField_0x24→dwRenderTargetHandle, bField_0x3C→bRenderEnabled |
| cSteamPunchthroughPlugin | 3 | nField_0x88→nMinAddress, nField_0x8C→nMaxAddress, nField_0x90→nNextAddress |
| cCachedPingResults | 2 | nField_0x00→nRbTreeHeader, nField_0x14→nMapNodeCount |
| cShardNetworkComponent | 2 | nField_0x10→nLastSerializedState, bField_0x14→bSerializeRetry |
| MapRenderer | 2 | dwField_0x14→dwBlendTextureHandle, dwField_0x18→dwBlendFactor |
| cNetworkManager | 13 | nField_0x70→nWhitelistSlots, nField_0x74→nConnectionTimeoutMs, nField_0x98→nServerGameplayFlags, nField_0xC0→nSteamGroupIdLo, nField_0xC4→nSteamGroupIdHi, nRakString→nMRakString, bField_0x108→bEnableFrameDeserialize, wField_0x118→wUnassignedSystemIndex, pStrField_0x1A0→pStr_0x1A0, pStrField_0x1B0→pStr_0x1B0, pStrField_0x1B4→pStr_0x1B4, pStrField_0x1F8→pStr_0x1F8, pUnknown2FC→pVtableObject_0x2FC |
| cUITransformComponent | 6 | nField_0x4C→nHAnchor, nField_0x50→nVAnchor, flField_0x70→flScaleX, flField_0x74→flScaleY, flField_0x78→flScaleZ, flField_0x180→flMaxScale |
| cSteamPunchthrough | 6 | pField_0x2C→pVecPendingClanGUID_begin, nField_0x30→nVecPendingClanGUID_end, nField_0x34→nVecPendingClanGUID_cap, bField_0x3E→bGameConnectionInitiated, nField_0x40→nAuthTargetIP, wField_0x44→wAuthTargetPort |
| GraphRenderer | 1 | dwField_0x10→dwExtraVertBuffer |
| WindowManager | 1 | pField_0x7C→pOCurrentModeFlags |
| cLuaNetworkVariable | 1 | bField_0x04→bDirty |
| TextNode | 17 | dwVertDescHandle→dwFontHandle, flFontScale→flFontSize, flField_0x9C→flLineSpacing, flMax_0xA0→flRegionW, flMax_0xA4→flRegionH, dwField_0xA8→dwWordWrap, bField_0xAC→bWhitespaceWrap, dwField_0xB0→dwHAnchor, dwField_0xB4→dwVAnchor, pHandles_0xBC→pEditLineHandles, dwField_0xF4→dwDepthTest, pVec3_0x100→pOffset, bField_0x110→bAutoRegion, bField_0x114→bStrText, bField_0x118→bShowEditCursor, pStrText→pEditCursorPos, dwField_0x124→dwTexHandle |
| DebugRenderComponent | 16 | nField_0xA4→nY, nField_0xAC..nField_0xE4→nVecStrings/Lines/Circles/Boxes/Triangles begin/end/cap 全组 |
| cSoundEmitterComponent | 16 | pVtable→pEvents_begin, nField_0x14→nEvents_end, nField_0x18→nEvents_cap, nField_0x1C..0x24→nVecSoundNames_begin/end/cap, nField_0x28→nMapNamedEvents, nField_0x2C..0x38→nMapHeader_color/parent/left/right, nField_0x3C→nMapNodeCount, nField_0x40→nActive, nField_0x44→nVecDirtyEvents, nField_0x48→nVecDirtyEventsPrev, nField_0x4C→nVolume |
| cShardManager | 4 | nField_0x40→nDefaultFlag, bField_0x5C→bIncomingMigrationActive, bField_0x98→bFlag_0x98, bField_0x99→bFlag_0x99 |
| cAccountCommunication | 2 | bField_0x30→bConnected, bField_0xC0→bBusy |
| DynamicShadowComponent | 2 | nField_0x10→nSizeX, nField_0x14→nSizeY |
| cAccountManager | 2 | bField_0x04→bInitialized, bField_0x40→bOnlineCapable |
| MapComponent | 1 | flField_0x188→flOverlayScale |
| cMasterServer | 2 | nField_0x8C→nProtocolFlags(拆分 nField_0x80[4] 数组为 4 个 int,布局不变), bField_0x90→bEnabled |
| cSteamRichPresence | 2 | bField_0x1C→bDirty, bField_0x52→bHasConnectString |
| cNetworkComponent | 1 | bField_0x170→bIsSleeping |
| BitmapFont | 1 | nField_0x14→dwOutline |
| ParticleBuffer | 1 | wField_0x08→wActiveCount |
| TDataCacheImageNode | 1 | pUNKNOWN_0x48→pImageCacheState |
| TDataCacheTextNode | 1 | pUNKNOWN_0x48→pTextCacheState |
| cMasterServerRequest | 1 | bField_0x04→bInFlight |
| tServerListing | 17 | pM_mods→pListModsInfo, wField_0x3C→wPort, wField_0x3E→wMaxConnections, wField_0x40→wConnected, nField_0x44→nPing, nField_0x48→nVersion, nField_0x4C→nSteamRoomLo, nField_0x50→nSteamRoomHi, nField_0xAC→nTick, bField_0xB0→bDedicated, bField_0xB1→bClientHosted, nField_0xB2→nFlagsBoolPack, nField_0xF0→nNat, nField_0xF4→nFlagsPost, pStr_0xF8→pStrModsConfigData, nField_0xFC→nFlagsClient, bField_0x100→bOffline |
| VideoNode | 15 | pVtable→pSizeXY, UNKNOWN_0x58→pSgnTailAndGame, nField_0xA0→dwWidth, nField_0xA4→dwHeight, tint→dwTint, nField_0xB4→dwPlayState, name→pStrPath, ioCallbacks→pIoAndPlayback, nField_0xEC→dwTexY, nField_0xF0→dwTexU, nField_0xF4→dwTexV, bField_0xF8→bLoopOrFlag, nField_0x108→dwFrameBuf0, nField_0x10C→dwFrameBuf1, nField_0x110→dwFrameBufIndex |
| ControlMapper | 11 | wField→wIsMapping, pGlobal→pMappingDeviceId, nField_0x10→nControlType, pMappingStorage2→pMappingScratch, nField_0x24→nLastInputId, bField_0x28→bMappingChanged, nField_0x34→nCallbackUser, nField_0x38→nInputMappings, nField_0x3C→nDeviceDirtyFlags, nField_0x40→nNumDevices, pUNKNOWN_0x44→pMappingTableBlob |
| FollowerComponent | 7 | nField_0x10→nSymbolHash, sName→pSymbolCstr, vec_0x18→pOffset, vec_0x24→pOffsetNet, nField_0x30→nLeaderGuid, nField_0x3C→nTransform, wField_0x40→wDirtyFlags |
| DontStarveSystemService | 2 | nField_0x38→nStorageStateA, nField_0x3C→nStorageStateB |
| EnvelopeTemplate | 4 | dwField_0x00→dwVtable, dwField_0x04→dwCount, dwField_0x08→dwEntries, dwField_0x0C→dwCapacity |
| MigrationInfo | 2 | nField_0x00→nState, wField_0x08→wPort |
| cTwitchManager | 2 | bField_0x1C→bEnabled, nField_0x20→nState |
| cLightEmitterComponent | 4 | vecColour_0x10→pLightParams, nColour_0x20→nColour, nField_0x24→nFlagsEnabled, bField_0x28→bDirtyFlags |
| SimplexNoise | 2 | pUNKNOWN_0x104→pGrad3, pUNKNOWN_0x504→pGrad3B |
| GameServiceImpl | 2 | nField_0x04→nNumSimultaneousPlayers, nField_0x08→nActivePlayerCount |
| cGiftingManager | 1 | nField_0x04→nState |
| PostProcessor | 1 | UNKNOWN_0x04→pPostState |
| TDataCacheVFXParticleBufferRenderer | 1 | pUNKNOWN_0x48→pCachedState |
| TDataCacheMapComponent | 1 | pUNKNOWN_0x48→pMapCache |
| TDataCacheMiniMapRenderer | 1 | pUNKNOWN_0x48→pMiniMapCache |

## 布局差异记录(以 Ghidra 为准,头文件保留原字段分解)

1. **cMasterServer**: 头文件原为 `int32_t nField_0x80[4]`(一个 16B 数组);Ghidra 为 4 个独立 int(nField_0x80 / nField_0x84 / nField_0x88 / nProtocolFlags)。为暴露 nProtocolFlags 名,按 Ghidra 拆成 4 个 int32_t,类型/size/顺序未变。
2. **VideoNode 头部区(0x00-0xA4)**: 头文件分解与 Ghidra 不同——头文件 `base[80]` 覆盖 Ghidra 的 pVtable(0x00)+pSgnBase(0x04, 76B) 两字段;头文件 `flSize[8]`、`decoderHandles[3]` 在 Ghidra 中无对应独立字段(对应 pSizeXY/pSgnTailAndGame 区域的部分)。本次仅改 Ghidra 有对应语义的字段名(pVtable→pSizeXY、UNKNOWN_0x58→pSgnTailAndGame、name→pStrPath、ioCallbacks→pIoAndPlayback、tint→dwTint),未重排/拆分。头文件总 size 注释 0x114 与按字段求和(≈0x10D)有 7B 差,系历史近似,未在本次修正范围。
3. **TextNode 0x119/0x11A**: retype-unknown-a.md 中 bEditCursorState / bScrollEditWindow 两字段在 Ghidra 无独立字段(0x119-0x11B gap),头文件亦无,无需同步。TextNode 其余 17 字段全部对齐 Ghidra(含 bStrText@0x114、pEditCursorPos@0x11C 顺序依赖)。

## 验证

- struct 总数: 276(修改前 276,未变)
- 更新 struct: 48;更新字段: 209
- 全部 48 个 struct 布局均来自 `get_struct_layout(program=dontstarve_steam)` 实测,非推断
- 未发现头文件之外(源码)对这些字段名的引用,改名无调用方影响
