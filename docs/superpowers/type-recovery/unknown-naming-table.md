# UNKNOWN 字段命名表 (回写清单)

| struct | field | offset | new_name | confidence |
|---|---|---|---|---|
| WaveComponent | nField_0x60 | 0x60 | flTime (波浪时间累加器) | high |
| WaveComponent | pVec_0x64 | 0x64 | 拆分为 flWidth@0x64 + flHeight@0x68 + nNumWaves@0x6C | high |
| WaveComponent | nField_0x78 | 0x78 | dwWaveTextureHandle | high |
| WaveComponent | nField_0x7C | 0x7C | dwWaveEffectHandle | high |
| WaveComponent | nField_0x80 | 0x80 | dwVertexBufferHandle | high |
| WaveComponent | nField_0x84 | 0x84 | dwVertexDescHandle | high |
| WaveComponent | bField_0x88 | 0x88 | bEnabled | high |
| WaveComponent | nField_0x8C | 0x8C | pGameRenderer (GameRenderer*) | high |
| RoadManagerComponent | nField_0xD0 | 0xD0 | pGameRenderer (GameRenderer*) | high |
| RoadManagerComponent | nField_0xD4 | 0xD4 | dwVertexDescHandle | high |
| RoadManagerComponent | nField_0xD8 | 0xD8 | pQuadTreeRoot (boost::shared_ptr<QuadTreeNode<RoadTri>> 指针侧) | high |
| RoadManagerComponent | nField_0xDC | 0xDC | pSpCountedBase (shared_ptr 计数块) | high |
| cLightWatcherComponent | bField_0x10 | 0x10 | bIsInLight | high |
| cLightWatcherComponent | nField_0x14 | 0x14 | flLightAlpha (GetLightAtPoint 第 4 输出) | medium |
| cLightWatcherComponent | nField_0x18 | 0x18 | flLightValue | high |
| cLightWatcherComponent | flField_0x34 | 0x34 | flLightThresh (进入光照阈值) | high |
| cLightWatcherComponent | flField_0x38 | 0x38 | flDarkThresh (离开光照阈值) | medium |
| cLightWatcherComponent | wField_0x3C | 0x3C | bFlags (bit0 @0x3D = 阈值 dirty) | medium |
| cPController | flField_0x00 | 0x00 | flCurrent | high |
| cPController | flField_0x04 | 0x04 | flTarget | high |
| cPController | flField_0x08 | 0x08 | flRate (插值速度) | high |
| cPController | flField_0x14 | 0x14 | flDeadzone (死区阈值) | high |
| cPController | fField_0x18 | 0x18 | bClamp | high |
| MiniMapEntityComponent | nField_0x10 | 0x10 | nPriority | high |
| MiniMapEntityComponent | nField_0x14 | 0x14 | dwIconHash (cHashedString) | high |
| MiniMapEntityComponent | pSName | 0x18 | pStrName (std::string 4B) | medium |
| MiniMapEntityComponent | nField_0x1C | 0x1C | bFlags (bit0=visible?, bit2=iconDirty, bit3=priorityDirty) | medium |
| WallStencilBuffer | dwField_0x20 | 0x20 | dwDepthTextureHandle | high |
| WallStencilBuffer | dwField_0x24 | 0x24 | dwRenderTargetHandle | high |
| WallStencilBuffer | bField_0x3C | 0x3C | bRenderEnabled | high |
| cSteamPunchthroughPlugin | nField_0x88 | 0x88 | dwMinAddress (地址池下限) | high |
| cSteamPunchthroughPlugin | nField_0x8C | 0x8C | dwMaxAddress (地址池上限) | high |
| cSteamPunchthroughPlugin | nField_0x90 | 0x90 | dwNextAddress (下一个分配地址游标) | high |
| cCachedPingResults | nField_0x00 | 0x00 | pRbTreeHeader (std::map<uint,ushort> 根/头, 非 int) | medium |
| cCachedPingResults | nField_0x14 | 0x14 | nMapNodeCount (map 计数, 部分头) | medium |
| cShardNetworkComponent | nField_0x10 | 0x10 | nLastSerializedState | high |
| cShardNetworkComponent | bField_0x14 | 0x14 | nSerializeRetry (重试计数/节流) | high |
| MapRenderer | dwField_0x14 | 0x14 | dwBlendTextureHandle | high |
| MapRenderer | dwField_0x18 | 0x18 | flBlendFactor | high |
| cNetworkManager | nField_0x70 | 0x70 | nWhitelistSlots | high |
| cNetworkManager | nField_0x74 | 0x74 | nConnectionTimeoutMs | high |
| cNetworkManager | wField_0x8E | 0x8E | bPad_0x8E + bAutosaverEnabled (ushort 打包; 高字节=autosaver) | high |
| cNetworkManager | nField_0x98 | 0x98 | dwServerGameplayFlags (byte@+1=bPauseWhenEmpty; byte@+3=clan-officer 鉴权路径标志) | medium |
| cNetworkManager | nField_0xC0 | 0xC0 | dwSteamGroupIdLo (与 0xC4 组成 ullSteamGroupId) | high |
| cNetworkManager | nField_0xC4 | 0xC4 | dwSteamGroupIdHi | high |
| cNetworkManager | nRakString | 0x100 | mRakString (内嵌 RakNet::RakString,非 int) | high |
| cNetworkManager | bField_0x108 | 0x108 | bEnableFrameDeserialize | medium |
| cNetworkManager | wField_0x118 | 0x118 | wUnassignedSystemIndex | medium |
| cNetworkManager | pStrField_0x1A0 | 0x1A0 | pStr_0x1A0 (std::string; 语义 UNKNOWN 保持) | medium |
| cNetworkManager | pStrField_0x1B0 | 0x1B0 | pStr_0x1B0 (std::string; 语义 UNKNOWN 保持) | medium |
| cNetworkManager | pStrField_0x1B4 | 0x1B4 | pStr_0x1B4 (std::string; 语义 UNKNOWN 保持) | medium |
| cNetworkManager | pStrField_0x1F8 | 0x1F8 | pStr_0x1F8 (std::string; 语义 UNKNOWN 保持) | medium |
| cNetworkManager | pUnknown2FC | 0x2FC | pVtableObject_0x2FC (虚接口指针; 精确类型 UNKNOWN 保持) | medium |
| cUITransformComponent | nField_0x4C | 0x4C | nHAnchor | medium |
| cUITransformComponent | nField_0x50 | 0x50 | nVAnchor | medium |
| cUITransformComponent | flField_0x70 | 0x70 | flScaleX | high |
| cUITransformComponent | flField_0x74 | 0x74 | flScaleY | high |
| cUITransformComponent | flField_0x78 | 0x78 | flScaleZ | high |
| cUITransformComponent | flField_0x180 | 0x180 | flMaxScale | medium |
| cSteamPunchthrough | pField_0x2C | 0x2C | pVecPendingClanGUID_begin | high |
| cSteamPunchthrough | nField_0x30 | 0x30 | pVecPendingClanGUID_end | high |
| cSteamPunchthrough | nField_0x34 | 0x34 | pVecPendingClanGUID_cap | high |
| cSteamPunchthrough | bField_0x3E | 0x3E | bGameConnectionInitiated | high |
| cSteamPunchthrough | nField_0x40 | 0x40 | dwAuthTargetIP | high |
| cSteamPunchthrough | wField_0x44 | 0x44 | wAuthTargetPort | high |
| GraphRenderer | dwField_0x10 | 0x10 | pExtraVertBuffer | medium |
| WindowManager | pField_0x04 | 0x04 | oWindowState (建议拆字段,非单 blob) | high |
| WindowManager | pField_0x7C | 0x7C | oCurrentModeFlags (12B: 8B 数据 + bFlag0=1 + bFlag1=1) | medium |
| cLuaNetworkVariable | bField_0x04 | 0x04 | bDirty | medium |
| TDataCacheParticleBufferRenderer | pUNKNOWN_0x48 | 0x48 | 应拆为粒子缓存快照字段(非单 blob) | high |
| TDataCacheVideoNode | pUNKNOWN_0x48 | 0x48 | 应拆为视频节点渲染快照 | high |
| ImageNode | pUNKNOWN_0x94 | 0x94 | 应拆为 Image 渲染状态(非单 blob) | medium |
| GameLibConfig | pField_0x00 | 0x00 | 应拆(非单 68B blob) | high |
| GameLibConfig | pStrs | 0x44 | 8×std::string (含 "DoNotStarveTogether" @ +0x14) | high |
| GameLibConfig | pNetIds | 0x64 | 尾部 cNetID2 + 标志; remaining-b: +0x8C/+0x90 清零 + oNetID2@+0x94 | high |
| TextNode | dwVertDescHandle | 0x94 | dwFontHandle | high |
| TextNode | flFontScale | 0x98 | flFontSize | high |
| TextNode | flField_0x9C | 0x9C | flLineSpacing | medium |
| TextNode | flMax_0xA0 | 0xA0 | flRegionW | high |
| TextNode | flMax_0xA4 | 0xA4 | flRegionH | high |
| TextNode | dwField_0xA8 | 0xA8 | bWordWrap | high |
| TextNode | bField_0xAC | 0xAC | bWhitespaceWrap | high |
| TextNode | dwField_0xB0 | 0xB0 | nHAnchor | high |
| TextNode | dwField_0xB4 | 0xB4 | nVAnchor | high |
| TextNode | pHandles_0xBC | 0xBC | pEditLineHandles | medium |
| TextNode | dwField_0xF4 | 0xF4 | bDepthTest | medium |
| TextNode | pVec3_0x100 | 0x100 | pOffset | UNKNOWN(低) | low |
| TextNode | bField_0x110 | 0x110 | bAutoRegion | high |
| TextNode | bField_0x114 | 0x114 | pStrText (布局错位!) | high |
| TextNode | bField_0x118 | 0x118 | bShowEditCursor | high |
| TextNode | field_0x119 | 0x119 | bEditCursorState | high |
| TextNode | field_0x11a | 0x11A | bScrollEditWindow | high |
| TextNode | pStrText | 0x11C | nEditCursorPos | high |
| TextNode | dwField_0x124 | 0x124 | dwTexHandle | high |
| DebugRenderComponent | nField_0xA4 | 0xA4 | flY | high |
| DebugRenderComponent | nField_0xAC | 0xAC | pVecStrings_begin | high |
| DebugRenderComponent | nField_0xB0 | 0xB0 | pVecStrings_end | high |
| DebugRenderComponent | nField_0xB4 | 0xB4 | pVecStrings_cap | high |
| DebugRenderComponent | nField_0xB8 | 0xB8 | pVecLines_begin | high |
| DebugRenderComponent | nField_0xBC | 0xBC | pVecLines_end | high |
| DebugRenderComponent | nField_0xC0 | 0xC0 | pVecLines_cap | high |
| DebugRenderComponent | nField_0xC4 | 0xC4 | pVecCircles_begin | high |
| DebugRenderComponent | nField_0xC8 | 0xC8 | pVecCircles_end | high |
| DebugRenderComponent | nField_0xCC | 0xCC | pVecCircles_cap | high |
| DebugRenderComponent | nField_0xD0 | 0xD0 | pVecBoxes_begin | high |
| DebugRenderComponent | nField_0xD4 | 0xD4 | pVecBoxes_end | high |
| DebugRenderComponent | nField_0xD8 | 0xD8 | pVecBoxes_cap | high |
| DebugRenderComponent | nField_0xDC | 0xDC | pVecTriangles_begin | high |
| DebugRenderComponent | nField_0xE0 | 0xE0 | pVecTriangles_end | high |
| DebugRenderComponent | nField_0xE4 | 0xE4 | pVecTriangles_cap | high |
| cSoundEmitterComponent | pVtable | 0x10 | pEvents_begin | high |
| cSoundEmitterComponent | nField_0x14 | 0x14 | pEvents_end | high |
| cSoundEmitterComponent | nField_0x18 | 0x18 | pEvents_cap | high |
| cSoundEmitterComponent | nField_0x1C | 0x1C | pVecSoundNames_begin | high |
| cSoundEmitterComponent | nField_0x20 | 0x20 | pVecSoundNames_end | high |
| cSoundEmitterComponent | nField_0x24 | 0x24 | pVecSoundNames_cap | high |
| cSoundEmitterComponent | nField_0x28 | 0x28 | pMapNamedEvents (map header base / _M_key_compare pad) | high |
| cSoundEmitterComponent | nField_0x2C | 0x2C | nMapHeader_color (map end-sentinel header) | high |
| cSoundEmitterComponent | nField_0x30 | 0x30 | pMapHeader_parent | high |
| cSoundEmitterComponent | nField_0x34 | 0x34 | pMapHeader_left | high |
| cSoundEmitterComponent | nField_0x38 | 0x38 | pMapHeader_right | high |
| cSoundEmitterComponent | nField_0x3C | 0x3C | nMapNodeCount | high |
| cSoundEmitterComponent | nField_0x40 | 0x40 | bActive (低字节; +1 另有抑制标志) | high |
| cSoundEmitterComponent | nField_0x44 | 0x44 | pVecDirtyEvents | high |
| cSoundEmitterComponent | nField_0x48 | 0x48 | pVecDirtyEventsPrev | high |
| cSoundEmitterComponent | nField_0x4C | 0x4C | flVolume | high |
| cShardManager | pField_0x00 | 0x00 | pVtable + 前置状态块 (建议拆: pVtable@0 / 若干 int / std::string@0x14 / std::string@0x24) | medium |
| cShardManager | nField_0x40 | 0x40 | nDefaultFlag (初值 1) | low |
| cShardManager | bField_0x5C | 0x5C | bIncomingMigrationActive | low |
| cShardManager | bField_0x98 | 0x98 | bFlag_0x98 | low |
| cShardManager | bField_0x99 | 0x99 | bFlag_0x99 | low |
| cAccountCommunication | bField_0x30 | 0x30 | bConnected (或 bHasNetId) | medium |
| cAccountCommunication | bField_0xC0 | 0xC0 | bBusy (或 bRequestPending) | low |
| DynamicShadowComponent | nField_0x10 | 0x10 | flSizeX | high |
| DynamicShadowComponent | nField_0x14 | 0x14 | flSizeY | high |
| DynamicShadowComponent | nField_0x18 | 0x18 | bEnabled (+0x18) / bPristine(+0x19) / bFlags(+0x1A) 打包区 | high |
| cAccountManager | bField_0x04 | 0x04 | bInitialized (或 bLoggedIn) | low |
| cAccountManager | bField_0x40 | 0x40 | bOnlineCapable (初值 1) | medium |
| MapComponent | flField_0x188 | 0x188 | flOverlayScale (初值 0.25) | medium |
| cMasterServer | nField_0x8C | 0x8C | dwProtocolFlags (初值 0x1000001) | medium |
| cMasterServer | bField_0x90 | 0x90 | bEnabled | medium |
| cSteamRichPresence | bField_0x1C | 0x1C | bDirty | medium |
| cSteamRichPresence | bField_0x52 | 0x52 | bHasConnectString | medium |
| cNetworkComponent | bField_0x170 | 0x170 | bIsSleeping (或 bLocalFlags) | low |
| BitmapFont | dwField_0x14 | 0x14 | nOutline | medium |
| ParticleEmitter | pUNKNOWN_0x04 | 0x04 | pEmitterState (混合块, 建议后续拆分) | medium |
| ParticleBuffer | wField_0x08 | 0x08 | wActiveCount | medium |
| TDataCacheImageNode | pUNKNOWN_0x48 | 0x48 | pImageCacheState | medium |
| TDataCacheTextNode | pUNKNOWN_0x48 | 0x48 | pTextCacheState | medium |
| cMasterServerRequest | bField_0x04 | 0x04 | bInFlight | medium |
| tServerListing | pStrs | 0x00 | pStrBlock (std::string[13]: name/ip/row/session/host/desc/tags/mode/data/worldgen/players/season/intent) | high |
| tServerListing | pM_mods | 0x34 | listModsInfo (std::list<tServerModInfo>) | high |
| tServerListing | wField_0x3C | 0x3C | wPort | high |
| tServerListing | wField_0x3E | 0x3E | wMaxConnections | high |
| tServerListing | wField_0x40 | 0x40 | wConnected | high |
| tServerListing | nField_0x44 | 0x44 | nPing | high |
| tServerListing | nField_0x48 | 0x48 | nVersion | high |
| tServerListing | nField_0x4C | 0x4C | nSteamRoomLo | high |
| tServerListing | nField_0x50 | 0x50 | nSteamRoomHi | high |
| tServerListing | nField_0xAC | 0xAC | nTick | high |
| tServerListing | bField_0xB0 | 0xB0 | bDedicated | high |
| tServerListing | bField_0xB1 | 0xB1 | bClientHosted | high |
| tServerListing | nField_0xB2 | 0xB2 | flagsBoolPack (bPvp@+0, bPassword@+1, bMods@+2, bFriendsOnly@+3) | high |
| tServerListing | nField_0xF0 | 0xF0 | nNat | high |
| tServerListing | nField_0xF4 | 0xF4 | flagsPost (offline@+0, bClanOnly@+1, bLanOnly@+2) | high |
| tServerListing | pStr_0xF8 | 0xF8 | pStrModsConfigData | high |
| tServerListing | nField_0xFC | 0xFC | flagsClient (bHasDetails@0, bFriend@+1, bFriendPlaying@+2, bModsFailedDeser@+3) | high |
| tServerListing | bField_0x100 | 0x100 | bOffline | medium |
| VideoNode | pBase_0x04 | 0x04 | sgnBase (SceneGraphNode body after vtable) | high |
| VideoNode | pSize | 0x50 | flSizeXY | medium |
| VideoNode | pUNKNOWN_0x58 | 0x58 | pSgnTailAndGame | medium |
| VideoNode | dwField_0xA0 | 0xA0 | flWidth | high |
| VideoNode | dwField_0xA4 | 0xA4 | flHeight | high |
| VideoNode | dwTint | 0xB0 | dwTint (already named) | high |
| VideoNode | dwField_0xB4 | 0xB4 | nPlayState | high |
| VideoNode | pName | 0xB8 | pStrPath (already named) | high |
| VideoNode | timer | 0xC0 | timer (already named) | high |
| VideoNode | pIoCallbacks | 0xC8 | ioAndPlayback (IoFopen @+0x10, elapsed/frameMs, framebufs @+0x40) | high |
| VideoNode | dwField_0xEC | 0xEC | dwTexY | high |
| VideoNode | dwField_0xF0 | 0xF0 | dwTexU | high |
| VideoNode | dwField_0xF4 | 0xF4 | dwTexV | high |
| VideoNode | bField_0xF8 | 0xF8 | bLoopOrFlag | medium |
| VideoNode | dwField_0x108 | 0x108 | pFrameBuf0 | high |
| VideoNode | dwField_0x10C | 0x10C | pFrameBuf1 | high |
| VideoNode | dwField_0x110 | 0x110 | nFrameBufIndex | high |
| ControlMapper | wField | 0x04 | wIsMapping | high |
| ControlMapper | pGlobal | 0x08 | nMappingDeviceId | high |
| ControlMapper | nField_0x10 | 0x10 | nControlType | high |
| ControlMapper | pMappingStorage2 | 0x14 | mappingScratch | medium |
| ControlMapper | nField_0x24 | 0x24 | nLastInputId | high |
| ControlMapper | bField_0x28 | 0x28 | bMappingChanged | high |
| ControlMapper | nField_0x34 | 0x34 | nCallbackUser | medium |
| ControlMapper | nField_0x38 | 0x38 | pInputMappings | high |
| ControlMapper | nField_0x3C | 0x3C | pDeviceDirtyFlags | high |
| ControlMapper | nField_0x40 | 0x40 | nNumDevices | high |
| ControlMapper | pUNKNOWN_0x44 | 0x44 | pMappingTableBlob | medium |
| FollowerComponent | nField_0x10 | 0x10 | nSymbolHash | high |
| FollowerComponent | pSName | 0x14 | pSymbolCstr | high |
| FollowerComponent | pVec_0x18 | 0x18 | flOffset | high |
| FollowerComponent | pVec_0x24 | 0x24 | flOffsetNet | high |
| FollowerComponent | nField_0x30 | 0x30 | nLeaderGuid | high |
| FollowerComponent | nField_0x3C | 0x3C | pTransform | high |
| FollowerComponent | wField_0x40 | 0x40 | wDirtyFlags | high |
| DontStarveSystemService | pCacheMap | 0x0C | pCacheMap (already named) | high |
| DontStarveSystemService | nField_0x38 | 0x38 | nStorageStateA | medium |
| DontStarveSystemService | nField_0x3C | 0x3C | nStorageStateB | medium |
| EnvelopeTemplate | dwField_0x00 | 0x00 | pVtable | high |
| EnvelopeTemplate | dwField_0x04 | 0x04 | nCount | high |
| EnvelopeTemplate | dwField_0x08 | 0x08 | pEntries | high |
| EnvelopeTemplate | dwField_0x0C | 0x0C | nCapacity | high |
| MigrationInfo | nField_0x00 | 0x00 | nState | medium |
| MigrationInfo | wField_0x08 | 0x08 | wPort | medium |
| cTwitchManager | bField_0x1C | 0x1C | bEnabled | medium |
| cTwitchManager | nField_0x20 | 0x20 | nState | medium |
| cLightEmitterComponent | pVecColour_0x10 | 0x10 | flLightParams (derivedRadius, falloff, intensity, controlRadius) | high |
| cLightEmitterComponent | nColour_0x20 | 0x20 | dwColour | high |
| cLightEmitterComponent | nField_0x24 | 0x24 | flagsEnabled (bEnabled@0, flags@1..2, bPristine@3); ctor 0x101 | high |
| cLightEmitterComponent | bField_0x28 | 0x28 | bDirtyFlags | high |
| SimplexNoise | pUNKNOWN_0x104 | 0x104 | pGrad3 | high |
| SimplexNoise | pUNKNOWN_0x504 | 0x504 | pGrad3B | high |
| GameServiceImpl | nField_0x04 | 0x04 | nNumSimultaneousPlayers | high |
| GameServiceImpl | nField_0x08 | 0x08 | nActivePlayerCount | medium |
| cGiftingManager | nField_0x04 | 0x04 | nState | medium |
| PostProcessor | pUNKNOWN_0x04 | 0x04 | postState (pRenderer@+0, vertDesc/VB, bloom/RT, blurh/blurv/combine/postprocess effects, colour-cubes, event dispatcher@+0x7c) | high |
| TDataCacheVFXParticleBufferRenderer | pUNKNOWN_0x48 | 0x48 | pCachedState | medium |
| TDataCacheMapComponent | pUNKNOWN_0x48 | 0x48 | pMapCache | high |
| TDataCacheMiniMapRenderer | pUNKNOWN_0x48 | 0x48 | pMiniMapCache | medium |
