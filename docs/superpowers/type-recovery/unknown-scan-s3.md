# UNKNOWN 字段扫描 — Slice3

- 程序: `dontstarve_steam` (macOS i386, base 0x1000)
- 日期: 2026-08-10
- 方法: 只读 ghidra-mcp (get_struct_layout / search_functions / decompile_function)；ctor + 使用方反编译
- **禁止写 Ghidra**（仅建议命名）
- 命名: p/n/b/dw/fl/w 前缀
- (scout 沙箱 EPERM, 主 agent 物化)

---

## TextNode (356B) — 18 字段深入
ctor 0xc6626

### TextNode.dwVertDescHandle @ 0x94
semantic: dwFontHandle
evidence: SetFont@0xc696a GetRegisteredFont; assert mRenderParams.m_font; ctor=-1
confidence: high

### TextNode.flFontScale @ 0x98
semantic: flFontSize
evidence: cTextWidget::SetFontSize@0x7dd7e; ctor=10.0f
confidence: high

### TextNode.flField_0x9C @ 0x9C
semantic: flLineSpacing
evidence: ctor=1.0f; remaining-a/e 一致
confidence: medium

### TextNode.flMax_0xA0 @ 0xA0
semantic: flRegionW
evidence: GetRegionSize@0xc6c3e 返回 &flMax_0xA0; CalculateBounds; FLT_MAX
confidence: high

### TextNode.flMax_0xA4 @ 0xA4
semantic: flRegionH
evidence: GetRegionSize/HasOverflow@0xc6d1e
confidence: high

### TextNode.dwField_0xA8 @ 0xA8
semantic: bWordWrap
evidence: EnableWordWrap@0xc6b9e
confidence: high

### TextNode.bField_0xAC @ 0xAC
semantic: bWhitespaceWrap
evidence: EnableWhitespaceWrap@0xc6bae
confidence: high

### TextNode.dwField_0xB0 @ 0xB0
semantic: nHAnchor
evidence: SetHAnchor@0xc68fe; ctor=2
confidence: high

### TextNode.dwField_0xB4 @ 0xB4
semantic: nVAnchor
evidence: SetVAnchor@0xc6934; ctor=2
confidence: high

### TextNode.pHandles_0xBC @ 0xBC (56B)
semantic: pEditLineHandles
evidence: ctor -1/-1/0 循环 +0xBC..+0xF0
confidence: medium

### TextNode.dwField_0xF4 @ 0xF4
semantic: bDepthTest
evidence: ctor byte=0; cLabelComponent::OnSetEntity@0x40d98 写 +0xF4=1
confidence: medium

### TextNode.pVec3_0x100 @ 0x100
semantic: pOffset | UNKNOWN(低)
evidence: ctor Zero
confidence: low

### TextNode.bField_0x110 @ 0x110
semantic: bAutoRegion
evidence: GetRegionSize/HasOverflow 门控; ctor=1
confidence: high

### TextNode.bField_0x114 @ 0x114
semantic: pStrText (布局错位!)
evidence: SetString@0xc6ab4 assign(&bField_0x114); empty_rep. Ghidra pStrText@0x11C 错误
confidence: high

### TextNode.bField_0x118 @ 0x118
semantic: bShowEditCursor
evidence: ShowEditCursor@0xc6bca
confidence: high

### TextNode.field_0x119 @ 0x119
semantic: bEditCursorState
evidence: SetEditCursorState@0xc6bfc
confidence: high

### TextNode.field_0x11a @ 0x11A
semantic: bScrollEditWindow
evidence: EnableScrollEditWindow@0xc6c0c
confidence: high

### TextNode.pStrText @ 0x11C (布局名)
semantic: nEditCursorPos
evidence: SetEditCursorPos@0xc6b2e / SetString 写 *(uint*)pStrText
confidence: high

### TextNode.dwField_0x124 @ 0x124
semantic: dwTexHandle
evidence: SetFont square.tex; assert mTexHandle; ctor=-1
confidence: high

### TextNode.dwField_0x128/12C/148/14C/160
semantic: UNKNOWN (保持)
evidence: 已扫描无 setter
confidence: low

---

## MiniMapComponent (96B) — 14 字段深入
ctor 0x4fa9e; dtor 0x4fc06; OnInit 0x4fe70

### MiniMapComponent.nField_0x2C/30
semantic: pVecData_begin/end
evidence: dtor delete nField_0x2C
confidence: medium

### MiniMapComponent.nField_0x34
semantic: UNKNOWN (保持)
evidence: 无独立证据
confidence: low

### MiniMapComponent.nField_0x38
semantic: pMapComponent
evidence: OnInit GetComponentList<MapComponent>; +0xa5=1
confidence: high

### MiniMapComponent.nField_0x3C
semantic: pMiniMapRenderer
evidence: new(0xE4) MiniMapRenderer; GetTextureHandle@0x50080; Offset@0x500c0; dtor
confidence: high

### MiniMapComponent.nField_0x40/44/48
semantic: pVecLayerHandles_begin/end/cap
evidence: dtor Release MapLayerRenderData; BuildVBCmd/GenerateMapCmd &nField_0x40
confidence: high

### MiniMapComponent.bField_0x4C
semantic: bEnabled
evidence: ctor=1
confidence: medium

### MiniMapComponent.bField_0x4D
semantic: UNKNOWN (保持)
confidence: low

### MiniMapComponent.nField_0x50/54/58
semantic: pVecAtlases_begin/end/cap
evidence: OnInit AddAtlas 遍历; dtor free
confidence: high

### MiniMapComponent.nField_0x5C
semantic: bEnablePlayerUpdate
evidence: EnablePlayerMinimapUpdate@0x5043a; OnInit +3=1
confidence: high

---

## cNetworkClientObject2
### pUNKNOWN_0x1BC @ 0x1BC (60B)
semantic: playerListing / cPlayerListingData
evidence: ctor@0x162dea cPlayerListingData(&field_0x17c)
confidence: high
### pField_0x20C
semantic: pNetStatsPair
evidence: operator_new(8)
confidence: medium
### bField_0x204/210/211/bFlags_0x212/nField_0x213/wField_0x217/nField_0x21C
semantic: UNKNOWN (保持)
confidence: low

## CurlRequest
### dwField_0x14 → dwHttpFlags (medium)
### wField_0x18 → wRequestFlags (high) SetupCurl Content-Type
### wField_0x34 → wCurlOptBuf (medium)
### wField_0x28/bField_0x2A/dwField_0x30 → UNKNOWN (保持)

## cLoggerImplementation
### nField_0x04 → pFile (high) dtor fclose
### nField_0x48/4C → nBufPos/nBufLen (medium)
### pUNKNOWN_0x50 → pLogBuffer (medium) 4088B
### nField_0x104C → nLogFd (medium) ctor=-1

## Texture dwField_0x14..0x24 ×5 → UNKNOWN (保持) ctor 清零无语义

## PathfinderComponent nField_0x10/14/18 → pVecPending_* (medium)

## Socket nField_0x08/0x0C/pUNKNOWN_0x10 → UNKNOWN (保持)

## DontStarveInputHandler nField_0x40/nTail_* → UNKNOWN (保持)

## cInventoryManager
### nField_0x04 → bFlags 3B (medium)
### pUNKNOWN_0x48 1024B → UNKNOWN (保持) restricted-build 存储

## cNetworkRPCManager
### (unnamed)@0x04 → pBitStream (high) new BitStream 0x114
### nField_0x0C/bField_0x10 → UNKNOWN (保持)

## FileOpResult nField_0x140/144 → UNKNOWN (保持)
## SettingFile nField_0x04/08 → map头(对照 tier3-e)
## Maze.nField_0x20 → nMazeParam (medium) ctor param_4
## PerfPane.pUNKNOWN_0x2C → UNKNOWN (保持)
## HWRenderTarget.dwField_0x10 → UNKNOWN (保持)
## VFXEffectEmitter.pUNKNOWN_0x04 124B → UNKNOWN (保持)
## cLabelComponent.nField_0x10 → pTextNode (high)
## cSteamFriendsManager.bField_0x1C → UNKNOWN (保持)
## MyMotionState 全 → UNKNOWN (保持) 无符号
## TDataCacheRoadManagerNode.pUNKNOWN_0x48 → UNKNOWN (保持)
## ShaderConstantSet.dwField_0x00 → nStackTop (medium)
## ParticleBufferRenderer.dwField_0x9C → dwSortKey (medium) from GameRenderer+0x7d8
## cDedicatedServerProcess.nField_0x20 → UNKNOWN; fField_0x24 → bTerminated (medium)

---

## 汇总
**命名 N=48 / UNKNOWN 保持 M=37**

关键备注:
1. TextNode 布局错位: string@0x114 非 0x11C; 0x11C=nEditCursorPos — 回写需重建字段
2. MiniMapComponent 多 int 实为指针/vector — 应改类型
3. cNetworkClientObject2.pUNKNOWN_0x1BC → 内嵌 cPlayerListingData
4. 只读未改 Ghidra
