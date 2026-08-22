# UNKNOWN 字段扫描 — Slice1 (网络/渲染/实体组件)

- 程序: `dontstarve_steam` (macOS i386, base 0x1000)
- 日期: 2026-08-10
- 方法: 只读 ghidra-mcp (get_struct_layout / search_functions / decompile_function / get_xrefs_to / read_memory)；ctor + 使用方反编译
- **禁止写 Ghidra**（仅建议命名）
- 命名: p/n/b/dw/fl/w 前缀
- (scout 沙箱 EPERM, 主 agent 物化 — 本报告由 UnknownScan1Redo 重跑写盘)

---

## WaveComponent (144B) — 29 字段深入

ctor 0x8979c; Update 0x89e5a; DoRender 0x89e90; dtor 0x89a32
Setters: SetWaveTexture 0x8a44c / SetWaveEffect 0x8a504 / SetWaveSize 0x8a666 / SetRegionNumWaves 0x8a5de

### WaveComponent.nField_0x10..0x5C @ 0x10 (20 × float)
semantic: flPhase[20] (flWavePhases)
evidence: DoRender@0x89e90 循环 `iVar11=0..0x13` 读 `*(float *)(this + iVar11*4 + 0x10)` 作 `sinf(phase + time*const)` 波浪相位数组; ctor 全清零
confidence: high

### WaveComponent.nField_0x60 @ 0x60
semantic: flTime (波浪时间累加器)
evidence: Update@0x89e5a `if(bField_0x88) nField_0x60 = fmodf(param_1 + nField_0x60, 0x40060a92)`; DoRender 以 `*(float*)(+0x60)*const` 驱动相位
confidence: high

### WaveComponent.pVec_0x64 @ 0x64 (12B)
semantic: 拆分为 flWidth@0x64 + flHeight@0x68 + nNumWaves@0x6C
evidence: ctor 从 PTR_Zero 拷贝 8B + 清零 4B; DoRender `fVar18 = *(float*)(+0x68) / (uint)(+0x6C)`(波长 = 高度/波数)、`fVar2 = *(float*)(+0x64)`(宽度参与 ceilf 网格计数); SetRegionNumWaves@0x8a5de 写 `+0x6C = lua 整数`
confidence: high (0x6C) / medium (0x64/0x68 语义名)

### WaveComponent.nField_0x70/0x74 @ 0x70/0x74
semantic: flWaveSizeX / flWaveSizeY
evidence: SetWaveSize@0x8a666 `*(float*)(+0x74)=lua#2; *(float*)(+0x70)=lua#1`; DoRender 读 +0x70 参与波距计算
confidence: high

### WaveComponent.nField_0x78 @ 0x78
semantic: dwWaveTextureHandle
evidence: SetWaveTexture@0x8a44c 经 EffectManager 查表写 `+0x78 = 句柄`,失败置 -1 + Assert "mWaveParameters.mTexture != INVALID"; DoRender `SetTexture(renderer, 0, *(uint*)(+0x78))`
confidence: high

### WaveComponent.nField_0x7C @ 0x7C
semantic: dwWaveEffectHandle
evidence: SetWaveEffect@0x8a504 经 TextureManager 查表写 `+0x7C = 句柄`,失败置 -1 + Assert "mWaveParameters.mEffect != INVALID"; DoRender `SetEffect(renderer, *(uint*)(+0x7C))`
confidence: high

### WaveComponent.nField_0x80 @ 0x80
semantic: dwVertexBufferHandle
evidence: DoRender `SetVertexBuffer(renderer, *(uint*)(+0x80))`; dtor@0x89a32 `if(+0x80 != -1) cResourceManager<VertexBuffer>::Release(*(uint*)(+0x8C+0x194))`
confidence: high

### WaveComponent.nField_0x84 @ 0x84
semantic: dwVertexDescHandle
evidence: DoRender `SetVertexDescription(renderer, *(uint*)(+0x84))`; ctor 置 -1 哨兵
confidence: high

### WaveComponent.bField_0x88 @ 0x88
semantic: bEnabled
evidence: Update@0x89e5a 门控 `if(bField_0x88 != 0) { 累加时间 }`; ctor 置 0
confidence: high

### WaveComponent.nField_0x8C @ 0x8C
semantic: pGameRenderer (GameRenderer*)
evidence: dtor@0x89a32 以 `+0x8C` 为基址访问 `+0x194`(VertexBuffer 管理器)释放 VB; 与 cSimulation 链 `pEntity+0x40 → +0x5C → +0x30` 一致
confidence: high

---

## RoadManagerComponent (248B) — 10 字段深入

ctor 0x6c896; dtor 0x6c9a6; Update 0x6cc98; DoRender 0x6cd00; RenderRoads 0x6cdde; GenerateVB 0x6d63f; GenerateQuadTree 0x6da20; IsOnRoad 0x6d836; OnBeginRoad 0x6d1fe
RoadBuilder 内嵌 @0xA4 (44B, 已独立文档化 remaining-f2)

### RoadManagerComponent.nField_0xD0 @ 0xD0
semantic: pGameRenderer (GameRenderer*)
evidence: RenderRoads@0x6cdde `PushShaderConstantHash(this->nField_0xD0, ...)` 与 GenerateVB `Renderer::CreateVB((Renderer*)this->nField_0xD0, ...)` 将 +0xD0 当渲染器; dtor@0x6c9a6 `cResourceManager<VertexBuffer>::Release(*(uint*)(+0xD0+0x194))` + `VertexDescription::Release(*(uint*)(+0xD0+400))`
confidence: high

### RoadManagerComponent.nField_0xD4 @ 0xD4
semantic: dwVertexDescHandle
evidence: RenderRoads `SetVertexDescription(renderer, this->nField_0xD4)`; ctor 置 -1
confidence: high

### RoadManagerComponent.nField_0xD8 @ 0xD8
semantic: pQuadTreeRoot (boost::shared_ptr<QuadTreeNode<RoadTri>> 指针侧)
evidence: GenerateQuadTree@0x6da20 `boost::shared_ptr<QuadTreeNode<RoadTri>>::operator=(&this->nField_0xD8, shared_ptr)`; IsOnRoad@0x6d836 `QuadTreeNode<RoadTri>::Visit<PointInTriVisitor>(this->nField_0xD8, ...)`
confidence: high

### RoadManagerComponent.nField_0xDC @ 0xDC
semantic: pSpCountedBase (shared_ptr 计数块)
evidence: dtor@0x6c9a6 `if(this->nField_0xDC != 0) boost::detail::sp_counted_base::release()`; 与 +0xD8 组成 shared_ptr 对
confidence: high

### RoadManagerComponent.nField_0xE0/0xE4/0xE8 @ 0xE0/0xE4/0xE8
semantic: pVecRoadTri_begin / pVecRoadTri_end / pVecRoadTri_cap
evidence: GenerateQuadTree `piVar1=&this->nField_0xE0; nField_0xE4 = nField_0xE0; vector<RoadTri>::reserve(piVar1)` 后 push_back; dtor `if(+0xE0) operator_delete`; 三字段 ctor 同清零
confidence: high (begin/end) / medium (cap)

### RoadManagerComponent.nField_0xEC/0xF0/0xF4 @ 0xEC/0xF0/0xF4
semantic: pVecRoadRenderData_begin / pVecRoadRenderData_end / pVecRoadRenderData_cap
evidence: OnBeginRoad@0x6d1fe `vector<RoadRenderData>::resize(&this->nField_0xEC, ...)`; RenderRoads 以 +0xEC/+0xF0 为 [begin,end) 遍历 0xB0 步长元素; dtor 遍历释放 4×VB/元素后 `operator_delete(+0xEC)`
confidence: high (begin/end) / medium (cap)

---

## cLightWatcherComponent (62B) — 7 字段深入

ctor 0x43a2c; Update 0x43cb2; GetTimeInLight 0x43ae0; SetLightThresh 0x43aa0; LuaProxy: IsInLight 0x4417c / GetLightValue 0x4432c / GetLightAngle 0x442b4

### cLightWatcherComponent.bField_0x10 @ 0x10
semantic: bIsInLight
evidence: Update@0x43cb2 比较后写入 0/1 并 PushLuaEvent("enterlight"/"enterdark"); IsInLight Lua 读 `+0x10`; GetTimeInLight 门控
confidence: high

### cLightWatcherComponent.nField_0x14 @ 0x14
semantic: flLightAlpha (GetLightAtPoint 第 4 输出)
evidence: Update@0x43cb2 `GetLightAtPoint(sim, pos+0xe8, (float*)(+0x18), (Vector3*)(+0x28), (float*)(+0x14))` — +0x14 为 4 参输出(alpha/光强衰减); ctor 置 0
confidence: medium

### cLightWatcherComponent.nField_0x18 @ 0x18
semantic: flLightValue
evidence: GetLightValue Lua 读 `*(float*)(+0x18)`; Update 写 +0x18 并与 +0x34/+0x38 阈值比较
confidence: high

### cLightWatcherComponent.nField_0x28..0x30 @ 0x28/0x30
semantic: flLightDirX / flLightDirZ (Vector3 方向, 0x2C=Y 未用)
evidence: GetLightAngle Lua `atan2f(*(+0x30), *(+0x28))` 求光线角; Update 经 GetLightAtPoint 写方向
confidence: high

### cLightWatcherComponent.flField_0x34 @ 0x34
semantic: flLightThresh (进入光照阈值)
evidence: SetLightThresh@0x43aa0 `+0x34 = param_1` 并置 `byte(+0x3D) |= 1`; ctor 置 0.1; Update `if(!bIsInLight && lightValue < +0x34) return`
confidence: high

### cLightWatcherComponent.flField_0x38 @ 0x38
semantic: flDarkThresh (离开光照阈值)
evidence: Update@0x43cb2 `else if(+0x38 < lightValue) return` (已入光时的退出条件); ctor 置 0.05
confidence: medium

### cLightWatcherComponent.wField_0x3C @ 0x3C
semantic: bFlags (bit0 @0x3D = 阈值 dirty)
evidence: SetLightThresh `*(byte*)(&wField_0x3C+1) |= 1`; ctor 置 0
confidence: medium

---

## cPController (25B) — 6 字段深入

无 ctor/dtor (平凡); Update 0x27076; cFreeCamera 内嵌两实例间距 0x1C (remaining-f4)

### cPController.flField_0x00 @ 0x00
semantic: flCurrent
evidence: Update@0x27076 `fVar1 = flField_0x04 - flField_0x00; flField_0x00 += fVar1 * flField_0x08 * dt` (当前值向目标插值)
confidence: high

### cPController.flField_0x04 @ 0x04
semantic: flTarget
evidence: Update 读取作目标; cFreeCamera SetHeading/SetFocusPos 写
confidence: high

### cPController.flField_0x08 @ 0x08
semantic: flRate (插值速度)
evidence: Update `current += (target-current) * rate * dt`
confidence: high

### cPController.flField_0x0C/0x10 @ 0x0C/0x10
semantic: flMin / flMax (钳制范围)
evidence: Update `if(bClamp) current = clamp(current, min, max)` (fVar1 = +0x10 / +0x0C 两分支)
confidence: high

### cPController.flField_0x14 @ 0x14
semantic: flDeadzone (死区阈值)
evidence: Update `if(flField_0x14 <= |target-current|) 插值 else current = target` (死区内直接吸附)
confidence: high

### cPController.fField_0x18 @ 0x18
semantic: bClamp
evidence: Update `if(fField_0x18 != false) { 钳制 }`
confidence: high

---

## MiniMapEntityComponent (33B) — 4 字段深入

ctor 0x4f59c; SetPriority 0x4f664; SetIcon 0x4f67a; LuaProxy SetIcon 0x51266 / SetPriority 0x512ac

### MiniMapEntityComponent.nField_0x10 @ 0x10
semantic: nPriority
evidence: SetPriority@0x4f664 `if(+0x10 != v) { +0x10 = v; *(byte*)(&+0x1C+2) |= 4 }` (置 priority dirty)
confidence: high

### MiniMapEntityComponent.nField_0x14 @ 0x14
semantic: dwIconHash (cHashedString)
evidence: SetIcon@0x4f67a 比较 hash, 变更则 `cHashedString::Set(&+0x14)` 并置 dirty bit 2
confidence: high

### MiniMapEntityComponent.pSName @ 0x18
semantic: pStrName (std::string 4B)
evidence: ctor `*(undefined4*)(+0x18) = PTR_mEmptyString` (空串); 无独立语义访问点
confidence: medium (类型) / low (语义名)

### MiniMapEntityComponent.nField_0x1C @ 0x1C
semantic: bFlags (bit0=visible?, bit2=iconDirty, bit3=priorityDirty)
evidence: ctor 置 1; SetIcon/SetPriority 写 byte(+0x1E) bit2/bit3
confidence: medium

### MiniMapEntityComponent.bField_0x20 @ 0x20
semantic: UNKNOWN (保持)
evidence: ctor 置 1; 已扫 SetIcon/SetPriority/AddCachedMiniMapEntityData 无读写
confidence: low

---

## WallStencilBuffer (61B) — 4 字段深入

ctor 0xbf7c6; CreateResources 0xbfcd2; DestroyResources 0xbfe90; RenderToTexture 0xbff18; HandleEvent 0xc0254; dtor 0xbfdec

### WallStencilBuffer.dwField_0x18 @ 0x18
semantic: UNKNOWN (保持)
evidence: ctor 置 0; CreateResources/DestroyResources/RenderToTexture/dtor 均不触碰
confidence: low

### WallStencilBuffer.dwField_0x20 @ 0x20
semantic: dwDepthTextureHandle
evidence: CreateResources@0xbfcd2 `HWTexture::HWTexture(...); InitializeTexture(...); cResourceManager<Texture>::Add(renderer+0x18c)` → +0x20; ctor 置 -1; DestroyResources `Texture::Release(renderer+0x18c, +0x20)`; RenderToTexture `SetTexture(renderer, 4, +0x20)`
confidence: high

### WallStencilBuffer.dwField_0x24 @ 0x24
semantic: dwRenderTargetHandle
evidence: CreateResources `Renderer::CreateRenderTarget(renderer, +0x20, ...)` → +0x24; RenderToTexture `BeginRenderTarget(renderer, +0x24, 2)`; ctor 置 -1; dtor 释放
confidence: high

### WallStencilBuffer.bField_0x3C @ 0x3C
semantic: bRenderEnabled
evidence: RenderToTexture@0xbff18 门控 `if(bField_0x3C != 0) { 全部绘制 }`; ctor 置 0
confidence: high

---

## cSteamPunchthroughPlugin (196B) — 3 字段深入

ctor 0x1beae6; GetNextUnusedAddress 0x1bfb5a; HasSession 0x1bf0e6; 其余 5×map/2×CCallback/PluginInterface2 均已文档化 (remaining-f1 §13)

### cSteamPunchthroughPlugin.nField_0x88 @ 0x88
semantic: dwMinAddress (地址池下限)
evidence: ctor 置 1; GetNextUnusedAddress@0x1bfb5a `if(max < next) next = *(uint*)(+0x88)` 回绕下限; 与 +0x8C 构成 [min,max] 地址池
confidence: high

### cSteamPunchthroughPlugin.nField_0x8C @ 0x8C
semantic: dwMaxAddress (地址池上限)
evidence: ctor 置 -1(0xFFFFFFFF); GetNextUnusedAddress 读取 `uVar2 = *(uint*)(+0x8C)` 作容量上界与回绕判断
confidence: high

### cSteamPunchthroughPlugin.nField_0x90 @ 0x90
semantic: dwNextAddress (下一个分配地址游标)
evidence: GetNextUnusedAddress `next = *(uint*)(+0x90)+1; +0x90 = next; if(max < next) +0x90 = min; SystemAddress 用 +0x90 构造并查重`
confidence: high

---

## cCachedPingResults (44B) — 2 字段深入

ctor 0x14949c; dtor 0x149584; SaveCached 0x1495e8; 全局对象(静态初始化表 0x4f1eb4)

### cCachedPingResults.nField_0x00 @ 0x00
semantic: pRbTreeHeader (std::map<uint,ushort> 根/头, 非 int)
evidence: dtor@0x149584 `_Rb_tree<uint,pair<uint,ushort>>::_M_erase(this)` 以对象首址作树基; SaveCached `_Rb_tree::find(this)` 查 +0x00 树
confidence: medium (map 头) / 语义名 UNKNOWN

### cCachedPingResults.nField_0x14 @ 0x14
semantic: nMapNodeCount (map 计数, 部分头)
evidence: ctor 置 0; pM_cachedPings 自引用 +0xC/+0x10 = &this+4 表明 map 头跨 0x00..0x14
confidence: medium

---

## cShardNetworkComponent (21B) — 2 字段深入

ctor 0x753cc; WallUpdate 0x7550e; dtor 0x75488; SetLocalShardNetworkComponent 0x1abdd0 (存于 cShardManager+0x1C)

### cShardNetworkComponent.nField_0x10 @ 0x10
semantic: nLastSerializedState
evidence: WallUpdate@0x7550e `if(serverState==2) { v = *(sim+0x4C); if(v != +0x10) { +0x10 = v; 序列化实体并 SendLuaWorldDataPacket } }`
confidence: high

### cShardNetworkComponent.bField_0x14 @ 0x14
semantic: nSerializeRetry (重试计数/节流)
evidence: WallUpdate `if(byte(+0x14) < 2) { +0x14 = 2; 发送 } else { +0x14 -= 1 }`; ctor 置 0
confidence: high

---

## MapRenderer (28B) — 2 字段深入

ctor 0x98bfa; dtor 0x98d5c; DrawMap 0x98ee2; DrawUnderground 0x99222; PushBlendFactor 0x98e08; PopBlendFactor 0x98ec6

### MapRenderer.dwField_0x14 @ 0x14
semantic: dwBlendTextureHandle
evidence: ctor 置 -1; PushBlendFactor@0x98e08 `if(+0x14 != 0xffffffff) SetTexture(renderer, 2, +0x14); SetTextureState(renderer, 2, 0, blend)`
confidence: high

### MapRenderer.dwField_0x18 @ 0x18
semantic: flBlendFactor
evidence: ctor 置 0; PushBlendFactor 以 `(float)+0x18` 计算三组 clamped 混合因子入 shader; DrawMap `if(0.0 < (float)+0x18) 用 dwEffectHandle_2 else dwEffectHandle_1`
confidence: high

---

## cEntityManager (309B) — 1 字段深入

ctor 0xd2796; Update 0xd4382; PostUpdate 0xd3ee0; UpdateEntityManagementLists 0xd311e; DestroyEntity 0xd2ff0

### cEntityManager.nField_0xC4/0xC8/0xCC @ 0xC4/0xC8/0xCC
semantic: UNKNOWN (保持)
evidence: ctor 三字段置 0; 已扫 ctor/Update/PostUpdate/UpdateEntityManagementLists/DestroyEntity/Recycle/dtor 无读写
confidence: low

---

## cSimulation (412B) — 1 字段深入

ctor 0xf71d2 (review-slice1 已逐字段验证, 此补 UNKNOWN)

### cSimulation.nField_0x74 @ 0x74
semantic: UNKNOWN (保持)
evidence: ctor 置 -1 (哨兵); 位于 pDebugCamera@0x70 与 flElapsedUpdateTime@0x78 之间; 已扫 ctor/DoReset/CheckPointer 无语义访问
confidence: low

---

## MapComponentBase (304B) — 1 字段深入

ctor 0x46eb6 (本次未解, 依赖 audit-s2/review-slice7 布局)

### MapComponentBase.bUndergroundLayer @ 0x110
semantic: UNKNOWN (保持)
evidence: 布局 byte@0x110; pUNKNOWN_0x10 232B 为 SceneGraphNode 基区; 未获得独立读写证据
confidence: low

---

## cNetworkLuaProxy (32B) — 1 字段深入

(review-slice12 WARN: +0x08 map_like 容器语义存疑)

### cNetworkLuaProxy.nField_0x04 @ 0x04
semantic: UNKNOWN (保持)
evidence: ctor 未写; +0x08 的 20B 为 map 头初始化模式但 dtor 无 _M_erase (review-slice12); pNetworkContext@0x1C 已定
confidence: low

---

## Region (24B) — 1 字段深入

### Region.pUNKNOWN_0x04 @ 0x04 (20B)
semantic: UNKNOWN (保持)
evidence: 仅 dwHash@0x00 已知; 无 ctor 符号/使用方反编译 (本扫未定位)
confidence: low

---

## BitmapFontRenderer (96B) — 1 字段深入

ctor 0xade62

### BitmapFontRenderer.nField_0x04 @ 0x04
semantic: UNKNOWN (保持)
evidence: ctor 写 vtable@0 后直接 `WorkingVB::WorkingVB(&this->workingVB)`(+0x08), +0x04 未初始化; 其余字段(pRenderer/pFontManager/3×effect/vertDesc)已定
confidence: low

---

## cBPWorld (52B) — 1 字段深入

ctor 0xc9fb2

### cBPWorld.pUNKNOWN_0x20 @ 0x20 (12B) + field_0x2C @ 0x2C
semantic: UNKNOWN (保持)
evidence: ctor 连续清零 +0x20..+0x2F; 其余 8 Bullet 指针 + pSimulation@0x30 均已定 (audit-s5); 无独立语义证据
confidence: low

---

## cSteamAccountCommunication (284B) — 1 字段深入

ctor 0x1bbb5c (remaining-f1 §11: base + 3×CCallback + 票证缓冲)

### cSteamAccountCommunication.nField_0x118 @ 0x118
semantic: UNKNOWN (保持)
evidence: 布局 int@0x118 位于 nTicketBufferSize@0x114 之后; ctor 未置位证据; 其余字段(3×CCallback/pAuthTicketBuffer@0x10C/dwAuthTicket@0x110/nTicketBufferSize@0x114)已定
confidence: low

---

## cNetworkConnection (676B) — 1 字段深入

基类 Connection_RM3 0x2A0 (raknet-review-r1); 内联 ctor @ AllocConnection 0x189a92

### cNetworkConnection.nField_0x2A0 @ 0x2A0
semantic: UNKNOWN (保持)
evidence: 派生类唯一自有 int, 基类 ctor 不写 (raknet-review-r1: "该尾字段用途未定"); 游戏侧 +0x2A0 扩展
confidence: low

---

## TDataCacheGameRender (1264B) — 1 字段深入

### TDataCacheGameRender.pOwner @ 0x04
semantic: UNKNOWN (保持) — 布局错位
evidence: remaining-e: +0x04 实为内嵌 TDataCacheWorld(952B) 而非指针; audit-s3 判"layout mismatch 待定"; pUNKNOWN_0x48 1192B 未拆
confidence: low

---

## HWBuffer (20B) — 1 字段深入

ctor 0x1c6260 (内联于 CreateVB)

### HWBuffer.dwField_0x0C @ 0x0C
semantic: UNKNOWN (保持)
evidence: remaining-a: ctor 写 +4 stride/+8 count/+16 usage, +0x0C 未写; 无使用方证据
confidence: low

---

## TDataCacheWorld (952B) — 1 字段深入

### TDataCacheWorld.pOwner @ 0x04
semantic: UNKNOWN (保持) — 布局错位
evidence: audit-s3: TDataCacheWorld 为纯数据(无 vtable/pOwner 头); remaining-e ctor 0x180d2 无 vtable 写入; 命名与布局不符
confidence: low

---

## TDataCacheMiniMapComponent (104B) — 1 字段深入

ctor 0x50b3a; CacheForRender 0x504fc

### TDataCacheMiniMapComponent.pOwner @ 0x04
semantic: UNKNOWN (保持) — 布局错位
evidence: audit-s3: +0x98 实为 MiniMapRenderer*; pOwner@0x04 无 ctor 置位证据; pUNKNOWN_0x48 32B 未拆
confidence: low

---

## 汇总

| 类别 | 数量 |
|------|------|
| **命名建议 (semantic ≠ UNKNOWN 保持)** | **73** |
| **UNKNOWN 保持** | **19** |
| 扫描字段/分组合计 | **92** |

### 命名 73 (high/medium 明细)
1–20. WaveComponent flPhase[20] @0x10..0x5C
21. WaveComponent.flTime @0x60
22–23. WaveComponent.flWidth/flHeight @0x64/0x68
24. WaveComponent.nNumWaves @0x6C
25–26. WaveComponent.flWaveSizeX/Y @0x70/0x74
27. WaveComponent.dwWaveTextureHandle @0x78
28. WaveComponent.dwWaveEffectHandle @0x7C
29. WaveComponent.dwVertexBufferHandle @0x80
30. WaveComponent.dwVertexDescHandle @0x84
31. WaveComponent.bEnabled @0x88
32. WaveComponent.pGameRenderer @0x8C
33. RoadManagerComponent.pGameRenderer @0xD0
34. RoadManagerComponent.dwVertexDescHandle @0xD4
35. RoadManagerComponent.pQuadTreeRoot @0xD8
36. RoadManagerComponent.pSpCountedBase @0xDC
37–39. RoadManagerComponent pVecRoadTri begin/end/cap @0xE0/0xE4/0xE8
40–42. RoadManagerComponent pVecRoadRenderData begin/end/cap @0xEC/0xF0/0xF4
43. cLightWatcherComponent.bIsInLight @0x10
44. cLightWatcherComponent.flLightAlpha @0x14
45. cLightWatcherComponent.flLightValue @0x18
46–47. cLightWatcherComponent.flLightDirX/Z @0x28/0x30
48. cLightWatcherComponent.flLightThresh @0x34
49. cLightWatcherComponent.flDarkThresh @0x38
50. cLightWatcherComponent.bFlags @0x3C
51–56. cPController flCurrent/flTarget/flRate/flMin/flMax/flDeadzone @0x00..0x14
57. cPController.bClamp @0x18
58. MiniMapEntityComponent.nPriority @0x10
59. MiniMapEntityComponent.dwIconHash @0x14
60. MiniMapEntityComponent.pStrName @0x18
61. MiniMapEntityComponent.bFlags @0x1C
62–63. WallStencilBuffer dwDepthTextureHandle/dwRenderTargetHandle @0x20/0x24
64. WallStencilBuffer.bRenderEnabled @0x3C
65–67. cSteamPunchthroughPlugin dwMinAddress/dwMaxAddress/dwNextAddress @0x88/0x8C/0x90
68–69. cCachedPingResults pRbTreeHeader/nMapNodeCount @0x00/0x14
70–71. cShardNetworkComponent nLastSerializedState/nSerializeRetry @0x10/0x14
72–73. MapRenderer dwBlendTextureHandle/flBlendFactor @0x14/0x18

### UNKNOWN 保持 19
cEntityManager 0xC4/C8/CC (3); cSimulation 0x74; MapComponentBase 0x110; cNetworkLuaProxy 0x04; Region 0x04(20B); BitmapFontRenderer 0x04; cBPWorld 0x20(12B)+0x2C; cSteamAccountCommunication 0x118; cNetworkConnection 0x2A0; TDataCacheGameRender.pOwner; HWBuffer 0x0C; TDataCacheWorld.pOwner; TDataCacheMiniMapComponent.pOwner; MiniMapEntityComponent.bField_0x20; WallStencilBuffer.dwField_0x18

### 报告路径
`docs/superpowers/type-recovery/unknown-scan-s1.md`
