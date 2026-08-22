# Unknown Field Scan — Slice2

> program: `dontstarve_steam` (macOS i386)
> method: read-only ghidra-mcp (get_struct_layout + search_functions + decompile_function)
> priority: UNKNOWN_0x* first; cNetworkManager deep-dive (ctor @0x165992)
> date: 2026-08-10
> agent: UnknownScan2

---

## cNetworkManager (5048B) — priority deep dive

Ctor: `cNetworkManager::cNetworkManager` @ **0x165992**
Users: `LoadSettings` @ **0x166a6a**, `SetTickRate` @ **0x1668d4**, dtor @ **0x167598**, `cSteamPunchthrough::ReceiveAuthenticationBlob` @ **0x1bdec0**

### cNetworkManager.bField_0x3C @ 0x3C
semantic: UNKNOWN (保持)
evidence: ctor@0x165992 置 0; LoadSettings/dtor 无读写语义证据
confidence: low

### cNetworkManager.nField_0x70 @ 0x70
semantic: nWhitelistSlots
evidence: LoadSettings@0x166a6a `SettingFile::Get(...,"whitelist_slots")` → atoi → `this->nField_0x70`; ctor 置 0
confidence: high

### cNetworkManager.nField_0x74 @ 0x74
semantic: nConnectionTimeoutMs
evidence: ctor@0x165992 置 `0x1f40`(8000); LoadSettings@0x166a6a `Get(...,"connection_timeout")` → atoi → `this->nField_0x74`
confidence: high

### cNetworkManager.wField_0x8E @ 0x8E
semantic: bPad_0x8E + bAutosaverEnabled (ushort 打包; 高字节=autosaver)
evidence: ctor 置 `0x100`(LE: lo=0,hi=1); LoadSettings `*(bool*)((int)&this->wField_0x8E+1)=strcasecmp(autosaver_enabled,"true")==0`
confidence: high

### cNetworkManager.nField_0x98 @ 0x98
semantic: dwServerGameplayFlags (byte@+1=bPauseWhenEmpty; byte@+3=clan-officer 鉴权路径标志)
evidence: ctor 置 0; LoadSettings 写 `*(bool*)((int)&this->nField_0x98+1)=pause_when_empty`; ReceiveAuthenticationBlob@0x1bdec0 读 `*(char*)((int)&pcVar8->nField_0x98+3)` 控制 clan officer 列表请求
confidence: medium

### cNetworkManager.nField_0xC0 @ 0xC0
semantic: dwSteamGroupIdLo (与 0xC4 组成 ullSteamGroupId)
evidence: ReceiveAuthenticationBlob@0x1bdec0 将 `nField_0xC0/nField_0xC4` 作为 64-bit 传入 `SteamFriends` vtable+0x98 (clan/group 查询); LoadSettings 经 `steam_group_id` → SetDefaultClanInfo
confidence: high

### cNetworkManager.nField_0xC4 @ 0xC4
semantic: dwSteamGroupIdHi
evidence: 同上,与 0xC0 组成 uint64 steam group id
confidence: high

### cNetworkManager.bField_0xC8 @ 0xC8
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 已扫 LoadSettings/SetTickRate/dtor 无进一步读写
confidence: low

### cNetworkManager.nField_0xF4 @ 0xF4
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 已扫代表函数无读写
confidence: low

### cNetworkManager.nRakString @ 0x100
semantic: mRakString (内嵌 RakNet::RakString,非 int)
evidence: ctor `RakNet::RakString::RakString((RakString*)&this->nRakString)`; dtor `~RakString`
confidence: high

### cNetworkManager.bField_0x108 @ 0x108
semantic: bEnableFrameDeserialize
evidence: SetTickRate@0x1668d4: `if (this->bField_0x108==0)` 则 frame deserialize interval 全 0,否则按 tick 与 simulation 浮点比较后设置 `SetFrameDeserializeInterval`
confidence: medium

### cNetworkManager.wField_0x118 @ 0x118
semantic: wUnassignedSystemIndex
evidence: ctor 置 `0xffff`(=UNASSIGNED_SYSTEM_INDEX 惯用哨兵); 已扫无其它写
confidence: medium

### cNetworkManager.bField_0x19C @ 0x19C
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 已扫无证据
confidence: low

### cNetworkManager.bField_0x19D @ 0x19D
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 已扫无证据
confidence: low

### cNetworkManager.pStrField_0x1A0 @ 0x1A0
semantic: pStr_0x1A0 (std::string; 语义 UNKNOWN 保持)
evidence: ctor 置 empty_rep; dtor@0x167598 `string::_Rep::_M_destroy`; 无 assign 点命名线索
confidence: medium (类型) / low (语义名)

### cNetworkManager.pStrField_0x1B0 @ 0x1B0
semantic: pStr_0x1B0 (std::string; 语义 UNKNOWN 保持)
evidence: ctor `string::string(...,"")`; dtor 销毁; 无语义访问点
confidence: medium (类型) / low (语义名)

### cNetworkManager.pStrField_0x1B4 @ 0x1B4
semantic: pStr_0x1B4 (std::string; 语义 UNKNOWN 保持)
evidence: 同上
confidence: medium (类型) / low (语义名)

### cNetworkManager.bField_0x1EC @ 0x1EC
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 已扫无证据
confidence: low

### cNetworkManager.pStrField_0x1F8 @ 0x1F8
semantic: pStr_0x1F8 (std::string; 语义 UNKNOWN 保持)
evidence: ctor empty_rep; dtor 销毁; 无语义访问点
confidence: medium (类型) / low (语义名)

### cNetworkManager.nField_0x2F8 @ 0x2F8
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 已扫无证据
confidence: low

### cNetworkManager.pUnknown2FC @ 0x2FC
semantic: pVtableObject_0x2FC (虚接口指针; 精确类型 UNKNOWN 保持)
evidence: ctor 后若非空调 `(*vtbl+0x10)(obj)`; dtor 调 `(*vtbl+4)` 虚删; 分配点未在本扫定位
confidence: medium (vtable 对象) / low (具体类型名)

### cNetworkManager.bField_0x135C @ 0x135C
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 已扫无证据
confidence: low

### cNetworkManager.bField_0x135D @ 0x135D
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 已扫无证据
confidence: low

### cNetworkManager.nField_0x1360 @ 0x1360
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 已扫无证据
confidence: low

---

## cUITransformComponent (388B)

Ctor: `cUITransformComponent::cUITransformComponent` @ **0x83b3e** / **0x83c3a**

### cUITransformComponent.nField_0x4C @ 0x4C
semantic: nHAnchor
evidence: ctor 置 3 (UI 锚点枚举常见 Center=3); 与 nField_0x50 成对
confidence: medium

### cUITransformComponent.nField_0x50 @ 0x50
semantic: nVAnchor
evidence: ctor 置 3; 与 0x4C 成对
confidence: medium

### cUITransformComponent.nField_0x54 @ 0x54
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 无使用方反编译
confidence: low

### cUITransformComponent.nField_0x58 @ 0x58
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 与 0x5C/0x60/0x64 成组但无读写证实,不命名
confidence: low

### cUITransformComponent.nField_0x5C @ 0x5C
semantic: UNKNOWN (保持)
evidence: ctor 置 0
confidence: low

### cUITransformComponent.nField_0x60 @ 0x60
semantic: UNKNOWN (保持)
evidence: ctor 置 0
confidence: low

### cUITransformComponent.nField_0x64 @ 0x64
semantic: UNKNOWN (保持)
evidence: ctor 置 0
confidence: low

### cUITransformComponent.nField_0x68 @ 0x68
semantic: UNKNOWN (保持)
evidence: ctor 置 0
confidence: low

### cUITransformComponent.nField_0x6C @ 0x6C
semantic: UNKNOWN (保持)
evidence: ctor 置 0
confidence: low

### cUITransformComponent.flField_0x70 @ 0x70
semantic: flScaleX
evidence: ctor 置 1.0; 与 flField_0x74/0x78 三轴缩放
confidence: high

### cUITransformComponent.flField_0x74 @ 0x74
semantic: flScaleY
evidence: ctor 置 1.0
confidence: high

### cUITransformComponent.flField_0x78 @ 0x78
semantic: flScaleZ
evidence: ctor 置 1.0
confidence: high

### cUITransformComponent.nField_0x7C @ 0x7C
semantic: UNKNOWN (保持)
evidence: ctor 置 0
confidence: low

### cUITransformComponent.pUNKNOWN_0x80 @ 0x80
semantic: UNKNOWN (保持) — 256B 缓冲,ctor 不初始化
evidence: ctor@0x83b3e 完全不写 0x80..0x17F; 无代表使用方反编译(方法符号未 demangle 到命名空间)
confidence: low

### cUITransformComponent.flField_0x180 @ 0x180
semantic: flMaxScale
evidence: ctor 置 3.0; 尾部独立 float
confidence: medium

---

## FileHandle (344B, KleiFile::FileHandle)

Ctor: **0x26a436**; Initialize **0x26a5f2**; Free **0x26a6d2**; GetSize **0x26d938**

### FileHandle.nField_0x118 @ 0x118
semantic: UNKNOWN (保持)
evidence: ctor 置 0; Initialize/Free/GetSize 均不读写 0x118; 已扫描无证据
confidence: low

### FileHandle.nField_0x128 @ 0x128
semantic: UNKNOWN (保持)
evidence: ctor/Free 清零; 无语义访问
confidence: low

### FileHandle.nField_0x12C @ 0x12C
semantic: UNKNOWN (保持)
evidence: ctor/Free 清零; 无语义访问
confidence: low

### FileHandle.nField_0x130 @ 0x130
semantic: UNKNOWN (保持)
evidence: ctor/Free 清零; 无语义访问
confidence: low

### FileHandle.nField_0x134 @ 0x134
semantic: UNKNOWN (保持)
evidence: ctor/Free 清零; 无语义访问
confidence: low

### FileHandle.nField_0x144 @ 0x144
semantic: UNKNOWN (保持)
evidence: Free 清零; 无语义访问
confidence: low

### FileHandle.nField_0x148 @ 0x148
semantic: UNKNOWN (保持)
evidence: Free 清零
confidence: low

### FileHandle.nField_0x14C @ 0x14C
semantic: UNKNOWN (保持)
evidence: Free 清零
confidence: low

---

## cSteamPunchthrough (70B)

Ctor: **0x1bdafa**; OnStart **0x1bdcca**; SendAuthenticationBlob **0x1be488**; ReceiveAuthenticationBlob **0x1bdec0**; GetSteamGameServer **0x1bde26**

### cSteamPunchthrough.pField_0x2C @ 0x2C
semantic: pVecPendingClanGUID_begin
evidence: ReceiveAuthenticationBlob@0x1bdec0 `std::vector<RakNet::RakNetGUID>::push_back(param_1+0x2c)`; 与 0x30/0x34 构成 vector 三件套
confidence: high

### cSteamPunchthrough.nField_0x30 @ 0x30
semantic: pVecPendingClanGUID_end
evidence: 同上 vector 布局; ctor 三字段同清零
confidence: high

### cSteamPunchthrough.nField_0x34 @ 0x34
semantic: pVecPendingClanGUID_cap
evidence: 同上
confidence: high

### cSteamPunchthrough.bField_0x3E @ 0x3E
semantic: bGameConnectionInitiated
evidence: SendAuthenticationBlob@0x1be488 在 `InitiateGameConnection` 成功后 `this->bField_0x3E=1`
confidence: high

### cSteamPunchthrough.nField_0x40 @ 0x40
semantic: dwAuthTargetIP
evidence: SendAuthenticationBlob `this->nField_0x40 = SystemAddress::IPToUInt(...)`; 随后传入 SteamUser InitiateGameConnection
confidence: high

### cSteamPunchthrough.wField_0x44 @ 0x44
semantic: wAuthTargetPort
evidence: SendAuthenticationBlob `this->wField_0x44 = SystemAddress::GetPort(...)`
confidence: high

---

## GraphRenderer (88B)

Ctor: **0xb0d76**; dtor **0xb1042**

### GraphRenderer.dwField_0x10 @ 0x10
semantic: pExtraVertBuffer
evidence: ctor 置 0; dtor `if ((void*)dwField_0x10) operator_delete`; 独立于 pVecTriangles 的堆缓冲
confidence: medium

### GraphRenderer.dwField_0x14 @ 0x14
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 与 0x10 成组但无 dtor/使用证实命名
confidence: low

### GraphRenderer.dwField_0x18 @ 0x18
semantic: UNKNOWN (保持)
evidence: ctor 置 0
confidence: low

### GraphRenderer.dwField_0x34 @ 0x34
semantic: UNKNOWN (保持)
evidence: ctor 置 0; dtor 不释放; 已扫无证据
confidence: low

### GraphRenderer.dwField_0x38 @ 0x38
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 已扫无证据
confidence: low

---

## ShadowManagerComponent (32B)

Ctor: **0x70df6**

### ShadowManagerComponent.nField_0x10 @ 0x10
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 无使用方反编译
confidence: low

### ShadowManagerComponent.nField_0x14 @ 0x14
semantic: UNKNOWN (保持)
evidence: ctor 置 0
confidence: low

### ShadowManagerComponent.nField_0x18 @ 0x18
semantic: UNKNOWN (保持)
evidence: ctor 置 -1; 常见 invalid handle 模式,但无读写点
confidence: low

### ShadowManagerComponent.nField_0x1C @ 0x1C
semantic: UNKNOWN (保持)
evidence: ctor 置 -1; 同上
confidence: low

---

## TwitchAuthThread (193B)

Ctor: **0xb85c4** (`cTwitchManager::tCheshireCat::TwitchAuthThread`)

### TwitchAuthThread.nField_0x78 @ 0x78
semantic: UNKNOWN (保持)
evidence: ctor 置 0; Thread 派生增量首字段; 无后续读写
confidence: low

### TwitchAuthThread.nField_0x7C @ 0x7C
semantic: UNKNOWN (保持)
evidence: ctor 置 0
confidence: low

### TwitchAuthThread.nField_0x80 @ 0x80
semantic: UNKNOWN (保持)
evidence: ctor 置 0
confidence: low

### TwitchAuthThread.nField_0x98 @ 0x98
semantic: UNKNOWN (保持)
evidence: 布局洞(0x84..0x94 五 string 后); ctor **未写** 0x98; remaining-d 亦标 UNKNOWN
confidence: low

---

## cNetworkReplica (354B)

无独立 ctor; 子类 `cNetworkTileRegion` @ **0x18bb16** 内联初始化

### cNetworkReplica.nField_0x158 @ 0x158
semantic: UNKNOWN (保持)
evidence: 子类 ctor 置 0; 无语义使用点(仅清零)
confidence: low

### cNetworkReplica.nField_0x15C @ 0x15C
semantic: UNKNOWN (保持)
evidence: 子类 ctor 置 0
confidence: low

### cNetworkReplica.bField_0x160 @ 0x160
semantic: UNKNOWN (保持)
evidence: 子类 ctor 置 0; 与 bRegistered@0x161 相邻但无读写语义
confidence: low

---

## DontStarveGameService (36B)

Ctor: **0x1a3b2**

### DontStarveGameService.nField_0x08 @ 0x08
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 已扫无证据
confidence: low

### DontStarveGameService.nField_0x0C @ 0x0C
semantic: UNKNOWN (保持)
evidence: ctor 置 0; pM_achievements 为后续 map 头
confidence: low

---

## cMasterServerBroadcast (88B)

Ctor: **0x15ee66**

### cMasterServerBroadcast.bField_0x00 @ 0x00
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 无启用/状态读写点,不猜测 bEnabled
confidence: low

### cMasterServerBroadcast.nField_0x08 @ 0x08
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 夹在两个 string 之间; 无使用证据
confidence: low

---

## WindowManager (136B)

Ctor: **0x1d0662** (Renderer*, cEventDispatcher*)

### WindowManager.pField_0x04 @ 0x04
semantic: oWindowState (建议拆字段,非单 blob)
evidence: ctor 初始化 map 头、`Mutex::Mutex(pField_0x04+0x18)`、`*(+0x58)=Renderer*`、`*(+0x64)=dispatcher`、`vector::resize(+0x68/+0x74, numDisplays)`; remaining-f3-ui 分解一致
  - +0x00 map<Resolution,...> 头
  - +0x18 Mutex
  - +0x50 nField 清零
  - +0x58 pRenderer
  - +0x5C pSDLWindow
  - +0x60 pGLContext
  - +0x64 pSysEventDispatcher
  - +0x68 vec<vec<Resolution>> per-display modes
  - +0x74 vec<map<Resolution,vec<int>>> refresh rates
confidence: high

### WindowManager.pField_0x7C @ 0x7C
semantic: oCurrentModeFlags (12B: 8B 数据 + bFlag0=1 + bFlag1=1)
evidence: ctor 清 0..7, `[8]=1,[9]=1`; 紧随 display 枚举之后
confidence: medium

---

## cEntity (252B)

本扫未定位 cEntity 独立 ctor 符号; 以下字段已扫描无访问证据 → 全保持。

### cEntity.bUnknown_0x59 @ 0x59
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### cEntity.pField_0xa8 @ 0xa8
semantic: UNKNOWN (保持)
evidence: audit-s2 亦跳过; 无 ctor/使用反编译
confidence: low

### cEntity.bUnknown_0xc9 @ 0xc9
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### cEntity.bUnknown_0xca @ 0xca
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### cEntity.bUnknown_0xcb @ 0xcb
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### cEntity.bUnknown_0xcc @ 0xcc
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### cEntity.bUnknown_0xcf @ 0xcf
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### cEntity.dwField_0xe4 @ 0xe4
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### cEntity.dwField_0xf8 @ 0xf8
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

---

## cGame (304B)

本扫未定位 cGame 独立 ctor 符号。

### cGame.pField_0x5C @ 0x5C
semantic: UNKNOWN (保持)
evidence: audit-s2 跳过; 夹在 MOTDImageLoader 与 GameEventDispatcher 之间
confidence: low

### cGame.pStrUnknown68 @ 0x68
semantic: UNKNOWN (保持)
evidence: 命名暗示 string; 无反编译证实
confidence: low

### cGame.bField_0x6E @ 0x6E
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### cGame.nField_0x78 @ 0x78
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### cGame.nField_0x90 @ 0x90
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

### cGame.nField_0xD4 @ 0xD4
semantic: UNKNOWN (保持)
evidence: 已扫描无证据
confidence: low

---

## MapGenSim (92B)

Ctor: **0x4ac0c**

### MapGenSim.nField_0x14 @ 0x14
semantic: UNKNOWN (保持)
evidence: ctor **未写** 0x14; 仅清 coll/vec; 已扫描无证据
confidence: low

---

## Thread (248B)

### Thread.pUNKNOWN_0x78 @ 0x78
semantic: UNKNOWN (保持) — 实为派生类扩展区(TwitchAuthThread 在 0x78 起写自有字段)
evidence: TwitchAuthThread ctor 在 `this+0x78` 起初始化; Thread 有效基类区约 0x78; 128B blob 不应属基类语义
confidence: medium (结构问题) / 字段名保持 UNKNOWN

---

## AtlasManager (64B)

Ctor: **0xa6fbc**

### AtlasManager.nField_0x04 @ 0x04
semantic: UNKNOWN (保持)
evidence: ctor 不显式写 0x04(资源 vector 从 0x08 起); 已扫描无证据
confidence: low

---

## VFXEffect (28B)

Ctor: **0x85d1c**

### VFXEffect.pUNKNOWN_0x04 @ 0x04
semantic: UNKNOWN (保持)
evidence: ctor 先 `cEntityComponent(this)` 再写 vtable,仅清绝对 0x10..0x17; 24B blob 无细分证据
confidence: low

---

## cSoundSystem (56B)

Ctor: **0x124a1c**

### cSoundSystem.bField_0x34 @ 0x34
semantic: UNKNOWN (保持)
evidence: ctor 置 0; 双 map 之后单字节标志,无读写证实
confidence: low

---

## cLuaNetworkVariable (16B)

Ctor: **0xe3520**

### cLuaNetworkVariable.bField_0x04 @ 0x04
semantic: bDirty
evidence: ctor 置 0; 网络变量脏标记惯用位置(vtable 后首字节); 无反证
confidence: medium

---

## cNetworkTileRegion (388B)

Ctor: **0x18bb16**

### cNetworkTileRegion.nField_0x180 @ 0x180
semantic: UNKNOWN (保持)
evidence: ctor 置 0; remaining-f1 亦无语义
confidence: low

---

## TDataCacheParticleBufferRenderer (108B)

Ctor: **0x60774**

### TDataCacheParticleBufferRenderer.pUNKNOWN_0x48 @ 0x48
semantic: 应拆为粒子缓存快照字段(非单 blob)
- +0x00 pParticleSysA (`*(owner+0x94)`)
- +0x04 pParticleSysB (`*(owner+0x98)`)
- +0x08 nField_owner9C
- +0x0C nParticleCount (ushort 零扩展自 sys+8)
- +0x10 pColors (count×4, CacheRenderAllocate)
- +0x14 pField2 (count×4)
- +0x18 pPositions (count×12)
- +0x1C pUVs (count×8)
- +0x20 pSizes (count×4)
evidence: ctor@0x60774 从 ParticleBufferRenderer 拷贝并按 count 分配/memcpy 五块缓冲
confidence: high

---

## TDataCacheVideoNode (124B)

Ctor: **0xc9df2**

### TDataCacheVideoNode.pUNKNOWN_0x48 @ 0x48
semantic: 应拆为视频节点渲染快照
- +0x00 / +0x04 自 owner+0xA8/0xAC
- +0x08 qword 自 owner+0xA0
- +0x10 自 owner+0x94
- +0x14 自 owner+0xB0
- +0x18 / +0x1C 自 owner+0xD0/0xD4
- +0x24 / +0x28 / +0x2C 自 owner+0xEC/0xF0/0xF4
- +0x30 bVisibleOrPlaying (`owner[0xF8]!=0 || owner+0xB4==1`)
evidence: ctor@0xc9df2 逐字段从 VideoNode 拷贝
confidence: high (布局) / medium (具体名依赖 VideoNode 字段表)

---

## ImageNode (260B)

Ctor: **0xc3416**

### ImageNode.pUNKNOWN_0x94 @ 0x94
semantic: 应拆为 Image 渲染状态(非单 blob)
- +0x00..+0x07 0xFF 填充
- +0x0C eMode=3
- +0x10 / +0x14 / +0x18 自 GameRenderer 资源句柄 (`*(game+0x30)+0x7bc` → +8/+0xC/+0x18)
- +0x1C Vector2 Zero
- +0x2C Colour = White
- +0x30..+0x3B float 1.0 ×3
- +0x3C Vector3 Zero
- +0x48 / +0x4C float 0 / 1.0
- +0x50 Quaternion/矩阵片段 Zero
- +0x60 / +0x61 标志字节
- +0x64 Vector3 Zero
evidence: ctor@0xc3416 大量立即数与 White/Zero 全局
confidence: medium

---

## GameLibConfig (148B)

Ctor: **0x19fcc** (对照 remaining-b-input §GameLibConfig)

### GameLibConfig.pField_0x00 @ 0x00
semantic: 应拆(非单 68B blob)
- +0x00 标志区
- +0x04 nMaxPlayers = 10
- +0x08..0x10 清零 int×3
- +0x14 oNetID1 (cNetID2::Clear, 44B)
- +0x40 oProcessId (ProcessId::ProcessId)
evidence: ctor@0x19fcc 逐字段; remaining-b 完整表
confidence: high

### GameLibConfig.pStrs @ 0x44
semantic: 8×std::string (含 "DoNotStarveTogether" @ +0x14)
evidence: ctor 8 次 string::string
confidence: high

### GameLibConfig.pNetIds @ 0x64
semantic: 尾部 cNetID2 + 标志; remaining-b: +0x8C/+0x90 清零 + oNetID2@+0x94
evidence: ctor Clear 第二份 cNetID2
confidence: high

---

## 汇总

| 类别 | 数量 |
|------|------|
| **命名建议 (semantic ≠ UNKNOWN 保持)** | **36** |
| **UNKNOWN 保持** | **64** |
| 扫描字段合计 | 100 |

### 命名 36 (high/medium)
1. cNetworkManager.nWhitelistSlots @0x70
2. cNetworkManager.nConnectionTimeoutMs @0x74
3. cNetworkManager.bAutosaverEnabled (wField_0x8E 高字节) @0x8F
4. cNetworkManager.dwServerGameplayFlags @0x98
5. cNetworkManager.dwSteamGroupIdLo @0xC0
6. cNetworkManager.dwSteamGroupIdHi @0xC4
7. cNetworkManager.mRakString @0x100
8. cNetworkManager.bEnableFrameDeserialize @0x108
9. cNetworkManager.wUnassignedSystemIndex @0x118
10–12. cSteamPunchthrough pVecPendingClanGUID begin/end/cap @0x2C/0x30/0x34
13. cSteamPunchthrough.bGameConnectionInitiated @0x3E
14. cSteamPunchthrough.dwAuthTargetIP @0x40
15. cSteamPunchthrough.wAuthTargetPort @0x44
16–18. cUITransformComponent.flScaleX/Y/Z @0x70/0x74/0x78
19–20. cUITransformComponent.nHAnchor/nVAnchor @0x4C/0x50
21. cUITransformComponent.flMaxScale @0x180
22. GraphRenderer.pExtraVertBuffer @0x10
23. cLuaNetworkVariable.bDirty @0x04
24. WindowManager.oWindowState 拆分 @0x04
25. WindowManager.oCurrentModeFlags @0x7C
26. TDataCacheParticleBufferRenderer 粒子缓存拆分 @0x48
27. TDataCacheVideoNode 视频快照拆分 @0x48
28. ImageNode 渲染状态拆分 @0x94
29–31. GameLibConfig pField_0x00 / pStrs / pNetIds 拆分

### UNKNOWN 保持 64
含: cNetworkManager 其余 flag/string 语义空洞(含 pStrField_0x1A0/1B0/1B4/1F8 类型可定但语义无名); FileHandle 8; ShadowManager 4; TwitchAuth 4; cNetworkReplica 3; cEntity 9; cGame 6; MapGenSim/Atlas/VFX/Sound/TileRegion/MasterServerBroadcast/DontStarveGameService 等

### 报告路径
`docs/superpowers/type-recovery/unknown-scan-s2.md`
