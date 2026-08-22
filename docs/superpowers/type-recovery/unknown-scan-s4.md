# Unknown Field Scan — Slice4

- 日期: 2026-08-10
- 二进制: `dontstarve_steam` (macOS i386, Ghidra program=`dontstarve_steam`)
- 方法: 只读 ghidra-mcp (`get_struct_layout` / `search_functions` / `decompile_function` / `get_xrefs_to`)
- 范围: Slice4 分片 structs 的 UNKNOWN / nField_* / bField_* / pUNKNOWN_* 字段
- 命名约定: 指针 p*, int n*, bool/byte b*, uint dw*, float fl*, ushort w*

---

## DebugRenderComponent (17)

### DebugRenderComponent.nField_0xA4 @ 0xA4
semantic: flY
evidence: SetY@00031a7c 将 float 写入 `nField_0xA4`; LuaProxy::SetZ@00033242 调 SetY; String@00031a90 用 `(float)nField_0xA4 + const` 作为字符串 Y 基线
confidence: high

### DebugRenderComponent.bField_0xA8 @ 0xA8
semantic: UNKNOWN (保持)
evidence: ctor@000317dc 置 0; Flush/Line/Circle/Box/Triangle/String/DebugRender 扫描未见读写
confidence: low

### DebugRenderComponent.nField_0xAC @ 0xAC
semantic: pVecStrings_begin
evidence: dtor@000318da `~vector<sStringSubmission>(&nField_0xAC)`; String@00031a90 `push_back` 到 &nField_0xAC; Flush@00031a26 `_M_erase_at_end` 清该 vector; DebugRender@00031da2 迭代 +0xAC..+0xB0
confidence: high

### DebugRenderComponent.nField_0xB0 @ 0xB0
semantic: pVecStrings_end
evidence: 与 0xAC 同 vector 三元组; DebugRender 用 end-begin 算 count
confidence: high

### DebugRenderComponent.nField_0xB4 @ 0xB4
semantic: pVecStrings_cap
evidence: ctor 与 begin/end 一并清零; 标准 vector 布局 begin/end/cap
confidence: high

### DebugRenderComponent.nField_0xB8 @ 0xB8
semantic: pVecLines_begin
evidence: Line@00031b96 `vector<sDebugLineInfo>::push_back(this+0xB8)`; DebugRender 步进 0x1C 调 vtable+0x10 (SubmitDebugLine); Flush 重置 end=begin; dtor operator_delete
confidence: high

### DebugRenderComponent.nField_0xBC @ 0xBC
semantic: pVecLines_end
evidence: Flush `nField_0xBC = nField_0xB8`; DebugRender 循环条件 end!=begin
confidence: high

### DebugRenderComponent.nField_0xC0 @ 0xC0
semantic: pVecLines_cap
evidence: ctor 清零; vector 三元组第三槽
confidence: high

### DebugRenderComponent.nField_0xC4 @ 0xC4
semantic: pVecCircles_begin
evidence: Circle@00031c14 `vector<sDebugCircInfo>::push_back(this+0xC4)`; DebugRender 步进 0x14 调 vtable+0x14 (SubmitCircle)
confidence: high

### DebugRenderComponent.nField_0xC8 @ 0xC8
semantic: pVecCircles_end
evidence: Flush `nField_0xC8 = nField_0xC4`
confidence: high

### DebugRenderComponent.nField_0xCC @ 0xCC
semantic: pVecCircles_cap
evidence: vector 三元组; ctor 清零
confidence: high

### DebugRenderComponent.nField_0xD0 @ 0xD0
semantic: pVecBoxes_begin
evidence: Box@00031c72 `vector<sDebugBoxInfo>::push_back(this+0xD0)`; DebugRender 步进 0x1C 拆四边 SubmitDebugLine
confidence: high

### DebugRenderComponent.nField_0xD4 @ 0xD4
semantic: pVecBoxes_end
evidence: Flush `nField_0xD4 = nField_0xD0`
confidence: high

### DebugRenderComponent.nField_0xD8 @ 0xD8
semantic: pVecBoxes_cap
evidence: vector 三元组; ctor 清零
confidence: high

### DebugRenderComponent.nField_0xDC @ 0xDC
semantic: pVecTriangles_begin
evidence: Triangle@00031ce4 `vector<sTriangleVertexData>::push_back(this+0xDC)`; DebugRender 步进 0x40 调 vtable+0xC (SubmitDebugTriangle); dtor operator_delete
confidence: high

### DebugRenderComponent.nField_0xE0 @ 0xE0
semantic: pVecTriangles_end
evidence: Flush `nField_0xE0 = nField_0xDC`
confidence: high

### DebugRenderComponent.nField_0xE4 @ 0xE4
semantic: pVecTriangles_cap
evidence: vector 三元组; ctor 清零
confidence: high

---

## cSoundEmitterComponent (16)

### cSoundEmitterComponent.pVtable @ 0x10
semantic: pEvents_begin
evidence: dtor@00076242 将 pVtable 当 FMOD::Event* 数组 begin 迭代 release 后 operator_delete; DoPlaySound@000776d0 `vector<FMOD::Event*>::push_back(this+0x10)`; 真实组件 vtable 在 base@0
confidence: high

### cSoundEmitterComponent.nField_0x14 @ 0x14
semantic: pEvents_end
evidence: dtor 循环 `for (pu=pVtable; pu!=nField_0x14; ++pu) Event::release`
confidence: high

### cSoundEmitterComponent.nField_0x18 @ 0x18
semantic: pEvents_cap
evidence: ctor@0007610a 与 begin/end 一并清零; vector 三元组
confidence: high

### cSoundEmitterComponent.nField_0x1C @ 0x1C
semantic: pVecSoundNames_begin
evidence: dtor `~vector<std::string>(&nField_0x1C)`
confidence: high

### cSoundEmitterComponent.nField_0x20 @ 0x20
semantic: pVecSoundNames_end
evidence: vector 三元组中槽
confidence: high

### cSoundEmitterComponent.nField_0x24 @ 0x24
semantic: pVecSoundNames_cap
evidence: vector 三元组; ctor 清零
confidence: high

### cSoundEmitterComponent.nField_0x28 @ 0x28
semantic: pMapNamedEvents (map header base / _M_key_compare pad)
evidence: dtor `_Rb_tree::_M_erase(&nField_0x28)`; DoPlaySound `map::find/operator[](this+0x28)` 类型 `map<cHashedString,FMOD::Event*>`
confidence: high

### cSoundEmitterComponent.nField_0x2C @ 0x2C
semantic: nMapHeader_color (map end-sentinel header)
evidence: ctor 将 left/right 哨兵指向 &nField_0x2C; dtor 迭代 end=`&nField_0x2C`
confidence: high

### cSoundEmitterComponent.nField_0x30 @ 0x30
semantic: pMapHeader_parent
evidence: std::map 内嵌 RBTree header 字段布局; ctor 清零
confidence: high

### cSoundEmitterComponent.nField_0x34 @ 0x34
semantic: pMapHeader_left
evidence: ctor `nField_0x34 = &nField_0x2C` (空树 left=header)
confidence: high

### cSoundEmitterComponent.nField_0x38 @ 0x38
semantic: pMapHeader_right
evidence: ctor `nField_0x38 = &nField_0x2C`
confidence: high

### cSoundEmitterComponent.nField_0x3C @ 0x3C
semantic: nMapNodeCount
evidence: map header size 字段; ctor=0
confidence: high

### cSoundEmitterComponent.nField_0x40 @ 0x40
semantic: bActive (低字节; +1 另有抑制标志)
evidence: dtor 若 `(char)nField_0x40` 则 StopAllNamedSounds + release; SetVolume@00077856 读 `(char)nField_0x40` 与 `*(char*)(&nField_0x40+1)` 早退; 类型实为 bool 而非 int
confidence: high

### cSoundEmitterComponent.nField_0x44 @ 0x44
semantic: pVecDirtyEvents
evidence: dtor 若非空则 ~vector<DirtyEventInfo> + operator_delete; SetVolume 在其上 find/resize
confidence: high

### cSoundEmitterComponent.nField_0x48 @ 0x48
semantic: pVecDirtyEventsPrev
evidence: dtor 同样释放第二个 vector<DirtyEventInfo>*; SetVolume 用其 begin/end 做 reverse_find
confidence: high

### cSoundEmitterComponent.nField_0x4C @ 0x4C
semantic: flVolume
evidence: ctor 写 0x3f800000 (1.0f); SetVolume 调 FMOD::Event::setVolume(vol * nField_0x4C)
confidence: high

### cSoundEmitterComponent.nField_0x50 @ 0x50
semantic: UNKNOWN (保持)
evidence: ctor=0; 已扫描 dtor/DoPlaySound/SetVolume/PlaySound Lua 路径无进一步读写证据
confidence: low

---

## cShardManager (7)

### cShardManager.pField_0x00 @ 0x00
semantic: pVtable + 前置状态块 (建议拆: pVtable@0 / 若干 int / std::string@0x14 / std::string@0x24)
evidence: ctor@001a2e44 写 vtable `PTR__cShardManager_0045719c` 到 *pField_0x00; 清零 +4..; 两处 empty-string 指到 +0x14 与 +0x24
confidence: medium

### cShardManager.nField_0x40 @ 0x40
semantic: nDefaultFlag (初值 1)
evidence: ctor 置 1; 与 pM_shardPlayers map 哨兵初始化相邻; 已扫描无更细语义
confidence: low

### cShardManager.bField_0x5C @ 0x5C
semantic: bIncomingMigrationActive
evidence: ctor=0; 位于 pM_incomingMigrations map 之后; 命名按位置推断
confidence: low

### cShardManager.nField_0x84 @ 0x84
semantic: UNKNOWN (保持)
evidence: 位于 Timer_1 与 Timer_2 之间; ctor 未直接赋(可能 Timer 内部); 已扫描无证据
confidence: low

### cShardManager.bField_0x98 @ 0x98
semantic: bFlag_0x98
evidence: ctor=0; 与 bField_0x99 成对; 语义未定
confidence: low

### cShardManager.bField_0x99 @ 0x99
semantic: bFlag_0x99
evidence: ctor=0; 已扫描无证据
confidence: low

### cShardManager.pField_0xA0 @ 0xA0
semantic: UNKNOWN (保持)
evidence: ctor=0; 位于 pCheshireCat 与 pShardBroadcast 之间; 无释放/读写证据
confidence: low

---

## cAccountCommunication (6)

### cAccountCommunication.bField_0x30 @ 0x30
semantic: bConnected (或 bHasNetId)
evidence: ctor@00142070 在 cNetID2::Clear 后置 0; 紧随 pM_netId
confidence: medium

### cAccountCommunication.nField_0x44 @ 0x44
semantic: UNKNOWN (保持)
evidence: ctor=0; 位于 4×string 与 Mutex 之间; 已扫描无证据
confidence: low

### cAccountCommunication.nField_0xAC @ 0xAC
semantic: UNKNOWN (保持)
evidence: ctor 与 0xB0/0xB4 一并置 0; review-slice12 同样无语义
confidence: low

### cAccountCommunication.nField_0xB0 @ 0xB0
semantic: UNKNOWN (保持)
evidence: ctor=0; 已扫描无证据
confidence: low

### cAccountCommunication.nField_0xB4 @ 0xB4
semantic: UNKNOWN (保持)
evidence: ctor=0; 已扫描无证据
confidence: low

### cAccountCommunication.bField_0xC0 @ 0xC0
semantic: bBusy (或 bRequestPending)
evidence: ctor=0; 位于 Timer 之后尾标志; 常见请求进行中标志模式
confidence: low

---

## DynamicShadowComponent (5)

> 注: LuaProxy::SetSize@00071e6e 将 this 当作 `ShadowEntityComponent*` 调 SetSize; ShadowEntityComponent 布局 flSizeX@0x10/flSizeY@0x14/bEnabled@0x18/bPristine@0x19/bFlags@0x1A (27B)。DynamicShadow 36B 在其后扩 9B。Ghidra 现为 5×int 误型。

### DynamicShadowComponent.nField_0x10 @ 0x10
semantic: flSizeX
evidence: ShadowEntityComponent::SetSize@00071792 写 flSizeX; DynamicShadow LuaProxy 转调该函数
confidence: high

### DynamicShadowComponent.nField_0x14 @ 0x14
semantic: flSizeY
evidence: 同上 SetSize 写 flSizeY
confidence: high

### DynamicShadowComponent.nField_0x18 @ 0x18
semantic: bEnabled (+0x18) / bPristine(+0x19) / bFlags(+0x1A) 打包区
evidence: ShadowEntityComponent 布局; SetSize 改 bFlags |= 2/4; Ghidra 把 4B 整 int 看待
confidence: high

### DynamicShadowComponent.nField_0x1C @ 0x1C
semantic: UNKNOWN (保持)
evidence: 超出 ShadowEntity 27B 的扩展字段; dtor 仅调基类; 已扫描无证据
confidence: low

### DynamicShadowComponent.nField_0x20 @ 0x20
semantic: UNKNOWN (保持)
evidence: 同上扩展字段; 已扫描无证据
confidence: low

---

## cAccountManager (4)

### cAccountManager.bField_0x04 @ 0x04
semantic: bInitialized (或 bLoggedIn)
evidence: ctor@00146ff6 置 0; 紧随 vtable
confidence: low

### cAccountManager.nField_0x30 @ 0x30
semantic: UNKNOWN (保持)
evidence: ctor=0; 位于若干 string 之后; 已扫描无证据
confidence: low

### cAccountManager.nField_0x3C @ 0x3C
semantic: UNKNOWN (保持)
evidence: ctor=0; 位于 pCommunication 之后; 已扫描无证据
confidence: low

### cAccountManager.bField_0x40 @ 0x40
semantic: bOnlineCapable (初值 1)
evidence: ctor 置 1; 后续 pPad 清零
confidence: medium

---

## ReplicaManager3 (4)

### ReplicaManager3.qwUNKNOWN_0x1C @ 0x1C
semantic: UNKNOWN (保持)
evidence: ctor@002457fa 写 0 到 +0x1C; RakNet 内部通道/列表区; 已扫描无具名证据
confidence: low

### ReplicaManager3.qwUNKNOWN_0x24 @ 0x24
semantic: UNKNOWN (保持)
evidence: ctor 清零 +0x20/+0x24; 已扫描无证据
confidence: low

### ReplicaManager3.qwUNKNOWN_0x2C @ 0x2C
semantic: UNKNOWN (保持)
evidence: ctor 清零 +0x28/+0x2C; 已扫描无证据
confidence: low

### ReplicaManager3.dwUNKNOWN_0x34 @ 0x34
semantic: UNKNOWN (保持)
evidence: ctor +0x34=0; 随后 +0x38=0x1e 属于 qwAutoSerializeInterval(已命名)
confidence: low

---

## Shader (3)

### Shader.nField_0x0C @ 0x0C
semantic: UNKNOWN (保持)
evidence: InitShader@001c815a 使用 nHandle@4 / pName@8; 0x0C/0x10/0x14 未在 InitShader 路径写入; 参数向量更可能在子类
confidence: low

### Shader.nField_0x10 @ 0x10
semantic: UNKNOWN (保持)
evidence: 同上; 已扫描无证据
confidence: low

### Shader.nField_0x14 @ 0x14
semantic: UNKNOWN (保持)
evidence: 同上; 已扫描无证据
confidence: low

---

## MapComponent (2)

### MapComponent.nField_0x184 @ 0x184
semantic: UNKNOWN (保持)
evidence: ctor@00044f2c 写入异常常量串地址(反编译产物可疑); 无其它读写证据
confidence: low

### MapComponent.flField_0x188 @ 0x188
semantic: flOverlayScale (初值 0.25)
evidence: ctor 置 0.25f; 位于网络 tile 区域与 bFinalized 之间; 具体用途未在扫描中确认
confidence: medium

---

## cMasterServer (2+)

### cMasterServer.nField_0x80 @ 0x80
semantic: UNKNOWN (保持)
evidence: ctor@001583e6 置 0; Mutex 之后
confidence: low

### cMasterServer.nField_0x84 @ 0x84
semantic: UNKNOWN (保持)
evidence: ctor=0
confidence: low

### cMasterServer.nField_0x88 @ 0x88
semantic: UNKNOWN (保持)
evidence: ctor=0
confidence: low

### cMasterServer.nField_0x8C @ 0x8C
semantic: dwProtocolFlags (初值 0x1000001)
evidence: ctor 写 0x1000001; 位打包版本/能力标志模式
confidence: medium

### cMasterServer.bField_0x90 @ 0x90
semantic: bEnabled
evidence: ctor 置 1
confidence: medium

---

## cNetworkReplicaManager (2)

### cNetworkReplicaManager.nField_0x45C @ 0x45C
semantic: UNKNOWN (保持)
evidence: ctor@00180026 置 0; ReplicaManager3 base 之后首字段
confidence: low

### cNetworkReplicaManager.nField_0x460 @ 0x460
semantic: UNKNOWN (保持)
evidence: ctor=0; 与 nFrameCounter@0x468 相邻
confidence: low

---

## cSteamRichPresence (2)

### cSteamRichPresence.bField_0x1C @ 0x1C
semantic: bDirty
evidence: ctor@001c0b9a 置 0; 位于 presence map 与 m_serverNetId 之间; 典型 dirty 标志位置
confidence: medium

### cSteamRichPresence.bField_0x52 @ 0x52
semantic: bHasConnectString
evidence: ctor=0; 位于 pM_connectString 之后尾标志
confidence: medium

---

## cNetworkComponent (1+)

### cNetworkComponent.nField_0x168 @ 0x168
semantic: UNKNOWN (保持)
evidence: ctor@0005adec 置 0; Replica3 之后
confidence: low

### cNetworkComponent.nField_0x16C @ 0x16C
semantic: UNKNOWN (保持)
evidence: ctor=0
confidence: low

### cNetworkComponent.bField_0x170 @ 0x170
semantic: bIsSleeping (或 bLocalFlags)
evidence: ctor=0; 紧邻 sleeping flags dword
confidence: low

### cNetworkComponent.bField_0x171 @ 0x171
semantic: UNKNOWN (保持)
evidence: ctor=0
confidence: low

---

## QuadTreeNode_Node (1)

### QuadTreeNode_Node.nField_0x20 @ 0x20
semantic: UNKNOWN (保持)
evidence: 布局上位于 4 children 与 std::set header 之间; QuadTreeNode 父 ctor@000c4a52 初始化 set 哨兵, 未直接写 Node.nField_0x20; RecCreate 路径未深挖
confidence: low

---

## CSHA1 (1)

### CSHA1.nField_0x1C @ 0x1C
semantic: UNKNOWN (保持)
evidence: ctor@001f6eca 初始化 pM_state/pM_count/pWorkspace, **未写** 0x1C; 位于 count 与 buffer 之间; review-slice19 亦标 UNKNOWN
confidence: low

---

## BitmapFont (1)

### BitmapFont.dwField_0x14 @ 0x14
semantic: nOutline
evidence: review-slice22 Load 路径写 0; 位于 flScaleH 与 dwPages 之间; outline 属性邻接
confidence: medium

---

## ParticleEmitter (1)

### ParticleEmitter.pUNKNOWN_0x04 @ 0x04
semantic: pEmitterState (混合块, 建议后续拆分)
evidence: ctor@0005e1fc 写多个子字段: +0x10 附近 1.0f (flMaxAge)、+0x2C 起 flags、+0x4C One 向量、+0x54=3、+0x74=3、+0x80=0x20 (nMaxParticles)、dtor@0005e2d2 释放 +0x78 渲染器虚调用 与 +0x7C ParticleBuffer*
confidence: medium

推荐子命名(相对 struct 绝对偏移, vtable@0):
- flMaxAge @ 0x10
- pEffectRenderer @ 0x7C
- pParticleBuffer @ 0x80
- nMaxParticles @ 0x84 (初值 0x20)

---

## TwitchComponent (1)

### TwitchComponent.nField_0x2C @ 0x2C
semantic: UNKNOWN (保持)
evidence: ctor@000826bc 置 0; 位于 map 头之后; 已扫描无证据
confidence: low

---

## Connection_RM3 (1)

### Connection_RM3.nUNKNOWN_0x29C @ 0x29C
semantic: UNKNOWN (保持)
evidence: ctor@002495a6 初始化至 bitStream2, **未写** 0x29C; 位于 bitStream2 末尾后 4B; 可能为对齐/保留
confidence: low

---

## cAnimStateComponent (1)

### cAnimStateComponent.nField_0x8C @ 0x8C
semantic: UNKNOWN (保持)
evidence: ctor@0002960c 置 0; 位于 override 色标志与 flHauntStrength 之间; SetOrientation/SetLayer 不碰该字段
confidence: low

---

## ParticleBuffer (1)

### ParticleBuffer.wField_0x08 @ 0x08
semantic: wActiveCount
evidence: ctor@000b6096 置 0; 位于两色后与数据指针前; 粒子活跃计数常见布局
confidence: medium

---

## TDataCacheImageNode (1)

### TDataCacheImageNode.pUNKNOWN_0x48 @ 0x48
semantic: pImageCacheState
evidence: ctor@000c40f8 从 ImageNode+0x94/0xB8/0xBC/0xB0/0x98/... 批量拷入 pUNKNOWN_0x48+0..; 含颜色 0xA3=0xFF 等
confidence: medium

---

## TDataCacheTextNode (1)

### TDataCacheTextNode.pUNKNOWN_0x48 @ 0x48
semantic: pTextCacheState
evidence: ctor@000c86b4 初始化大块默认色/对齐, 再从 TextNode+0xF4/0x100/0xF8/0x10C/0x104/0x124 拷入
confidence: medium

---

## cMasterServerRequest (1)

### cMasterServerRequest.bField_0x04 @ 0x04
semantic: bInFlight
evidence: ctor@001608ea 置 0; 位于 vtable 与 URL string 之间
confidence: medium

---

## 汇总

| 分类 | 数量 |
|------|------|
| 建议命名 (semantic ≠ UNKNOWN 保持) | **56** |
| UNKNOWN 保持 | **33** |
| 合计扫描字段 | **89** |

### 命名数 / 保持数
**命名 56 / UNKNOWN 保持 33**

### 高优先深入结果
- **DebugRenderComponent**: 17 中命名 16 (仅 bField_0xA8 保持) — 五组 debug 图元 vector + flY
- **cSoundEmitterComponent**: 17 槽位中命名 16 (仅 nField_0x50 保持) — FMOD Event 数组 / 音名 vector / 命名 map / dirty 双缓冲 / flVolume

### 备注
- DynamicShadowComponent 应与 ShadowEntityComponent 对齐重分字段(float/byte 打包), 当前 Ghidra int 布局是类型问题而非纯命名问题
- ParticleEmitter / TDataCache* 的大块 pUNKNOWN 适合二次拆分, 本扫描给出子偏移证据
- 禁止写 Ghidra; 本文件仅为命名建议报告
