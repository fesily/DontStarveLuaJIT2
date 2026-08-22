# Remaining F1 — 网络层类型恢复报告

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp (G) + idalib-mcp (I, 会话 c1f3f184, 健康)
> 方法:ctor/dtor 反编译(每类型 ≤2 次)+ 小方法反汇编 + vtable read_memory 验证
> 关键洞见:
> - **RakNet::Replica3 基类 = 0x158(344B)**;游戏侧中间基类 cNetworkReplica = Replica3 + 0xC 字段(+0x158/+0x15C int,+0x160/+0x161 byte) = **0x164**。
> - **cNetworkConnection : RakNet::Connection_RM3**(Tier 4),基类 0x2A0,游戏仅 +0x2A0 一个 int。
> - **cSteamPunchthrough : RakNet::Lobby2**(Tier 4, 8B);**cSteamPunchthroughPlugin : RakNet::PluginInterface2**(Tier 4, 多继承,次 vtable @ +4,thunk `ZThn4`)。
> - std::map 头部识别:ctor `X+0=0, X+4=0, X+8=&self, X+12=&self, X+16=0`(color/parent/left/right/count,头部 @ X+4,树根 @ X+8);dtor `_M_erase(base, *(this+root_off))` 给出精确 base/root 偏移与类型化元素。
> - CCallback = 24B(vtable@0, pObj@4, fn@8, 注册标志 @ +4);CCallResult = 32B(SteamWorkshop 记录)。
> - std::string = 4B(旧 ABI);cNetID2 = 44B(steamID 原始 uint64 @ +0x24/+0x28);Timer = 8B。
> - 本分片 15 类型在 Ghidra 中**全部为 1B 占位(/Demangler/)**,无已建布局;cNatTraversal 在 tier3-d 已定型但未写回。

---

## 1. cNetworkConnection — 待恢复(676B, 0x2A4)

- **基类**: RakNet::Connection_RM3 (Tier 4, 0x2A0);**vtable**: 0x456F38
- **无独立 ctor 符号**:构造内联于 `cNetworkReplicaManager::AllocConnection` (0x189a92):`operator new(0x2A4)` → `Connection_RM3 ctor` → `*v4 = &unk_456F38` → `v4[168] = *(manager+0x45C)` — **大小铁证 0x2A4**
- **D1** 0x16519a / **D0** 0x1651a0(D0 = 仅 `Connection_RM3::~` + `operator delete`,无游戏字段清理)

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x000 | pVtable | void* (0x456F38) | AllocConnection `*v4 = &unk_456F38`;vtable [D1, D0, AllocReplica 0x164396, RakNet 虚槽…] (G read_memory) |
| 0x000..0x29F | Connection_RM3 基类 | — | **Tier 4 跳过**;ctor 0x2495a6 |
| 0x2A0 | nField_0x2A0 | int | AllocConnection `v4[168] = *(manager+0x45C)` (I 0x189ae6) |

- 方法:AllocReplica 0x164396 / AllocEntityReplica 0x16449c / AllocClientObjectReplica2 0x164768(读基类 +0x8)/ GetClientIndex 0x1648be(读 cNetworkClientObject2+0x170 位掩码)/ QueryReplicaList 0x164900 / QueryConstructionMode 0x164da8(空)/ QueryGroupDownloadMessages 0x1651d4(6B)
- **回写建议**: 新建 — 基类 0x2A0 标 Tier 4,仅建 `nField_0x2A0@+0x2A0`,大小 0x2A4

---

## 2. cNetworkReplica — 待恢复(356B, 0x164, 游戏中间基类)

- **基类**: RakNet::Replica3 (Tier 4, 0x158);无自有 vtable(子类各自设置:cNetworkClientObject2 → 0x456E68,cNetworkTileRegion → 0x4570A8)
- 无独立 ctor 符号:基类初始化内联于两个子类 ctor(均先 `Replica3::Replica3(this)` 再写 +0x158..+0x161)

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x000..0x157 | Replica3 基类 | — | **Tier 4 跳过**;ctor 0x24ac80 |
| 0x158 | nField_0x158 | int =0 | cNetworkClientObject2 ctor (I 0x162e11) / cNetworkTileRegion ctor (I 0x18bb41) |
| 0x15C | nField_0x15C | int =0 | 同上 (I 0x162e07 / 0x18bb37) |
| 0x160 | bField_0x160 | byte =0 | 同上 (I 0x162e1b / 0x18bb4b) |
| 0x161 | bRegistered | byte =0→1 | 同上 (I 0x162e22 / 0x18bb52);两子类 dtor `if (*(this+0x161)) UnregisterWithReplicaManager` |

- 方法:UnregisterWithReplicaManager 0x188d96 → `cNetworkReplicaManager::RemoveFromLists` (I);SetAsleep/SetAwakeForConnection/RemoveFromLists 均在 cNetworkReplicaManager(非本分片)
- **回写建议**: 新建 — 中间基类,大小 0x164;Replica3 段标 Tier 4

---

## 3. cNetworkRPCManager — 待恢复(20B, 0x14, 无 vtable)

- **C2** 0x180258 (0x531) / **C1** 0x184968(5B), **D2** 0x18496e (0x8b) / D1 0x1849fa / D0 0x184a00
- ctor 注册 29 个 RPC 槽(RPC4::RegisterSlot → ReceiveLuaRPC…ReceiveAchievementNotification)

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pRPC4 | RakNet::RPC4* | ctor `= operator new(0x150); RPC4::RPC4` (I 0x180317);dtor 虚删 `(*(*p+4))(p)` (I 0x1849d8) — Tier 4 对象指针 |
| 0x04 | pBitStream | RakNet::BitStream* | ctor `= new(0x114); BitStream::BitStream` (I 0x180303);dtor 删 (I 0x1849b9) |
| 0x08 | ppSlotNames | char*[29] | ctor `new[](0x74)` + 29×`new[](2)` 单字符槽名 (I 0x180298..0x1802e0);dtor 逐项 delete[] + delete[] 数组 (I 0x184975..0x1849a8) |
| 0x0C | nField_0x0C | int =0 | ctor (I 0x18027a) |
| 0x10 | bField_0x10 | byte =0 | ctor (I 0x180288) |

- 方法:SignalToServer 0x184a52 / SignalToAll 0x184b70(用 +0x04 BitStream);SendLuaRPCToServer 0x184f2a;OnReceiveLuaRPC 0x185e00
- **回写建议**: 新建 — 大小 0x14;pRPC4/pBitStream 标 Tier 4 对象指针

---

## 4. cNetworkTileRegion — 待恢复(388B, 0x184)

- **基类**: cNetworkReplica (0x164) → RakNet::Replica3 (Tier 4);**vtable**: 0x4570A8 ([D1 0x18bd5c, D0 0x18bd62, Replica3 虚槽 0x21e134, 0x21e19e, …] G read_memory)
- **C2** 0x18bb16 (0x1e3) / **C1** 0x18bcfa, **D2** 0x18bd00 (0x5c) / D1 0x18bd5c / D0 0x18bd62

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x000..0x163 | cNetworkReplica 基类 | — | ctor `Replica3(this)` + 基类字段 (I 0x18bb32..0x18bb52) |
| 0x164 | pNetworkManager | cNetworkManager* | ctor `thisa[89] = a3` (I 0x18bb61);Deserialize `IMUL [pNM+0x10], [this+0x164]` (G 0x18c078) |
| 0x168 | nRegionIndex | int | ctor `thisa[90] = a4` (I 0x18bb67);Deserialize `IMUL [pTileGrid+0x14], [this+0x168]` |
| 0x16C | pTileGrid | TileGrid* | ctor `thisa[91] = *(MapComponent+0xE0)` (I 0x18bb91);Deserialize `[this+0x16C]→+0x10/+0x14` 宽高 |
| 0x170 | pMapComponent | MapComponent* | ctor `thisa[92] = a5` (I 0x18bb71);Deserialize `[this+0x170]→+0xC→+0x40` 取世界 |
| 0x174 | pTileData | Tile* (256 word) | ctor `thisa[93] = new[](0x200)` 填 0xFF+随机 (I 0x18bc0f..0x18bc49);dtor `delete[]` (I 0x18bd26);WriteTypeData 拷 0x100B (G 0x18bee4) |
| 0x178 | pTileDataPtr | Tile* | ctor `thisa[94] = a3 + TileGrid[2]*a4` (I 0x18bc5d) |
| 0x180 | nField_0x180 | int =0 | ctor `thisa[96] = 0` (I 0x18bb81) |

- 方法:SerializeConstruction 0x18bd8e / DeserializeConstruction 0x18bde4 / Serialize 0x18be44 / Deserialize 0x18bf1a(读写 +0x174 缓冲)/ ReadTypeData 0x18c21e / GetName 0x18c492
- **回写建议**: 新建 — 基类段 0x164 标 Tier 4 以上,游戏字段 +0x164..+0x180,大小 0x184

---

## 5. cNetworkVoiceManager — 待恢复(20B, 0x14)

- **vtable**: 0x457170 (16B: [D1 0x18dab6, D0 0x18dabc, 0, 0])
- **C2** 0x18d9d2 (0x78) / C1 0x18da4a, **D2** 0x18da50 (0x65) / D1 0x18dab6 / D0 0x18dabc

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* (0x457170) | ctor `*this = &unk_457170` (I 0x18d9e8) |
| 0x04 | pBitStream | RakNet::BitStream* | ctor `= new(0x114); BitStream::BitStream` (I 0x18da1d);dtor 删 (I 0x18da72) |
| 0x08 | bEnabled | byte =1 | ctor `*(this+8)=1` (I 0x18d9f1) |
| 0x0C | m_mutedPlayers | std::list<std::string> | ctor 自引用 +0xC/+0x10 = &this+0xC (I 0x18da06);dtor `_List_base<std::string>::_M_clear(this+0xC)` (I 0x18da8c) |

- 方法:SetPlayerMuted 0x18db16 / IsPlayerMuted 0x18db9a / BroadcastVoiceData 0x18dbe4 / ReceiveVoicePacket 0x18de7e / ProcessVoicePacket 0x18df1a
- **回写建议**: 新建 — 大小 0x14;pBitStream 标 Tier 4 对象指针

---

## 6. cNetworkClientObject2 — 待恢复(≥544B, 0x220)

- **基类**: cNetworkReplica (0x164) → RakNet::Replica3 (Tier 4);**vtable**: 0x456E68
- **C2** 0x162dea (0x26a) / C1 0x163054, **D2** 0x16305a (0x29f) / D1 0x163432 / D0 0x163438

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x000..0x163 | cNetworkReplica 基类 | — | ctor `Replica3(this)` + +0x158/+0x15C/+0x160/+0x161 (I 0x162e02..0x162e22) |
| 0x164 | m_rakNetGUID | RakNetGUID (12B) | ctor `QWORD[this+0x164] = a3[0..1]; [this+0x16C]=a3[2]` (I 0x162e3e);tClientProxy ctor 读 +0x164 判 IsServer (I 0x199430) |
| 0x170 | nConnectionMask | uint64 =0 | ctor 清零 (I 0x162e50/0x162e5a);cNetworkConnection::GetClientIndex 位扫描 `(*(this+0x170)>>i)&1` (I 0x1648c6) |
| 0x178 | pPlayerEntity | void* =0 | ctor (I 0x162e46);dtor `v3=*(this+0x178); v4=*(v3+0xC); SetPlayer(v4, this, 0)` (I 0x163092) |
| 0x17C | cPlayerListingData | 内嵌子对象 (~0x7F) | ctor `cPlayerListingData::cPlayerListingData(this+0x17C)` (I 0x162e6d);dtor 销毁其 string@+0 (+0x17C) 与 ptr@+0x70 (0x1EC);tClientProxy `pListing = clientObj+0x17C` (I 0x19943f) |
| 0x1B8 | colour | Colour (子对象内) | dtor `cClientColourPicker::ReleaseColour(this+0x1B8)` 当 (+0x212&1)==0 (I 0x163122) |
| 0x1FC | Timer | Timer (8B) | ctor `Timer::Timer(this+0x1FC)` (I 0x162e7f) |
| 0x204 | bField_0x204 | byte =0 | ctor (I 0x162e84) |
| 0x208 | pNetStats | void* =0 | ctor (I 0x162e8b);`= new[](0x1E0)` 480B + __bzero (I 0x162f71);dtor delete[] (I 0x1631ba) |
| 0x20C | pField_0x20C | void* =0 | ctor (I 0x162e95);`= new(8)` (I 0x162f85);dtor delete (I 0x1631cc) |
| 0x210 | bField_0x210 | byte =0xFF | ctor (I 0x162e9f) |
| 0x211 | bField_0x211 | byte =0 | ctor (I 0x162ea6) |
| 0x212 | bFlags_0x212 | byte =0x7F | ctor (I 0x162ead);bit0 = hasColour(ReleaseColour 守卫);tClientProxy `*(client+0x212)==0 → bNotDedicated` (I 0x19944e) |
| 0x213 | nField_0x213 | int =0 | ctor (I 0x162ec7);dtor 读作事件负载 (I 0x1630a8) |
| 0x217 | wField_0x217 | ushort =0 | ctor (I 0x162ebe) |
| 0x21C | nField_0x21C | int =0 | ctor (I 0x162eb4) |
| 0x220+ | UNKNOWN | — | ctor 未初始化;大小 ≥0x220 |

- 方法:SetPlayer 0x1632fa / SetName 0x1634f0 / SetUserID 0x163518 / SetNetID 0x16359e / Serialize 0x163be6 / Deserialize 0x163c5c / UpdateNetStats 0x163e1e / IsAFK 0x163dd0 / GetName 0x1642a2
- **回写建议**: 新建 — 基类段 0x164 标 Tier 4;字段 0x164..0x21F;cPlayerListingData 引用 tier3-d 已有分析(另行建)

---

## 7. cNetworkFileTransferCB — 待恢复(4B, 仅 vtable)

- **基类**: RakNet::FileListTransferCBInterface (Tier 4);**无数据成员**
- **D1** 0x1657bc(1B) / **D0** 0x1657be(5B, 仅 `operator delete`,无基类 dtor/字段清理)
- **vtable**: 0x456F88 — [D1 0x1657BC, D0 0x1657BE, OnFile 0x16575E, OnFileProgress 0x165638, Update(base 0x20f9e2), OnDownloadComplete 0x165526, OnDereference(base 0x20fa0c), 0×7, …] (G read_memory;槽序与 DDTCallback vtable 0x463730 一致)

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* (0x456F88) | D1/D0 xref (G get_xrefs_to 0x1657bc) |

- 方法:OnDownloadComplete 0x165526(只用参数+全局,`GetClientSessionDirectory`+`LoadWorldFile`)/ OnFileProgress 0x165638 / OnFile 0x16575e — 均无 `this` 字段访问
- 分配方式:栈/堆均可(无 ctor);无 `new(4)` 锚点,但 vtable-only 由方法零字段访问 + D0 仅 delete 保证
- **回写建议**: 新建 — 4B 接口回调类,仅 vtable;基类槽标 Tier 4

---

## 8. cPendingConnection — 待恢复(112B, 0x70, 无 vtable)

- **C2** 0x1995d6 (0x15b) / C1 0x1998c4, **D2** 0x1998ca (0x1b4) / D1 0x199a7e;无 vtable(ctor 直写 +0)

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | eState | int | 状态机:1=NewRequest, 2=Connecting, 3=WaitingForToken, 4=WaitingForPingResponse, 5=WaitingForLua, 6=ConnectionComplete(见下) |
| 0x04 | bIsDedicated | byte | NewConnectionRequest `[this+0x4] = arg` (G 0x199b68) |
| 0x08 | m_ip | std::string | ctor `=&empty` (I 0x1995f0);NewConnectionRequest `assign(this+0x8, ResolveConnectIP)` (G 0x199b8c);dtor 销毁 (I 0x1999a5) |
| 0x0C | wPort | ushort | NewConnectionRequest `[this+0xC]=port` (G 0x199bb0);IsAwaitingPingResponseFrom 比较 (G 0x199ca6) |
| 0x10 | RakNetGUID | RakNet::RakNetGUID (12B) | ctor `RakNetGUID::RakNetGUID(this+0x10)` (I 0x1995f9);NewConnectionRequest 拷 12B (G 0x199bb4..0x199bc1) |
| 0x1C | m_token | std::string | ctor `=&empty` (I 0x1995fe);GotLuaResponse `assign(this+0x1C, s)` (G 0x199e2b);dtor 销毁 (I 0x199985) |
| 0x20 | m_netId | cNetID2 (44B) | ctor `cNetID2::Clear` (I 0x199615);NewConnectionRequest `cNetID2::operator=(this+0x20, &arg)` (G 0x199bd7 调 0x1623f4) |
| 0x4C | bHasToken | byte =0 | ctor 区域;SetHasToken `[this+0x4C]=1` (G 0x199e4a) |
| 0x54 | Timer | Timer (8B) | ctor `Timer::Timer(this+0x54)` (I 0x199620) |
| 0x60 | pServerListing | tServerListing* | ctor `= new(0x10C); tServerListing::tServerListing` (I 0x199636);dtor 删 (I 0x1998e5);IsAwaitingTokenFor `[this+0x60]→+0x10` 名字串 (G 0x199c56) |
| 0x64 | m_pingIP | std::string | ctor `=&empty` (I 0x199641);IsAwaitingPingResponseFrom 比较 (G 0x199cb0);dtor 销毁 (I 0x199945) |
| 0x68 | wPingPort | ushort | IsAwaitingPingResponseFrom 比较 (G 0x199cc6) |

- 状态机证据:SetConnecting `[this]=2` (G 0x199de2)/ SetWaitingForToken `=3` (G 0x199dee)/ SetWaitingForLua `=5` (G 0x199dfa)/ SetHasToken `=2`+`[+0x4C]=1` / SetConnectionComplete `=6` (G 0x19a324)/ NewConnectionRequest `=1` (G 0x199b5e)/ IsAwaitingTokenFor `==3` (G 0x199c4d)/ IsAwaitingPingResponseFrom `==4` (G 0x199c82)
- 方法:Reset 0x199732 / ResolveConnectIP 0x199a84 / StartPing 0x199e56 / UpdatePing 0x199e8e / ReceivePong 0x19a1aa / SetServerListing 0x199cdc / GetMostPubliclyKnownServerAddress 0x19a32c
- **回写建议**: 新建 — 大小 0x70;RakNetGUID 12B、cNetID2 44B、Timer 8B 引用既有类型

---

## 9. cNatTraversal — 已存在(tier3-d 已定型,核对通过;Ghidra 仍为 1B 占位)

- **C2** 0x161b7a (0x62) / C1 0x161bdc, **D2** 0x161be2 / D1 0x161be8
- **基类**: RakNet::NatPunchthroughClient (Tier 4, 0x190);构造地址被静态初始化表引用(0x4f20ff [DATA]) → 全局对象

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x000..0x18F | NatPunchthroughClient 基类 | — | **Tier 4 跳过**;ctor `NatPunchthroughClient(this)` (I 0x161b8c) |
| 0x190 | cNatPunchthroughDebugInterfaceImpl | 子对象 (vtable 0x462738) | ctor `*(this+0x190) = &unk_462738` (I 0x161ba0);`SetDebugInterface(this+0x190)` (I 0x161bb7) |
| 0x194 | nField_0x194 | int =5 | ctor `*(this+0x194)=5` (I 0x161ba6) |

- 方法:OpenUPNP 0x161fb8 / NewPeer 0x16211a / OnConnectedToPunchThrough 0x162138 / OnFailedToConnectToPunchThrough 0x1621fe — 无新增字段
- **回写建议**: 重建 — 按 tier3-d 报告写回(Ghidra 当前 /Demangler/cNatTraversal 1B 占位),基类 0x190 标 Tier 4,大小 ≥0x198

---

## 10. cNatTraversal::cNatPunchthroughDebugInterfaceImpl — 待恢复(4B, 仅 vtable)

- **基类**: RakNet::NatPunchthroughDebugInterface (Tier 4)
- **vtable**: 0x462738 — [D1 0x162240, D0 0x162254, OnClientMessage 0x16225a, 0] (G read_memory)
- **D1** 0x162240(1B) / **D0** 0x162254(5B, `jmp operator delete`);**OnClientMessage** 0x16225a(0x13, 仅日志)

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* (0x462738) | cNatTraversal ctor `*(this+0x190)=&unk_462738` (I 0x161ba0) |

- **回写建议**: 新建 — 4B 接口类;基类槽标 Tier 4

---

## 11. cSteamAccountCommunication — 待恢复(284B, 0x11C)

- **基类**: cAccountCommunication (0xC4, 196B,**已存在**核对通过,get_struct_layout 确认);**vtable**: 0x457218
- **C2** 0x1bbb5c (0x1c8) / C1 0x1bc2a6, **D2** 0x1bc2ac (0x197) / D1 0x1bc444 / D0 0x1bc44a
- **大小铁证**: cAccountManager ctor `operator new(0x11C); cSteamAccountCommunication(...)` (I 0x147cef)

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x000..0x0C3 | cAccountCommunication 基类 | — (0xC4, 已存在) | ctor `cAccountCommunication(this)` (I 0x1bbb78);m_netId@+4 由 `cNetID2::operator=(CSteamID)` 覆写 (I 0x1bbc81) |
| 0x0C4 | CCallback<GameServerChangeRequested_t> | 24B (vtable 0x463278) | ctor `CCallback(this+0xC4, this, OnDirectJoinRequested)` (I 0x1bbbb0);dtor `SteamAPI_UnregisterCallback(this+0xC4)` 当 flag@+0xC8 (I 0x1bc383) |
| 0x0DC | CCallback<GameRichPresenceJoinRequested_t> | 24B (vtable 0x463258) | ctor `CCallback(this+0xDC, this, OnRichPresenceJoinRequested)` (I 0x1bbbe4);dtor 注销 flag@+0xE0 (I 0x1bc35d) |
| 0x0F4 | CCallback<GetAuthSessionTicketResponse_t> | 24B (vtable 0x463238) | ctor `CCallback(this+0xF4, this, OnValidateAuthTicketResponse)` (I 0x1bbc14);dtor 注销 flag@+0xF8 (I 0x1bc337) |
| 0x10C | pAuthTicketBuffer | void* =0→new[](0x800) | ctor `[this+0x10C]=0` 后 `= new[](0x800)` (I 0x1bbc19/0x1bbc4d);dtor delete[] (I 0x1bc31c) |
| 0x110 | hAuthTicket | uint32 =0 | ctor (I 0x1bbc23);dtor `SteamUser->CancelAuthTicket([this+0x110])` (I 0x1bc2ed) |
| 0x114 | nTicketBufferSize | int =2048 | ctor `= 0x800` (I 0x1bbc2d) |
| 0x118 | nField_0x118 | int =0 | ctor (I 0x1bbc37) |

- 方法:Login 0x1bc476 / ServerLogin 0x1bc6ce / DiscoverNetworkServiceToken 0x1bc85e / IsWaitingForResponse 0x1bc978 / OnValidateAuthTicketResponse 0x1bbfc8
- **回写建议**: 新建 — 子类增量 +0x58 (0xC4→0x11C);3×CCallback + 票证缓冲;基类引用已存在 cAccountCommunication

---

## 12. cSteamPunchthrough — 待恢复(≥70B, 0x46)

- **基类**: RakNet::Lobby2 : Lobby2Callbacks (Tier 4, 8B:vtable + callbackId@4);**vtable**: 0x4572A8
- **C2** 0x1bdafa (0x9b) / C1 0x1bdb96, **D2** 0x1bdc32 (0x65) / D1 0x1bdc98 / D0 0x1bdc9e

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x000 | pVtable | void* (0x4572A8) | ctor `*this = &unk_4572A8` (I 0x1bdb1c) |
| 0x004 | nCallbackId | int (基类) | ctor `= RakNet::Lobby2Callbacks::nextCallbackId++` (I 0x1bdb13) |
| 0x008 | pRakPeer | RakPeerInterface* =0 | ctor (I 0x1bdb1e);OnStart 存参 (G 0x1bdcda) |
| 0x00C | CCallResult<ClanOfficerListResponse_t> | 32B (vtable 0x463298, cbId 335@+0x14) | ctor `[this+0xC]=&unk_463298`, `[this+0x14]=335` (I 0x1bdb32/0x1bdb58);dtor `SteamAPI_UnregisterCallResult(this+0xC, hAPICall@+0x18/0x1C)` (I 0x1bdc7e) |
| 0x02C | pField_0x2C | void* =0 | ctor (I 0x1bdb35);dtor delete (I 0x1bdc49) |
| 0x030 | nField_0x30 | int =0 | ctor (I 0x1bdb3c) |
| 0x034 | nField_0x34 | int =0 | ctor (I 0x1bdb43) |
| 0x038 | pPlugin | cSteamPunchthroughPlugin* =0 | ctor (I 0x1bdb4a);OnStart 惰性 `= new(0xC4); cSteamPunchthroughPlugin ctor` (G 0x1bdcf1..0x1bdd00) |
| 0x03C | wField_0x3C | ushort =0 | ctor (I 0x1bdb8c) |
| 0x03D | bIsSteamGameServer | byte | GetSteamGameServer `if ([this+0x3D]) SteamGameServer()` (G 0x1bde26);IsSteamGameServerReady (G 0x1be465) |
| 0x03E | bField_0x3E | byte =0 | ctor (I 0x1bdb88) |
| 0x040 | nField_0x40 | int =0 | ctor (I 0x1bdb5f) |
| 0x044 | wField_0x44 | ushort =0 | ctor (I 0x1bdb66) |

- 方法:OnStart 0x1bdcca / OnStop 0x1bdd36 / GetNetID 0x1bde78(返回值构造,无成员写)/ GetPunchThroughAddress 0x1be7d8(空)/ ReceiveAuthenticationBlob 0x1bdec0 / SendAuthenticationBlob 0x1be488 / OnRequestClanOfficerList 0x1be18a / GetRoomID 0x1bde72(空)/ GetPendingCreation 0x1be808(空)
- **回写建议**: 新建 — 基类 8B 标 Tier 4;游戏字段 +0x08..+0x45;大小 ≥0x46

---

## 13. cSteamPunchthroughPlugin — 待恢复(196B, 0xC4)

- **多继承**: 主 vtable 0x457598 @ +0,次 vtable 0x4575BC @ +4(**RakNet::PluginInterface2** 基类,Tier 4,thunk `ZThn4`)
- **C2** 0x1beae6 (0x213) / C1 0x1bedbc, **D2** 0x1bedc2 (0x21d) / D1 0x1befe0 / D0 0x1beffc
- **大小铁证**: cSteamPunchthrough::OnStart `operator new(0xC4)` (G 0x1bdcf1)

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x000 | pVtable | void* (0x457598) | ctor (I 0x1beb13) |
| 0x004 | PluginInterface2 基类 | — (vtable 0x4575BC) | ctor `PluginInterface2::PluginInterface2(this+4)` (I 0x1beb08);RakNetSendTo/RakNetRecvFrom 虚槽 |
| 0x010 | CCallback<P2PSessionRequest_t> | 24B (vtable 0x4632D8) | ctor `CCallback(this+0x10, this, OnP2PSessionRequest)` (I 0x1beb46);dtor 注销 flag@+0x14 (I 0x1bef76) |
| 0x028 | CCallback<P2PSessionConnectFail_t> | 24B (vtable 0x4632B8) | ctor `CCallback(this+0x28, this, OnP2PSessionConnectFail)` (I 0x1beb73);dtor 注销 flag@+0x2C (I 0x1bef59) |
| 0x040 | m_addressToSteamID | std::map<SystemAddress, ull> (20B) | dtor `_Rb_tree<SystemAddress,pair<const SA,ull>>::_M_erase(this+0x40, *(this+0x48))` (I 0x1bedfc);ctor 头初始化 (I 0x1beb7b..0x1beba1) |
| 0x058 | m_steamIDToAddress | std::map<ull, SystemAddress> (20B) | dtor `_M_erase(this+0x58, *(this+0x60))` (I 0x1bee29) |
| 0x070 | m_idleTimers | std::map<ull, Timer> (20B) | dtor `_Rb_tree<ull,pair<const ull,Timer>>::_M_erase(this+0x70, *(this+0x78))` (I 0x1bee56) |
| 0x088 | nField_0x88 | int =1 | ctor (I 0x1bec05) |
| 0x08C | nField_0x8C | int =-1 | ctor (I 0x1bec0f) |
| 0x090 | nField_0x90 | int =0 | ctor (I 0x1bec19) |
| 0x094 | m_timers2 | std::map<ull, Timer> (20B) | dtor `_M_erase(this+0x94, *(this+0x9C))` (I 0x1bee8e) |
| 0x0AC | m_timers3 | std::map<ull, Timer> (20B) | dtor `_M_erase(this+0xAC, *(this+0xB4))` (I 0x1beecc) |

- 方法:GetAddressForHost 0x1bf03e / HasSession 0x1bf0e6 / CreateSession 0x1bf164 / RemoveSession 0x1bf986 / ResetIdleTimer 0x1bf122 / RakNetSendTo 0x1bf264 / RakNetRecvFrom 0x1bf492 / OnAttach 0x1bf75c / OnDetach 0x1bf830 / Update 0x1bf8dc / GetNextUnusedAddress 0x1bfb5a
- **回写建议**: 新建 — 大小 0xC4;PluginInterface2 段标 Tier 4;5×std::map 头部 20B(header@+4, root@+8)

---

## 14. cSteamFriendsManager — 待恢复(32B, 0x20)

- **vtable**: 0x457278
- **C2** 0x1bcd2a (0x5c) / C1 0x1bcd86, **D1** 0x1bd8e8 (0x6d) / **D0** 0x1bd956(0x71);无 D2 独立符号(D1 即主体)

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* (0x457278) | ctor `*this = &unk_457278` (I 0x1bcd3a) |
| 0x04 | m_friends | std::list<ull> (8B) | ctor 自引用 +0x4/+0x8 (I 0x1bcd4d);D1 遍历释放节点 (I 0x1bd934);IsFriendPlayingOnServer 节点 {next@0, prev@4, steamID ull@8} (G 0x1bcec7..0x1bced9) |
| 0x0C | m_clans | std::list<ull> (8B) | ctor 自引用 +0xC/+0x10 (I 0x1bcd64);D1 释放 (I 0x1bd91d) |
| 0x14 | m_clanMembers | std::list<ull> (8B) | ctor 自引用 +0x14/+0x18 (I 0x1bcd7b);D1 释放 (I 0x1bd903) |
| 0x1C | bField_0x1C | byte =1 | ctor (I 0x1bcd81) |

- 方法:IsFriend 0x1bcde2 / IsFriendPlayingOnServer 0x1bce48(+0x1C 端口重载 0x1bd2c6)/ LoadSteamInfoCache 0x1bcf38 / BelongsToClan 0x1bd3fa / ClearCachedInfo 0x1bd452 / ServerSupportsFriendsOnly 0x1bd9c8
- **回写建议**: 新建 — 大小 0x20;3×std::list<ull>(8B 头,节点 16B)

---

## 15. cSteamRichPresence — 待恢复(≥84B, 0x54)

- **vtable**: 0x457618
- **C2** 0x1c0b9a (0x9a) / C1 0x1c0c34, **D1** 0x1c1cd0 (0x5b) / **D0** 0x1c1d2c(0x77)

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* (0x457618) | ctor `*this = &unk_457618` (I 0x1c0baf) |
| 0x04 | m_presence | std::map<std::string,std::string> (20B) | ctor 头初始化 +0x8..+0x18 (I 0x1c0bc2..0x1c0bda);dtor `_Rb_tree<string,pair<const string,string>>::_M_erase(this+0x4, *(this+0xC))` (I 0x1c1d01);SetValue/ClearValue 0x1c1bd0/0x1c1c06 |
| 0x1C | bField_0x1C | byte =0 | ctor (I 0x1c0bdd) |
| 0x20 | m_serverNetId | cNetID2 (44B) | ctor `cNetID2::Clear(this+0x20)` + +0x44/+0x48 清零 (I 0x1c0be4..0x1c0bf5);SetCurrentServerNetId 0x1c17b6 |
| 0x4C | m_connectString | std::string | ctor `=&empty` (I 0x1c0c03);dtor 销毁 (I 0x1c1ce6);UpdateConnectionString 0x1c0dce 构建 |
| 0x52 | bField_0x52 | byte =0 | ctor (I 0x1c0c06) |

- 方法:Update 0x1c0c3a / ClearCurrentServerInfo 0x1c0d7e / UpdateConnectionString 0x1c0dce / UpdateServerInfo 0x1c10ee / SetCurrentServerAddress 0x1c1808 / GetFriendCurrentServerIP 0x1c1866 / GetFriendCurrentServerPort 0x1c18be / GetFriendCurrentServerSteamId 0x1c1a14
- **回写建议**: 新建 — 大小 ≥0x54;map<string,string> 头部 20B,cNetID2 引用既有类型

---

## 回写建议汇总表

| 类型名 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| cNetworkConnection | 新建 | 0x2A4 (676B) | AllocConnection 0x189a92 `new(0x2A4)`;基类 Connection_RM3(Tier 4);游戏仅 +0x2A0 |
| cNetworkReplica | 新建 | 0x164 (356B) | 两个子类 ctor 内联基类初始化;+0x158..+0x161 四字段;Replica3 基类 Tier 4 |
| cNetworkRPCManager | 新建 | 0x14 (20B) | ctor 0x180258 / dtor 0x18496e;pRPC4+pBitStream+29 槽名数组;无 vtable |
| cNetworkTileRegion | 新建 | 0x184 (388B) | ctor 0x18bb16 / dtor 0x18bd00;pNetworkManager+TileGrid+MapComponent+512B tile 缓冲 |
| cNetworkVoiceManager | 新建 | 0x14 (20B) | ctor 0x18d9d2 / dtor 0x18da50;BitStream + list<string> |
| cNetworkClientObject2 | 新建 | ≥0x220 (544B) | ctor 0x162dea / dtor 0x16305a;RakNetGUID@0x164、连接掩码@0x170、cPlayerListingData@0x17C、Timer@0x1FC、netstats 缓冲@0x208 |
| cNetworkFileTransferCB | 新建 | 0x4 (4B) | 仅 vtable 0x456F88;D0 0x1657be 仅 delete;方法零字段访问 |
| cPendingConnection | 新建 | 0x70 (112B) | ctor 0x1995d6 / dtor 0x1998ca;状态机 6 态@+0;string+GUID+cNetID2+tServerListing*;无 vtable |
| cNatTraversal | 重建(写回 tier3-d 结论) | ≥0x198 (408B) | ctor 0x161b7a;游戏部分 8B @ +0x190(调试接口子对象+int 5);基类 NatPunchthroughClient Tier 4 |
| cNatTraversal::cNatPunchthroughDebugInterfaceImpl | 新建 | 0x4 (4B) | vtable 0x462738;OnClientMessage 0x16225a 仅日志 |
| cSteamAccountCommunication | 新建 | 0x11C (284B) | ctor 0x1bbb5c / dtor 0x1bc2ac;`new(0x11C)` 铁证;增量 +0x58:3×CCallback + 票证缓冲;基类 cAccountCommunication(已存在) |
| cSteamPunchthrough | 新建 | ≥0x46 (70B) | ctor 0x1bdafa / dtor 0x1bdc32;基类 Lobby2 Tier 4;CCallResult@0xC;+0x38 pPlugin 惰性 new(0xC4);+0x3D bIsSteamGameServer |
| cSteamPunchthroughPlugin | 新建 | 0xC4 (196B) | ctor 0x1beae6 / dtor 0x1bedc2;`new(0xC4)` 铁证;5×map(2×Timer 值);PluginInterface2 多继承 Tier 4 |
| cSteamFriendsManager | 新建 | 0x20 (32B) | ctor 0x1bcd2a / D1 0x1bd8e8;3×list<ull>;+0x1C byte=1 |
| cSteamRichPresence | 新建 | ≥0x54 (84B) | ctor 0x1c0b9a / D1 0x1c1cd0;map<string,string>@0x04 + cNetID2@0x20 + string@0x4C |

## 方法/注意事项

1. **基类策略**:Connection_RM3(0x2A0)、Replica3(0x158)、NatPunchthroughClient(0x190)、Lobby2(8B)、PluginInterface2、FileListTransferCBInterface、NatPunchthroughDebugInterface 一律 Tier 4 跳过,只建游戏自有偏移(报告均给出基类长度锚点,便于回写时标 Tier 4)。
2. **std::map 头**(本分片全部 20B):对象基址 X(4B allocator/pad) + header@X+4 {color@+4, parent@+8, left@+12=&self, right@+16=&self, count@+20};dtor `_M_erase(X, *(this+X+8))` 给出精确根指针偏移。
3. **CCallback = 24B**(vtable@0, pObj@4, fn@8, flag@+4);**CCallResult = 32B**(vtable@0, flag@4, cbId@8, hAPICall@0xC(8B), pObj@0x14, fn@0x18)。
4. **std::string = 4B** 旧 ABI(数据指针,length/cap 在 _Rep);**cNetID2 = 44B**(type@0, 十六进制串@4, 原始 uint64 steamID@0x24);**RakNetGUID = 12B**(systemIndex+g, 本分片 ctor 拷 12B);**Timer = 8B**。
5. 状态枚举:cPendingConnection eState {1=NewRequest, 2=Connecting, 3=WaitingForToken, 4=WaitingForPingResponse, 5=WaitingForLua, 6=ConnectionComplete}(小方法反汇编逐一定值)。
6. cNetworkClientObject2 的 cPlayerListingData(+0x17C)为内嵌子对象(含 string@+0、colour@+0x3C=0x1B8、堆指针@+0x70=0x1EC),完整字段表见 tier3-d 报告,建议单独建类型后引用。
