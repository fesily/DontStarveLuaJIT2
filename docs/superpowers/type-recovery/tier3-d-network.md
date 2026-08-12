# Tier 3-D — Networking / Steam 子系统类型恢复报告

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp (G) + idalib-mcp (I, 会话 f9cdc808, 健康)
> 方法:ctor/dtor 反编译 + 关键方法字段访问验证 + 静态初始化表 xref
> 关键洞见:**本二进制 `std::string` 是旧 ABI,仅 4 字节**(对象内只存数据指针,length/capacity/refcount 在 `_Rep` 中)。dtor 逐成员 `_M_destroy` 的字符串指针间距即 4 字节。
> 容器判定规则:ctor 写 `*(X+8) = &this+X; *(X+12) = &this+X` 且 `X..X+4` 清零 → **std::map**(header@X, left/right 自引用);写 `*X = &this+X; *(X+4) = &this+X` → **std::list**。

---

## 1. cShardManager — 完成 ✓(168B, 0xA8)

- **ctor** 0x1a2e44 (C2, 0x8ab), D1 0x1ab06e / D0 0x1ab074, dtor 0x1aada6 (G)
- **vtable**: 0x45719C (16B: [~D1 0x1ab06e, ~D0 0x1ab074, 0, 0])
- 单例:`Util::cSingleton<cShardManager>::mInstance` @ 0x45db68;静态 `packetHandlers` map @ 0x470368(ctor 注册约 40 个 Handle*Packet 成员指针)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | ctor `*this = &unk_45719C` (0x1a2e67) |
| 0x04 | eShardType | int | RegisterSlave: `if (*(cShardManager::mInstance+4) == 3)` 才走 slave 注册 (I 0x1a0f00) |
| 0x08 | nField_0x08 | int =0 | ctor |
| 0x0C | nField_0x0C | int =0 | ctor |
| 0x10 | bField_0x10 | byte =0 | ctor `*(this+16)=0` |
| 0x14 | str_0x14 (m_clusterName?) | std::string | ctor `*(this+0x14)=&empty`;dtor `_M_destroy(*(this+0x14))` (G 0x1aada6) |
| 0x18 | m_shardId | uint | RegisterSlave: `_M_insert<unsigned long>(ss, *(shardMgr+0x18))` → json "id" (I 0x1a0f28) |
| 0x1C | nField_0x1C | int =0 | ctor |
| 0x20 | nField_0x20 | int =0 | ctor |
| 0x24 | str_0x24 (m_worldSessionName?) | std::string | ctor `=&empty`;dtor 销毁 (G) |
| 0x28 | m_shardPlayers | std::map<std::string, cClusterPlayer*> | GetPlayerFromId: `find(this+0x28, key)` (I 0x1ab9fa);dtor `_M_erase(this+0x28)` (G);header@0x2C (ctor left/right 自引用 0x34/0x38) |
| 0x40 | nField_0x40 | int =1 | ctor |
| 0x44 | m_incomingMigrations | std::map<std::string, IncomingMigrationInfo> | dtor `_M_erase(this+0x44)` (G);header@0x48 (ctor 自引用 0x50/0x54) |
| 0x5C | bField_0x5C | byte =0 | ctor |
| 0x60 | m_restartMigrations | std::map<RakNet::RakNetGUID, RestartMigrationInfo> | dtor `_M_erase(this+0x60)` (G);header@0x64 (ctor 自引用 0x6C/0x70) |
| 0x78 | flReconnectInterval | float =60.0f | ctor `*(this+0x78) = 1114636288` (0x42700000) |
| 0x7C | Timer_1 | Timer (8B) | ctor `Timer::Timer(this+0x7C)`;Timer ctor 写 8B mach_absolute_time (I 0x2747c8) |
| 0x84 | UNKNOWN_0x84 | int (未初始化) | ctor 未写 |
| 0x88 | Timer_2 | Timer (8B) | ctor `Timer::Timer(this+0x88)` |
| 0x90 | m_strList | std::list<std::string> | ctor 自引用 +0x90/+0x94;dtor `_List_base<std::string>::_M_clear` (G) |
| 0x98 | bField_0x98 / bField_0x99 | 2×byte =0 | ctor |
| 0x9C | pCheshireCat | cShardManager::tCheshireCat* | ctor `= operator new(0x40)`;dtor 释放 (G) |
| 0xA0 | pField_0xA0 | void* (带 vtable 对象) | dtor `(*(*p+4))(p)` 虚删除 (G);ctor 置 0 |
| 0xA4 | pShardBroadcast | cShardBroadcast* | ctor `= operator new(4); cShardBroadcast::cShardBroadcast`;dtor 删除 (G) |

**tCheshireCat (64B, 0x40)** — ctor 0x1b49ae (G):

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | RakNetGUID | RakNet::RakNetGUID (8B) | ctor `RakNetGUID::RakNetGUID(this)` |
| 0x0C | SystemAddress | RakNet::SystemAddress (24B) | ctor `SystemAddress::SystemAddress(this+0xC)` |
| 0x24 | str_0x24 | std::string | ctor `=&empty`;cShardManager dtor `_M_destroy(*(pCat+0x24))` (G) |
| 0x28 | m_shardSlaves | std::map<uint, SlaveInfo*> | GetSlaveFromId: `find(pCat+0x28, id)`;node+20 取值 (I 0x1ab8ce);dtor `_M_erase(pCat+0x28)` (G);header@0x2C |

> 注:+0x28 处的 slave map 在 pimpl 内,不在 cShardManager 本体。

---

## 2. cShardBroadcast — 完成 ✓(4B)

- **ctor** 0x1a0e3a / 0x1a0e50 (C1), dtor 0x1a0e66 — 均只处理首字段
- **无 vtable**(首字段为 string,ctor 写 `*this = &_S_empty_rep_storage+12`)
- **大小铁证**:cShardManager ctor 中 `v4 = operator new(4); cShardBroadcast(v4)` (I 0x1a2fd3)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | str_0x00 | std::string | ctor `*(this) = &empty`;dtor `_M_destroy(*(this))` (I 0x1a0e66) |

> RegisterSlave (0x1a0ee4) 只读全局(cShardManager 单例、cAccountManager+0x1C 作 "__token"、cNetworkManager+0x88 作 "port"、cMasterServer 地址),无成员偏移;成员数 = 1 仅由分配大小 4B 保证。

---

## 3. cNatTraversal — 部分 ✓(RakNet 基类 Tier 4,游戏部分 8B @ +0x190)

- **ctor** 0x161b7a, D1 0x161be2 / D0 0x161be8
- 结构:`cNatTraversal : RakNet::NatPunchthroughClient`(基类 ctor 0x2197f4 先调用)
- 构造地址被静态初始化表引用(0x4f20ff [DATA])→ 全局/静态对象

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00..0x18F | RakNet::NatPunchthroughClient 基类 | — | **Tier 4 跳过**;ctor `NatPunchthroughClient(this)` (I 0x161b8c) |
| 0x190 | cNatPunchthroughDebugInterfaceImpl | 子对象(vtable 0x462738) | ctor `*(this+0x190) = &unk_462738` (I 0x161ba0) |
| 0x194 | nField_0x194 | int =5 | ctor `*(this+0x194) = 5` (I 0x161ba6) |

- 方法:OpenUPNP (0x161fb8) 经 cNetworkManager+0xE0 拿 socket → gNatTraversal 全局 (0x46f4dc);NewPeer (0x16211a) 调 `RakPeerInterface::vtable[70]` 注册自身。无新增字段。
- 调试接口 vtable 0x462738 → ~cNatPunchthroughDebugInterfaceImpl (0x162254/0x162240) + OnClientMessage (0x16225a),游戏自有。

---

## 4. cAccountManager — 完成 ✓(80B, 0x50)

- **ctor** 0x146ff6 (0x4ba), dtor 0x147cc8, D1 0x148288 / D0 0x14828e
- **vtable**: 0x456DFC (槽2 指向 0x46e47c,不可读,标 UNKNOWN)
- 单例 mInstance @ 0x45db60

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | ctor `*this = &off_456DFC` |
| 0x04 | bField_0x04 | byte =0 | ctor |
| 0x08 | str_0x08 | std::string | ctor `string(this+8,"")`;dtor 销毁 |
| 0x0C | tAuthenticated | 子结构 (16B) | ctor `tAuthenticated(this+0xC)` |
| 0x0C..0x18 | 4×std::string | — | tAuthenticated ctor 0x149396: string@+0/+4/+8/+0xC (G) |
| 0x1C | m_authToken | std::string | ctor `*(this+0x1C)=&empty`;**RegisterSlave**: `json_string(*(accMgr+0x1C))` → "__token" (I 0x1a0f66) |
| 0x20 | m_username | std::string | SetUsername: `string::assign(this+0x20, s)` (I 0x14866a) |
| 0x24 | str_0x24 (m_password?) | std::string | ctor `string(this+0x24,"")` |
| 0x28 | str_0x28 | std::string | ctor `string(this+0x28,"")` |
| 0x2C | str_0x2C | std::string | ctor `string(this+0x2C,"")` |
| 0x30 | nField_0x30 | int =0 | ctor |
| 0x34 | str_0x34 | std::string | ctor `*(this+0x34)=&empty` |
| 0x38 | pCommunication | cSteamAccountCommunication* | ctor `= operator new(0x11C); cSteamAccountCommunication`;dtor 虚删除 (I 0x147cef) |
| 0x3C | nField_0x3C | int =0 | ctor |
| 0x40 | bField_0x40 | byte =1 | ctor `this[0x40]=1` |
| 0x41..0x43 | 3×byte =0 | — | ctor |
| 0x44 | str_0x44 | std::string | ctor `=&empty`;dtor 销毁 |
| 0x48 | str_0x48 | std::string | ctor `=&empty`;dtor 销毁 |
| 0x4C | m_offlineUserId | std::string | ctor `assign("OU_") + append(SteamUser id)` (I 0x147123..0x147158) |

- tAuthenticated ctor (0x149396, G): 4 个字符串 @ +0/+4/+8/+0xC(共 16B,字段名低置信:accountId/authToken/username/sessionToken)。

---

## 5. cTwitchManager — 完成 ✓(40B, 0x28)

- **ctor** 0xb9f8c (0x2c2), dtor 0xba6ea, D1 0xba930 / D0 0xba936
- **vtable**: 0x4562F8 (16B: [D1, D0, 0, 0])
- 单例 mInstance @ 0x45db54

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | ctor `*this = &off_4562F8` |
| 0x04 | pCheshireCat | tCheshireCat* (0x588) | ctor `= operator new(0x588)`;dtor 删 (G 0xba738) |
| 0x08 | bTVInitialized | int | dtor: `if (*(this+8)) { TTV_Chat_Shutdown; TTV_Shutdown; }` (G 0xba70b) |
| 0x0C | Timer | Timer (8B) | ctor `Timer::Timer(this+0xC)` (G 0xb9fc6) |
| 0x14 | bDeferredInit | byte | ctor 置 0;`if (*(this+0x14)) DeferredInitialize()` (G 0xba1bc) |
| 0x18 | m_username | std::string | GetUserName: `string::string(&ret, this+0x18)` (I 0xbb926);ctor `string(this+0x18,"")` |
| 0x1C | bField_0x1C | byte =1 | ctor `this[0x1C]=1` |
| 0x20 | nField_0x20 | int =0 | ctor |
| 0x24 | m_channelName | std::string | ctor `string(this+0x24,"")`;dtor 销毁 (G 0xba755) |

- tCheshireCat (0x588): TwitchAuthThread 子对象 @ +0x4C0 (ctor 0xb85c4,0x2a0);6 个 Chat*Callback 函数指针 @ +0x4A4..+0x4BC (v3[297..303],G ctor);TTV lib (Tier 4)。

---

## 6. SteamWorkshop — 完成 ✓(456B, 0x1C8)

- **ctor** 0x261cae (0x684), dtor 0x262338, D1 0x262826 / D0 0x26282c
- **vtable**: 0x45B9E8;单例 mInstance @ 0x45d9b0
- CCallResult 对象 = 32B:{ vtable@+0, flags@+4, cbId@+8, hAPICall(8B)@+0xC, pObj@+0x14, fn@+0x18 }(dtor `SteamAPI_UnregisterCallResult(this+X, *(X+0xC), *(X+0x10))`)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | ctor `*this = &unk_45B9E8` |
| 0x04..0x1B | 7×dword =0 | — | ctor |
| 0x1C | vector_1 | std::vector<UNKNOWN> (12B) | dtor `if (*(this+0x1C)) delete` (G 0x262338) |
| 0x28 | vector_2 | std::vector<UNKNOWN> (12B) | dtor `if (*(this+0x2C)) delete` |
| 0x34 | nField_0x34 | int =0 | ctor |
| 0x38 | nField_0x38 | int =0 | ctor |
| 0x3C | m_modVersions | std::vector<tModnameVersion> (12B) | dtor `vector<tModnameVersion>::~vector(this+0x3C)` |
| 0x48 | nField_0x48 | int =0 | ctor |
| 0x4C | CCallResult #1 (cb 1318 GetPublishedFileDetails) | 32B | ctor vtable 0x463CC8@+0x4C, cbId 1318@+0x54;dtor 注销 |
| 0x6C | CCallResult #2 (cb 1317 EnumerateSubscribedFiles) | 32B | vtable 0x463CA8@+0x6C, cbId 1317@+0x74 |
| 0x8C | CCallResult #3 (cb 1318, temp mods) | 32B | vtable 0x463CC8@+0x8C, cbId 1318@+0x94 |
| 0xAC | CCallResult #4 (cb 1314 DownloadUGC) | 32B | vtable 0x463C88@+0xAC, cbId 1314@+0xB4 |
| 0xD0 | vector_3 | std::vector<UNKNOWN> (12B) | dtor `if (*(this+0xD0)) delete` |
| 0xDC | vector_4 | std::vector<UNKNOWN> (12B) | dtor `if (*(this+0xDC)) delete` |
| 0xE8 | vector_5 | std::vector<UNKNOWN> (12B) | dtor `if (*(this+0xE8)) delete` |
| 0xF4 | vector_6 | std::vector<UNKNOWN> (12B) | dtor `if (*(this+0xF4)) delete` |
| 0x100 | m_tempMods | std::deque<unsigned long long> (40B) | ctor `_Deque_base<ull>::_M_initialize_map(this+0x100,0)`;dtor ~_Deque_base |
| 0x128 | nField_0x128 / nField_0x12C | 2×int =0 | ctor |
| 0x130 | CCallResult #5 (cb 1318, version check) | 32B | vtable 0x463CA8@+0x130, cbId 1318@+0x138 |
| 0x150 | CCallResult #6 (cb 1317) | 32B | vtable 0x463CC8@+0x150, cbId 1317@+0x158 |
| 0x170 | m_list | std::list<UNKNOWN> (8B) | ctor 自引用 +0x170/+0x174;dtor 遍历 node 释放 (G) |
| 0x178 | Mutex | 56B | ctor/dtor `Mutex::Mutex/Dtor` (G) |
| 0x1B4 | m_workshopModData | std::map<unsigned long long, WorkshopModData> | dtor `_M_erase(this+0x1B4)` (G);header@0x1B8 |

> cbId 1314=RemoteStorageDownloadUGCResult、1317=EnumerateUserSubscribedFilesResult、1318=GetPublishedFileDetailsResult(Steam API k_iCallback)。

---

## 7. LuaHttpQuery — 完成 ✓(32B, 0x20)

- **无独立 ctor**(构造内联于 Startup @ 0x98cf,vtable xref 证据 G);dtor 0xacb8, D0 0xace6
- **vtable**: 0x45D9E8 (16B: [D1, D0, 0, 0])

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | dtor `*this = &unk_45D9E8` |
| 0x04 | m_requests | std::map<unsigned long, RequestInfo> | dtor `_M_erase(this+4, *(this+0xC))` (I 0xacdd);Submit: `map::operator[](this+4)`;CompleteRequest: `find(this+4)` end=this+8 (I 0xe2e7c) |
| 0x18 | m_pendingCount | uint | CompleteRequest 命中后 `--*(this+0x18)` (I 0xe2eae) |
| 0x1C | m_requestCounter | ulong | Submit: `v=*(this+0x1C); *(this+0x1C)=v+1;` 作 key (I 0xe30bd) |

**RequestInfo (8B)**: `{ +0 cSimulation* pSimulation; +4 int uid; }` — Submit 写 v[0]=sim, v[1]=uid;CompleteRequest 读 node+20=sim、node+24=uid (I 0xe2e93/e2e98)。

---

## 8. CurlRequest — 完成 ✓(≥0x36, 约 54B)

- **ctor** 0x1bb536 `(uint id, const HttpRequest2&, void* pMulti)`, dtor 0x1bb3de
- **无 vtable**

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | m_id | uint | ctor `*(this) = id` (G 0x1bb54f) |
| 0x04 | m_url | std::string | ctor `string(this+4, HttpRequest2+0)` (G) |
| 0x08 | m_postData | std::string | ctor `string(this+8, HttpRequest2+4)` (G) |
| 0x0C | m_authToken? | uint64 | ctor `*(uint64)(this+0xC) = *(uint64)(req+8)` (G) |
| 0x14 | nField_0x14 | uint32 | ctor 自 req+0x10 复制 |
| 0x18 | wField_0x18 | uint16 | ctor 自 req+0x14 复制 |
| 0x1C | pCurlMulti | CURLM* | dtor `curl_multi_remove_handle(*(this+0x1C), *(this+0x20))` (G 0x1bb3de);ctor 参数 3 |
| 0x20 | pCurlEasy | CURL* | dtor `curl_easy_cleanup(*(this+0x20))`;SetupCurlHandle 0x1bb68c 设置 |
| 0x24 | pCurlSlist | curl_slist* | dtor `curl_slist_free_all(*(this+0x24))` |
| 0x28 | wField_0x28 / bField_0x2A | uint16+byte =0 | ctor |
| 0x2C | m_response | std::string | ctor `=&empty`;dtor 销毁;CurlWriteCallback 0x1bba86 追加 |
| 0x30 | nField_0x30 | uint32 =0 | ctor |
| 0x34 | wField_0x34 | uint16 =0 | ctor |

---

## 9. CurlRequestManager — 完成 ✓(8B)+ ClientThread (292B, 0x124)

- **ctor** 0x1b8354, dtor 0x1b83b2, D1 0x1b83fa / D0 0x1b8400;**vtable** 0x4571C8
- 单例:GetURL 单例内持有(GetURL::mInstance @ 0x45d9bc)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | ctor `*this = &unk_4571C8` |
| 0x04 | pClientThread | ClientThread* (0x124) | ctor `= operator new(0x124); ClientThread ctor; Thread::Start` (I 0x1b8375) |

**ClientThread** — ctor 0x1b86f4, dtor 0x1b88f6;**vtable** 0x4571E8:

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | Thread 基类 | Thread (含 name "GAClient") | ctor `Thread::Thread(this, "GAClient", 0, 1)` (I 0x1b873a) |
| 0x78 | bField_0x78 | byte =1 | ctor `*(this+0x78)=1` |
| 0x7C | Mutex_1 | 56B | ctor `Mutex::Mutex` (I 0x1b8764) |
| 0xB4 | nField_0xB4 | int =0 | ctor |
| 0xB8 | nField_0xB8 | int =0 | ctor |
| 0xBC | nField_0xBC | int =0 | ctor |
| 0xC0 | nField_0xC0 | int =1 | ctor |
| 0xC4 | pCurlMulti | CURLM* | ctor `= curl_multi_init()` (I 0x1b8811) |
| 0xC8 | Mutex_2 | 56B | ctor `Mutex::Mutex` (I 0x1b87aa) |
| 0x104 | m_requests | std::map<unsigned int, CurlRequest*> | ctor 自引用 +0x108/+0x10C = &this+0x104 (I 0x1b87e7);对应 `map<uint,CurlRequest*>::operator[]` (0x1b9954) |
| 0x118 | nField_0x118 / 0x11C / 0x120 | 3×int =0 | ctor(队列计数,UNKNOWN) |

---

## 10. GetURL — 完成 ✓(8B)

- **ctor** 0x1b81ea, dtor 0x1b824e, D1 0x1b829a / D0 0x1b82a0;**vtable** 0x4571AC
- 单例 mInstance @ 0x45d9bc(与 CurlRequestManager 同源)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | ctor `*this = &PTR__GetURL_004571ac` (G) |
| 0x04 | pHttpClient2 | HttpClient2* | ctor `= operator new(4); HttpClient2::HttpClient2` (G 0x1b81f8) |

---

## 11. cCachedPingResults — 完成 ✓(44B, 0x2C)

- **ctor** 0x14949c, dtor 0x149584;**无 vtable**(ctor 不写 +0)
- 构造经静态初始化表 0x4f1eb4 [DATA] 引用 → 全局对象

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | nField_0x00 | int (ctor 未写,非 vtable) | dtor `_M_erase(this, *(this+8))` 树基 +0 |
| 0x04 | m_cachedPings | std::map<unsigned int, unsigned short> | ctor 自引用 +0xC/+0x10 = &this+4 (I 0x1494d2);dtor `_M_erase` 值类型 ushort (I 0x1495b4) |
| 0x14 | nField_0x14 | int =0 | ctor |
| 0x18 | m_hashCache | std::vector<unsigned int> (12B) | ctor `vector<uint>::reserve(this+0x18, size)` (I 0x14954a) |
| 0x24 | bDirty | byte | dtor `if (*(this+0x24)) SaveCached()` (I 0x14958d) |
| 0x28 | m_cachedPingSize | int =5000 | ctor 读 SettingFile "cached_ping_size" 默认 5000 (I 0x149540) |

---

## 12. cGiftingManager — 完成 ✓(160B, 0xA0)

- **ctor** 0x14c2ca, dtor 0x14c3ca, D1 0x14c492 / D0 0x14c498;**vtable** 0x456E38
- 单例 mInstance @ 0x462618

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | ctor `*this = &unk_456E38` |
| 0x04 | nField_0x04 | int =0 | ctor |
| 0x08 | m_listA | std::list<UNKNOWN(平凡元素)> | ctor 自引用 +8/+0xC;dtor 手工遍历 node `operator delete` 释放 (G 0x14c415) |
| 0x10 | Mutex_1 | 56B | ctor/dtor `Mutex::Mutex/Dtor` (I 0x14c313) |
| 0x48 | m_giftItems | std::map<std::string, std::list<GiftItemStruct>> | dtor `_M_erase(this+0x48)`(类型见 mangling,G 0x14c405);ctor 自引用 +0x54/+0x58 = &this+0x4C |
| 0x60 | m_unverifiedReceipts | std::list<UnverifiedReceiptStruct> | dtor `_List_base<UnverifiedReceiptStruct>::_M_clear(this+0x60)` (G 0x14c3f3);ctor 自引用 +0x60/+0x64 |
| 0x68 | Mutex_2 | 56B | ctor 末 `Mutex::Mutex` (I 0x14c361) |

> map 树基 +0x48/header@+0x4C(list 值节点含 string,ctor 自引用写 +0x54/+0x58)。

---

## 13. DontStarveGameService — 完成 ✓(36B, 0x24)

- **ctor** 0x1a3b2 `(DontStarveSystemService*)`, dtor 0x1a47c, D1 0x1a4da / D0 0x1a4e0
- **vtable**: 0x4549E0(起始槽 [~DGS 0x1a4da, ~DGS 0x1a4e0, 0×4(纯虚位)];之后内存与相邻类 vtable 共享,槽位归属低置信)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | ctor `*this = &PTR__DontStarveGameService_004549e0` |
| 0x04 | pSystemService | DontStarveSystemService* | ctor 参数 1 直存 |
| 0x08 | nField_0x08 | int =0 | ctor;dtor 置 0 |
| 0x0C | nField_0x0C | int =0 | ctor;dtor 置 0 |
| 0x10 | m_achievements | std::map<cHashedString, GameService::AchievementId> | dtor `_M_erase(this+0x10)` (G 0x1a47c);ctor 自引用 +0x1C/+0x20 = &this+0x14 → header@+0x14 |

---

## 14. DontStarveSystemService — 完成 ✓(164B, 0xA4)

- **ctor** 0x24116, dtor 0x24d8e, D1 0x24df0 / D0 0x24df6
- **vtable**: 0x454A28(起始槽 [~DSS 0x24df0, ~DSS 0x24df6, 0, 0];后接相邻类 vtable)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | ctor `*this = &PTR__DontStarveSystemService_00454a28` |
| 0x04 | nField_0x04 | int =0 | ctor;dtor 置 0 |
| 0x08 | nField_0x08 | int =0 | ctor;dtor 置 0 |
| 0x0C | pCacheMap | std::map<cHashedString, MemoryCache::CacheItem>* (堆 0x18) | ctor `new(0x18)` map@+4;dtor `_M_erase` + delete (G 0x24d8e) |
| 0x10 | m_playerId | GameService::PlayerId (36B) | ctor `PlayerId::PlayerId(this+0x10)`;PlayerId ctor 清零 9 dword (G 0x1c21ce) |
| 0x34 | 4×bool | ={0,1,1,1} | ctor `*(this+0x34)=0x1010100` |
| 0x38 | nField_0x38 | int =4 | ctor(GetLastOperation 0x23d10 读取区) |
| 0x3C | nField_0x3C | int =7 | ctor(GetLastStatus 0x23d18 读取区) |
| 0x40..0x93 | 7×回调项 | {obj=this, fn, 0} 各 12B | ctor: OnStoragePrepared@+0x44/Overwritten@+0x50/FileLoaded@+0x5C/FileSaved@+0x68/FileDeleted@+0x74/FileChecked@+0x80/CacheFileSynchronized@+0x8C,obj 在 +0x40/0x4C/0x58/0x64/0x70/0x7C/0x88 (G) |
| 0x94..0xA0 | 4×int = -2 | — | ctor 各 0xFFFFFFFE;dtor 恢复默认 (G) |

---

## 15. GameService / SystemService — 接口类 ✓(无数据成员)

- **无 ctor/dtor**(纯抽象基类);**无自有 vtable 主体**(多态接口并入子类)
- GameService 方法(非虚,直接调用):Initialize 0x1c1e5a / Finalize 0x1c1eb8 / Update 0x1c1eec / Register 0x1c1f0b / RecordAchievement 0x1c1fd0 / IsEnabled 0x1c211f / IsSignedIn 0x1c2145 / GetPlayerInfo 0x1c21a1;嵌套类型 PlayerId(36B, ctor 0x1c21ce)、AchievementId、PlayerInfo、Request、RegisterRequest、RegisterResult ctor 位于 0x1c21ce..0x1c2fac
- SystemService 方法 stub(非虚,return 0):Initialize 0x1c3d40 / Finalize 0x1c3d43 / PrepareStorage 0x1c3d46 / LoadFile 0x1c3d47 / SaveFile 0x1c3d48 / DeleteFile 0x1c3d49 / CheckFile 0x1c3d4a / SetStalling 0x1c3d4b(G 反编译确认各为 1-3 字节空实现)
- **回写建议**:以 DontStarveGameService (36B) / DontStarveSystemService (164B) 为具体布局,GameService/SystemService 建成空接口(仅 4B vtable 占位或跳过)

---

## 16. cAccountCommunication — 完成 ✓(196B, 0xC4)

- **ctor** 0x142070 `(cAccountManager*)`, dtor 0x142302, D1 0x1424c6 / D0 0x1424cc
- **vtable**: 0x456D68
- 子类:cSteamAccountCommunication (ctor 0x1bbb5c,0x1c8 字节,在 cAccountManager ctor 中 `new(0x11C)` 构造)→ 基类 + 附加字段,见 cAccountManager +0x38

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | ctor `*this = &PTR__cAccountCommunication_00456d68` |
| 0x04 | m_netId | cNetID2 (44B) | ctor `cNetID2::Clear(this+4)`;cNetID2::Clear 清零 +0..+0x28 (G 0x1623a2) |
| 0x30 | bField_0x30 | byte =0 | ctor |
| 0x34..0x40 | 4×std::string | — | ctor `string(this+0x34/0x38/0x3C/0x40,"")`;dtor 销毁 (G 0x142302) |
| 0x44 | nField_0x44 | int =0 | ctor |
| 0x48 | Mutex | 56B | ctor/dtor `Mutex::Mutex/Dtor` (G) |
| 0x80 | m_accountEvents | std::deque<AccountEvent> (40B) | ctor `deque<AccountEvent>::deque(this+0x80)`;dtor ~deque (G) |
| 0xA8 | pAccountManager | cAccountManager* | ctor 参数 1 直存 |
| 0xAC | nField_0xAC | int =0 | ctor |
| 0xB0 | nField_0xB0 | int =0 | ctor |
| 0xB4 | nField_0xB4 | int =0 | ctor |
| 0xB8 | Timer | Timer (8B) | ctor `Timer::Timer(this+0xB8)` |
| 0xC0 | bField_0xC0 | byte =0 | ctor |

---

## 17. DatagramHeaderFormat — 完成 ✓(15B, 0x0F)

- **无 ctor/dtor/vtable**(纯数据 POD);Serialize 0x243bca / Deserialize 0x242cfc (G)
- 序列化:BitStream 写 1 bit(hasFullHeader@+8)→ 分支写 5 bits(标志@+9/+0xA/+0xC/+0xD 等)→ 24 bit(值 @ +0..+2)→ 32 bit(@ +4)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | n24_0x00 | 3 bytes (24-bit 头值) | Serialize 写 `this[0..2]` 24 bits;Deserialize 读 3 bytes 回填 (G 0x243bca) |
| 0x04 | n32_0x04 | uint32 | Serialize/Deserialize 读写 32 bits(网络序交换,ReverseBytes) |
| 0x08 | bFullHeader | byte | Serialize 首分支 `if (this[8]==0)`;Deserialize 位读回填 |
| 0x09 | b_0x09 | byte | Serialize `if (this[9]==0)` 分支 |
| 0x0A | b_0x0A | byte | Serialize `if (this[10]==0)` Write0/1 |
| 0x0B | b_0x0B | byte | Serialize 第二分支 `if (this[0xB]==0)` |
| 0x0C | b_0x0C | byte | Serialize `if (this[0xC]==0)` |
| 0x0D | b_0x0D | byte | Serialize `if (this[0xD]==0)` |
| 0x0E | b_0x0E | byte | Deserialize 首位读入 `this[0xE]` (G 0x242cfc) |

> 语义低置信:疑为游戏侧自定义 datagram header(RNS2 socket 层),字段名 UNKNOWN。

---

## 18. Socket — 完成 ✓(28B, 0x1C)

- **ctor** 0x1b6fea, dtor 0x1b7032;**无 vtable**
- 平台封装(非 RakNet socket,Tier 4 的 RakNet::RNS2_* 另行跳过)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | m_fd | int | ctor =0;TCPConnect `socket(...)` → `*(this)=fd` (G 0x1b7086);dtor `if (*(this)) shutdown(fd,2)` |
| 0x04 | m_lastError | int | TCPConnect 置 errno / SetBlockingMode 结果 (G 0x1b71a9) |
| 0x08 | nField_0x08 | int =0 | ctor |
| 0x0C | nField_0x0C | int =0 | ctor |
| 0x10 | UNKNOWN_0x10 | 8B (ctor 未写) | — |
| 0x18 | bBlocking | byte =1 | ctor `*(this+0x18)=1`;TCPConnect `SetBlockingMode(this, *(this+0x18))` |

---

## 19. NodeAddress — 完成 ✓(12B)

- **ctor** 0xc51f4 `(const char*)`;**无 vtable**
- 动画/场景图节点路径地址(SceneGraphNode::GetChild(NodeAddress) 0xc5898;StripHead 0xc5ef0)——二进制中唯一的 NodeAddress,非网络专用

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | m_path | std::vector<cHashedString> (12B) | ctor 清 3 dword 后按 '.' 分段 `cHashedString::Set` + `vector<cHashedString>::push_back(this)` (G 0xc51f4);StripHead 从 `begin+8` 起 push_back |

---

## 20. cNetworkLuaProxy — 完成 ✓(≥32B, 布局见下)

- **ctor** 0x18e4f6 / 0x18e614 (0x109), dtor 0x18e724, D1 0x18e79c / D0 0x18e7a2
- **vtable**: 0x457188 (12B: [~ 0x18e79c, ~ 0x18e7a2, HandleEvent 0x18e844])
- 独立 LuaProxy(非 ComponentLuaProxy);Lunar 注册 @ 0x18e7ce
- 方法大多委托全局 cNetworkManager 单例(GetServerListings/StartClient/DownloadServerDetails/GetServerListingReadDirty→pMasterServer+0x8E 等),自身字段少

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | ctor `*a1 = &unk_457188` (I 0x18e537) |
| 0x04 | UNKNOWN_0x04 | int (ctor 未写) | — |
| 0x08 | map_like_0x08 | 容器头部 (20B:+8..+0x1B) | ctor `+0x10=+0x14=&this+8, +8=+0xC=+0x18=0` — **std::map 初始化模式**(color/parent/left/right/count),但 dtor 未见 `_M_erase` — 语义存疑,标 UNKNOWN;可能是 tClientProxy 列表的变体容器 |
| 0x1C | pNetworkContext | void* | ctor `= *(*(cNetworkManager::mInstance+0x110)+0x20)`;HandleEvent 用 `*(*(this+0x1C)+0x58)` 取 lua_State (I 0x18e552 / G 0x18e844) |
| 0x20.. | UNKNOWN | — | ctor 未初始化超出部分 |

> tClientProxy 的 std::list 排序/归并 (0x198150/0x19833a) 被 0x452a38、0x4f2536 [DATA] 引用 — 列表本体未定位(疑在 cNetworkClientObject2 / cNetworkManager 内,不在代理对象上)。

---

## 21. cNetworkLuaProxy::tClientProxy — 完成 ✓(8B)

- **ctor** 0x1993e4 `(const cNetworkClientObject2*)`;operator< 0x1983cc;IsServerOwner 0x199370;PushClientTableToLua 0x195c0a

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | bIsServer | byte | ctor: `= (clientObj->rakNetGUID@+0x164 == cNetworkManager::GetServerGUID())` (I 0x199430) |
| 0x01 | bIsServerOwner | byte | ctor: `= IsServerOwner(a3, a3+0x17C)` (I 0x19943f) |
| 0x02 | bNotDedicated | byte | ctor: `= *(clientObj+0x212) == 0` (I 0x19944e) |
| 0x03 | (padding) | — | — |
| 0x04 | pPlayerListingData | cPlayerListingData* | ctor: `= clientObj+0x17C`;PushClientTableToLua `this_00 = *(tcp+4)` (G 0x195c17) |

> cPlayerListingData 字段(支撑证据):+0 name串、+4 cNetID2(44B)、+0x30 指针(+0x10 串)、+0x34/0x48/0x50/0x58/0x60/0x68 cHashedString、+0x3C..0x3F colour、+0x40 userflags、+0x41 netscore、+0x42 age(ushort)、+0x44 admin。

---

## 22. cShardLuaProxy — 完成 ✓(4B)

- **ctor** 0x1a220a, dtor 0x1a22a2;**无 vtable**(ctor 直写首字段,dtor 无 vtable 回写)
- 独立 LuaProxy(非 ComponentLuaProxy);Lunar 注册 @ 0x1a2750

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pShardManager | cShardManager* | ctor `*a1 = Util::cSingleton<cShardManager>::mInstance` (I 0x1a2220);dtor: Log + `cShardManager::OnShardLuaProxyDestroyed()` (G) |

---

## 回写建议汇总表

| 类型名 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| cShardManager | 重建(替换 1B 占位) | 0xA8 (168B) | ctor 0x1a2e44 + dtor 0x1aada6;3 map + 1 list + 2 Timer + pimpl |
| cShardManager::tCheshireCat | 新建 | 0x40 (64B) | ctor 0x1b49ae;RakNetGUID+SystemAddress+str+slave map |
| cShardBroadcast | 重建(替换 1B 占位) | 0x4 (4B) | `operator new(4)` 铁证;仅 1 string |
| cNatTraversal | 重建(游戏部分)/RakNet 基类标 Tier 4 | ≥0x198 | ctor 0x161b7a;游戏部分 @ +0x190 调试接口 |
| cAccountManager | 重建(替换 1B 占位) | 0x50 (80B) | ctor 0x146ff6 + RegisterSlave 交叉验证 token@+0x1C |
| cAccountManager::tAuthenticated | 新建 | 0x10 (16B) | ctor 0x149396;4×string |
| cTwitchManager | 重建(替换 1B 占位) | 0x28 (40B) | ctor 0xb9f8c + dtor 0xba6ea |
| SteamWorkshop | 重建(替换 1B 占位) | 0x1C8 (456B) | ctor 0x261cae + dtor 0x262338;6×CCallResult + 6 vector + deque + map + list + 2 Mutex |
| LuaHttpQuery | 重建(替换 1B 占位) | 0x20 (32B) | dtor 0xacb8 + Submit/CompleteRequest;map + 2 counter |
| LuaHttpQuery::RequestInfo | 新建 | 0x8 (8B) | Submit/CompleteRequest 读写 |
| CurlRequest | 重建(替换 1B 占位) | ~0x36 (54B) | ctor 0x1bb536 + dtor 0x1bb3de(curl 句柄) |
| CurlRequestManager | 重建(替换 1B 占位) | 0x8 (8B) | ctor 0x1b8354 |
| CurlRequestManager::ClientThread | 新建 | 0x124 (292B) | ctor 0x1b86f4;2 Mutex + map + curl_multi |
| GetURL | 重建(替换 1B 占位) | 0x8 (8B) | ctor 0x1b81ea |
| cCachedPingResults | 重建(替换 1B 占位) | 0x2C (44B) | ctor 0x14949c + dtor 0x149584 |
| cGiftingManager | 重建(替换 1B 占位) | 0xA0 (160B) | ctor 0x14c2ca + dtor 0x14c3ca |
| DontStarveGameService | 重建(替换 1B 占位) | 0x24 (36B) | ctor 0x1a3b2 + dtor 0x1a47c |
| DontStarveSystemService | 重建(替换 1B 占位) | 0xA4 (164B) | ctor 0x24116 + dtor 0x24d8e |
| GameService | 跳过(纯接口,无数据) | — | 无 ctor;方法非虚直调 |
| SystemService | 跳过(纯接口,无数据) | — | 无 ctor;stub 0x1c3d40..0x1c3d4b |
| cAccountCommunication | 重建(替换 1B 占位) | 0xC4 (196B) | ctor 0x142070 + dtor 0x142302 |
| cSteamAccountCommunication | 新建(子类) | 0x11C+ (≥284B) | ctor 0x1bbb5c;cAccountManager ctor `new(0x11C)` |
| DatagramHeaderFormat | 重建(替换 1B 占位) | 0x0F (15B) | Serialize 0x243bca / Deserialize 0x242cfc |
| Socket | 重建(替换 1B 占位) | 0x1C (28B) | ctor 0x1b6fea + dtor 0x1b7032 + TCPConnect |
| NodeAddress | 重建(替换 1B 占位) | 0x0C (12B) | ctor 0xc51f4(vector<cHashedString>) |
| cNetworkLuaProxy | 重建(替换 1B 占位) | ≥0x20 (32B+) | ctor 0x18e4f6 + dtor 0x18e724;+8 容器存疑 |
| cNetworkLuaProxy::tClientProxy | 新建 | 0x8 (8B) | ctor 0x1993e4 + PushClientTableToLua 0x195c0a |
| cShardLuaProxy | 重建(替换 1B 占位) | 0x4 (4B) | ctor 0x1a220a;无 vtable |

## 方法/注意事项

1. **std::string = 4B**(旧 ABI):所有 string 成员按 4B 指针处理;length/cap 在 `_Rep`(data-12)。
2. **容器判定**:map = `*(X+8)=*(X+12)=&this+X` + X/X+4 清零;list = `*X=*(X+4)=&this+X`。
3. Timer = 8B(mach_absolute_time);Mutex/CriticalSection = 56B;cNetID2 = 44B;RakNetGUID = 8B;SystemAddress = 24B。
4. RakNet 基类(NatPunchthroughClient、RNS2、ReliabilityLayer 等)一律 Tier 4 跳过,只恢复游戏自有偏移。
5. vtable 区域 (0x4549xx-0x4571xx) 密集且相邻类共享内存,槽位枚举需逐个 get_function_by_address 复核,本报告只保证 D1/D0 首两槽。
6. 未解决项:cNetworkLuaProxy +0x08 容器(dtor 不擦除,异常);tClientProxy 列表本体位置;cAccountManager vtable 槽2 (0x46e47c 不可读);DontStarve* vtable 槽 2+ 归属。
