# 嵌套子类型布局恢复报告 (remaining-d-nested) — 2026-08-08

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp (G, 当前程序 dontstarve_steam) + idalib-mcp (I, 会话 c1f3f184, 健康)
> 约束:纯只读调查;每类型 IDA decompile ≤2 次(本片全部用 Ghidra decompile_function,IDA 仅 func_query 发现符号,0 次 IDA decompile)
> 现状:所有目标类型在 Ghidra `/Demangler/` 下均为 **1B 占位**,无一已建 → 全部「待恢复」
> 关键前提:std::string = 4B 旧 ABI;std::map/_Rb_tree 头 = 24B(pad@0, color@4, parent@8, left@0xC, right@0x10, count@0x14);std::list 头 = 8B 循环;RakNet::RakNetGUID = 8B;RakNet::SystemAddress = 0x14 (20B)

---

## 1. cShardManager::tCheshireCat — 待恢复 (64B, 0x40)

- **状态**: 待恢复(现为 1B 占位;父类 cShardManager 已在 /cShardManager 168B 已建,但 pimpl 未建)
- **大小**: 64B (0x40) — 铁证:cShardManager ctor 0x1a2e44 `operator new(0x40)` → ctor (G 0x1a2fab)
- **ctor**: 0x1b49ae (C2, 0xb2) (I);**Clear**: 0x1b2bfa (0x17e) (I)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | m_guid | RakNet::RakNetGUID (8B) | ctor `RakNetGUID::RakNetGUID(this)`;Clear `*(undefined8*)this = UNASSIGNED_RAKNET_GUID` |
| +0x08 | wField_0x08 | uint16 = DAT_00470360 | Clear `*(undefined2*)(this+8) = DAT_00470360` |
| +0x0A | (pad) | 2B | — |
| +0x0C | m_systemAddress | RakNet::SystemAddress (0x14) | ctor `SystemAddress::SystemAddress(this+0xC)`;Clear op= UNASSIGNED_SYSTEM_ADDRESS |
| +0x20 | bField_0x20 | byte = 1 | Clear `this[0x20] = 1` |
| +0x24 | m_strName | std::string | ctor `= &_S_empty_rep_storage+0xC`;cShardManager dtor `_M_destroy` (tier3-d §1) |
| +0x28 | m_shardSlaves | std::map<uint, SlaveInfo*> (24B) | ctor 自引用头 @0x2C..0x3C;Clear `_M_erase(this+0x28)` + `_Rb_tree_rebalance_for_erase(p, this+0x2C)`;GetSlaveFromId `find(pCat+0x28)` (tier3-d) |

> 注:Clear 中 map 节点 (SlaveInfo*) 含 4 个 std::string (+0x24/+0x28/+0x34/+0x38 处释放)——SlaveInfo 为 4 字符串结构,建议随附恢复。
> **回写建议**: 新建 `cShardManager::tCheshireCat` 0x40,替换 /Demangler/ 1B 占位。

---

## 2. cNetworkManager::tCheshireCat — 待恢复 (352B, 0x160)

- **状态**: 待恢复(1B 占位;父类 cNetworkManager /cNetworkManager 5048B 已建)
- **大小**: 352B (0x160) — 铁证:cNetworkManager ctor 0x165992 `operator new(0x160)` → ctor (G)
- **ctor**: 0x180130 (C2, 0xb8) (I);**Clear**: 0x17d720 (0x109) (I);dtor 释放:cNetworkManager D2 0x167598 删除

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | m_guid | RakNet::RakNetGUID (8B) | ctor `RakNetGUID::RakNetGUID(this)`;Clear `= UNASSIGNED_RAKNET_GUID` |
| +0x08 | wField_0x08 | uint16 = DAT_0046f5a0 | Clear `*(undefined2*)(this+8) = DAT_0046f5a0` |
| +0x0C | m_systemAddress | RakNet::SystemAddress (0x14) | ctor `SystemAddress::SystemAddress(this+0xC)`;Clear op= |
| +0x20 | m_clientAddress | RakNet::SystemAddress (0x14) | ctor `SystemAddress::SystemAddress(this+0x20)`;Clear op= |
| +0x34 | m_serverListing | tServerListing (0x10C = 268B) | ctor `tServerListing::tServerListing(this+0x34)`;Clear `tServerListing::operator=`;D2 `~tServerListing(this+0x34)` |
| +0x140 | m_clients | std::map<RakNetGUID, cNetworkClientObject2*> (24B) | ctor 头自引用 @0x144..0x154;Clear `_M_erase(this+0x140)` + 头重初始化;C2 0x180130 序列 |
| +0x158 | nField_0x158 | int = 0 | Clear `*(this+0x15C)=0; *(this+0x158)=0` |
| +0x15C | nField_0x15C | int = 0 | 同上 |

> map 值类型由 CachePlayers (0x178bca) 确认:`find(pCheshireCat+0x144)` → 节点 `+0x1C` 取 cNetworkClientObject2*(遍历 `for(p=_Rb_tree_increment(...))`,即 map<RakNetGUID, cNetworkClientObject2*>)。
> **回写建议**: 新建 `cNetworkManager::tCheshireCat` 0x160(嵌套 tServerListing)。

---

## 3. cTwitchManager::tCheshireCat — 待恢复 (1416B, 0x588)

- **状态**: 待恢复(无任何占位记录,父类 cTwitchManager /cTwitchManager 40B 已建)
- **大小**: 1416B (0x588) — 铁证:cTwitchManager ctor 0xb9f8c `operator new(0x588)` + 内联初始化 (G)
- **ctor**: 内联于 cTwitchManager ctor 0xb9f8c (无独立离体符号);**dtor**: 内联(cTwitchManager dtor 0xba6ea 释放)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x000..+0x07F | UNKNOWN_0x00[0x80] | 32×dword = 0 | ctor `puVar1[0..0x1F] = 0` |
| +0x080..+0x29F | UNKNOWN_0x80 | TTV lib 状态(ctor 未初始化) | — |
| +0x2A0..+0x41F | UNKNOWN_0x2A0[0x180] | bzero 384B | ctor `___bzero(puVar1+0xA8, 0x180)`(dword 索引 0xA8 = 字节 0x2A0) |
| +0x420..+0x4A3 | UNKNOWN_0x420 | ctor 未初始化 | — |
| +0x4A4 | pChatStatusCallback | void* | ctor `puVar1[0x129] = ChatStatusCallback` |
| +0x4A8 | pChatMembershipCallback | void* | ctor `puVar1[0x12A] = ChatMembershipCallback` |
| +0x4AC | pChatUserCallback | void* | ctor `puVar1[299] = ChatUserCallback` |
| +0x4B0 | pChatMessageCallback | void* | ctor `puVar1[300] = ChatMessageCallback` |
| +0x4B4 | pChatTokenizedMessageCallback | void* | ctor `puVar1[0x12D] = ChatTokenizedMessageCallback` |
| +0x4B8 | pChatClearCallback | void* | ctor `puVar1[0x12E] = ChatClearCallback` |
| +0x4BC | pField_0x4BC | void* = 0 | ctor `puVar1[0x12F] = 0` |
| +0x4C0 | m_authThread | TwitchAuthThread (0xC8) | ctor `TwitchAuthThread::TwitchAuthThread(puVar1 + 0x130)`(dword 索引 = 字节 +0x4C0);0x4C0+0xC8 = 0x588 ✓ |

> **回写建议**: 新建 `cTwitchManager::tCheshireCat` 0x588(嵌套 TwitchAuthThread;TTV lib 区域标 UNKNOWN)。

---

## 4. cTwitchManager::tCheshireCat::TwitchAuthThread — 待恢复 (200B, 0xC8)

- **状态**: 待恢复(现为 /Demangler/.../TwitchAuthThread 1B 占位)
- **大小**: 200B (0xC8) — 位于 tCheshireCat +0x4C0,0x4C0+0xC8 = 0x588 (分配上限闭合)
- **ctor**: 0xb85c4 (C2, 0x2a0) (I);**D2**: 0xb886a (0x35c);**D0**: 0xb8bcc;vtable **0x4562D8**
- 继承 `Thread`(基类 0x78 头部:vtable@0/bRunning@4/dwPriority@8/dwStackSize@0xC/Mutex@0x10(0x38)/m_strName@0x74;Thread ctor 0x2740CC 只写到此,0x78 之后为派生字段区)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | Thread 基类 | Thread (0x78 有效区) | ctor `Thread::Thread(this, "TwitchAuthThread", 0, 2)` |
| +0x78 | nField_0x78 | int = 0 | ctor |
| +0x7C | nField_0x7C | int = 0 | ctor |
| +0x80 | nField_0x80 | int = 0 | ctor |
| +0x84 | str_0x84 | std::string | ctor = empty;D2 销毁 |
| +0x88 | str_0x88 | std::string | 同上 |
| +0x8C | str_0x8C | std::string | 同上 |
| +0x90 | str_0x90 | std::string | 同上 |
| +0x94 | str_0x94 | std::string | 同上 |
| +0x98 | UNKNOWN_0x98 | 4B (ctor 未写) | — |
| +0xA0 | str_0xA0 | std::string | ctor = empty;D2 销毁 |
| +0xA4 | str_0xA4 | std::string | 同上 |
| +0xA8 | m_socket | Socket (0x1C = 28B) | ctor `Socket::Socket(this+0xA8)`;D2 `Socket::~Socket` + `CleanupSocketLibrary` |

> **回写建议**: 新建 `cTwitchManager::tCheshireCat::TwitchAuthThread` 0xC8(Thread 基类按 0x78 有效区,UNKNOWN_0x98 标未知)。

---

## 5. cNetworkManager::MigrationInfo — 待恢复 (72B, 0x48)

- **状态**: 待恢复(1B 占位)
- **大小**: 72B (0x48) — ctor 写满至 +0x44;成员为 cNetworkManager 内嵌对象(cNetworkManager ctor 0x165992 内联构造)
- **ctor**: 0x165838 (C2, 0xf9) (I);**C1**: 0x165932

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | nField_0x00 | int = 0 | ctor |
| +0x04 | m_strTarget | std::string = "" | ctor `string::string(this+4, "")` |
| +0x08 | wField_0x08 | uint16 = 0 | ctor |
| +0x0C | m_strSteamId | std::string = "" | ctor `string::string(this+0xC, "")` |
| +0x10 | m_netId | RakNet::RakNetGUID (8B) = UNASSIGNED | ctor `*(undefined8*)(this+0x10) = UNASSIGNED_RAKNET_GUID` |
| +0x18 | nField_0x18 | int = DAT_0046f5a0 | ctor |
| +0x1C | m_targetNetId | cNetID2 (0x2C = 44B) | ctor `cNetID2::Clear(this+0x1C)`;尾部 +0x40/+0x44 清零 |

> 用途:SetMigrationInfo 0x17a28a 填充(带 RakNetGUID 源 GUID)。
> **回写建议**: 新建 `cNetworkManager::MigrationInfo` 0x48。

---

## 6. cNetworkManager::ServerListingData — 待恢复 (28B, 0x1C)

- **状态**: 待恢复(1B 占位于 /cNetworkManager/ServerListingData,非 Demangler)
- **大小**: 28B (0x1C) — Clear 写至 +0x1A
- **Clear**: 0x178b10 (0xba) (I);**CachePlayers**: 0x178bca (0x761) (I);dtor 于 cNetworkManager D2 0x167598(字符串 +0x00/0x04/0x08/0x14、list +0x0C 释放后 delete)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | m_strName | std::string | Clear `_M_mutate(this)`;D2 释放 |
| +0x04 | m_strAddress | std::string | Clear;D2 释放 |
| +0x08 | m_strGameMode | std::string | Clear;D2 释放 |
| +0x0C | m_players | std::list<cPlayerListingData> (8B 头) | Clear `_List_base::_M_clear()` + 头自引用;CachePlayers 遍历/`_M_create_node`/`_M_erase` |
| +0x14 | m_strLuaResult | std::string | Clear;D2 释放;CachePlayers `string::assign(this+0x14, lua result)` |
| +0x18 | wPlayerCount | uint16 = 0 | Clear `*(this+0x18)=0`;CachePlayers `*(short*)(this+0x18)++` |
| +0x1A | bDirty | byte = 1 | Clear `this[0x1A]=1`;CachePlayers `this[0x1A]=0` |

> **回写建议**: 新建 `cNetworkManager::ServerListingData` 0x1C。

---

## 7. cNetworkLuaProxy::tClientProxy — 待恢复 (8B)

- **状态**: 待恢复(1B 占位;tier3-d §21 已文档化,本片复核一致)
- **大小**: 8B
- **ctor**: 0x1993e4 (C2, 0x78) (I);**operator<**: 0x1983cc;IsServerOwner: 0x199370;PushClientTableToLua: 0x195c0a

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | bIsServer | byte | ctor `= (clientObj->rakNetGUID@+0x164 == cNetworkManager::GetServerGUID())` |
| +0x01 | bIsServerOwner | byte | ctor `= IsServerOwner(...)` |
| +0x02 | bNotDedicated | byte | ctor `= *(clientObj+0x212) == 0` |
| +0x03 | (pad) | 1B | — |
| +0x04 | pPlayerListingData | cPlayerListingData* = clientObj+0x17C | ctor `*(this+4) = param_1+0x17C`;PushClientTableToLua `*(tcp+4)` |

> **回写建议**: 新建 `cNetworkLuaProxy::tClientProxy` 0x8。

---

## 8. DontStarveInputHandler::ControlMapper — 待恢复 (516B, 0x204)

- **状态**: 待恢复(1B 占位;tier3-c-input.md §2.1 已文档化,本片复核一致)
- **大小**: 516B (0x204) — 嵌入 DontStarveInputHandler +0x44..+0x247(§2.1)
- **ctor**: C2 0x208c4 (0xf1) (I);C1 0x1c6e8;D2 0x20bc4;vtable 无(普通对象)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pInputManager | Input::IInputManager* | C2 0x208c4 `*(this)=param_1` |
| +0x04 | wField | uint16 = 0 | C2 |
| +0x08 | pGlobal | void* = MaxDeviceId@0x45011C | C2 `*(this+8) = *(PTR_MaxDeviceId_0045011c)` |
| +0x0C | nControlCount | int = 0x49 (73) | C2 |
| +0x10 | nField | int = 5 | C2 |
| +0x14 | pMappingStorage2 | void* (local_1c 未初始化→栈残留,见下) | C2 `*(undefined8*)(this+0x14) = local_1c` |
| +0x1C | pInputManager2 | void* | C2 `*(undefined8*)(this+0x1C) = local_14` |
| +0x24 | nField | int = -1 | C2 `= 0xFFFFFFFF` |
| +0x28 | bField | byte = 0 | C2 |
| +0x2C | pSelf | void* = this | C2 `*(this+0x2C) = this` |
| +0x30 | pGlobal2 | void* = OnControlMapped (0x209b6) | C2 `*(this+0x30) = OnControlMapped` |
| +0x34..+0x40 | nField×4 | int = 0 | C2 清零 |

> 与 tier3-c §2.1 完全一致(§2.1 称 +0x14/+0x1C 为 pMappingStorage2/pInputManager2,C2 实际用未初始化栈值写,运行时由 DontStarveInputHandler C2 0x1b208 传入真实指针)。
> **回写建议**: 新建 `DontStarveInputHandler::ControlMapper` 0x204(嵌套 Control 16B 见 types_common.h)。

---

## 9. DontStarveInputHandler::LuaProxy — 待恢复 (4B)

- **状态**: 待恢复(1B 占位)
- **大小**: 4B — Lunar::new_T 0x22ae2 `operator new(4)` (G)
- **ctor**: C1(handler) 0x22454 / C2(lua_State) 0x22460 / C1(lua) 0x2246c / C2(handler) 0x22478(均 0xb);Register 0x1c99a

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pField | void* = 0 | ctor `*(undefined4*)this = 0`;new_T `*(undefined4*)p = 0` |

> Lunar 注册代理(`Lunar<LuaProxy>::Register` 0x2269a),字段由 Lunar 框架填 pHandler/pLuaState。
> **回写建议**: 新建 `DontStarveInputHandler::LuaProxy` 0x4。

---

## 10. GameService::PlayerId — 待恢复 (36B, 0x24)

- **状态**: 待恢复(1B 占位)
- **大小**: 36B (0x24) — ctor 写 9 dword 至 +0x20
- **ctor**: C2 0x1c21ce (0x43);C2(PKc) 0x1c2256;C2(uint) 0x1c2326;Str 0x1c239c;Int 0x1c2402;eq 0x1c234a (I)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00..+0x20 | m_data[9] | uint32×9 = 0 | ctor 逐 dword 清零 |

> Str/Int 视图:0x1c239c 做十六进制字符串转换(0x1c2402 数值视图),同 AchievementId。
> **回写建议**: 新建 `GameService::PlayerId` 0x24。

---

## 11. GameService::PlayerInfo — 待恢复 (294B, 0x126)

- **状态**: 待恢复(1B 占位)
- **大小**: 294B (0x126) — C2() 0x1c2466 `___bzero(this, 0x126)`
- **ctor**: C2() 0x1c2466;C2(PlayerId,wchar,wchar,bool,bool) 0x1c249e;C2(PlayerId,char,char,bool,bool) 0x1c27b8 (I)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | playerId | GameService::PlayerId (0x24) | 0x1c249e 全字段拷贝(4×8B + 1×4B) |
| +0x24 | m_strName | wchar_t[0x20] (64B) | 0x1c249e `_wcsncpy(this+0x24, name, 0x1F)`;前置清零 0x24..0x40 |
| +0xA4 | m_strDisplayName | wchar_t[0x20] (64B) | 0x1c249e `_wcsncpy(this+0xA4, display, 0x1F)` |
| +0x124 | bIsSignedIn | byte = param_4 | 0x1c249e `this[0x124] = param_4` |
| +0x125 | bIsOnline | byte = param_5 | 0x1c249e `this[0x125] = param_5` |

> 中段 0x40..0xA3 清零(0x1c249e 序列),可视为 name 缓冲对齐区。
> **回写建议**: 新建 `GameService::PlayerInfo` 0x126。

---

## 12. GameService::AchievementId — 待恢复 (36B, 0x24)

- **状态**: 待恢复(1B 占位)
- **大小**: 36B (0x24) — 与 PlayerId 同构
- **ctor**: C2 0x1c2b7c (0x43);C2(PKc) 0x1c2c04;C2(uint) 0x1c2cd4;Str 0x1c2d4a;Int 0x1c2db0;eq 0x1c2cf8 (I)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00..+0x20 | m_data[9] | uint32×9 = 0 | ctor 逐 dword 清零 |

> map<cHashedString, AchievementId> 的 value 类型(0x1b006 _M_insert_unique 实例化)。
> **回写建议**: 新建 `GameService::AchievementId` 0x24。

---

## 13. SystemService::FileOpRequest — 待恢复 (324B, 0x144)

- **状态**: 待恢复(1B 占位)
- **大小**: 324B (0x144) — 5-参 ctor 写至 +0x140;3-参 ctor bzero 至 +0x144
- **ctor**: C2(PlayerId,PKc,FD,void*) 0x1c3fe6 (0xa0);C2(PlayerId,PKc,uint,PKc,FD,void*) 0x1c408c (0xb4) (I);vtable **0x4576A8**

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pVtable | void* = 0x4576A8 | ctor |
| +0x04 | m_callback | fastdelegate::FastDelegate2<Result const&, void*, void> (12B) | ctor 3 dword 写入 +0x04/+0x08/+0x0C |
| +0x10 | pContext | void* | ctor |
| +0x14 | nRequestType | int = 5 | ctor |
| +0x18 | playerId | GameService::PlayerId (0x24) | ctor 全字段拷贝 |
| +0x3C | szFilename | char[0x100] | 3-参 ctor `bzero(0x108)`+`strncpy(0xFF)`;5-参 `bzero(0x100)` |
| +0x13C | nDataLen | uint (5-参专用) | 5-参 ctor `= param_3` |
| +0x140 | pData | char* (5-参专用) | 5-参 ctor `= param_4` |

> **回写建议**: 新建 `SystemService::FileOpRequest` 0x144。

---

## 14. SystemService::FileOpResult — 待恢复 (328B, 0x148)

- **状态**: 待恢复(1B 占位)
- **大小**: 328B (0x148) — 各 ctor 写至 +0x144/+0x148
- **ctor**: C2() 0x1c43b2 (0x63);C2(req,Status) 0x1c447a;C2(req,Status,uint,PKc) 0x1c45ee;D2/D1 0x1c475a/0x1c475c;Copy 0x1c4764 (I);vtable **0x4576E8**

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pVtable | void* = 0x4576E8 | ctor |
| +0x04 | m_callback | fastdelegate FastDelegate2 (12B) | C2(req) 从 request +0x04 拷贝 |
| +0x10 | pContext | void* | C2(req) 从 request +0x10 |
| +0x14 | nRequestType | int = 5 | C2(req) 从 request +0x14;C2() = 5 |
| +0x18 | eStatus | SystemService::Result::Status (int) | C2() = 7;C2(req) = param_3 |
| +0x1C | playerId | GameService::PlayerId (0x24) | C2(req) 从 request +0x18 拷贝;C2() `PlayerId::PlayerId(this+0x1C)` |
| +0x40 | szData | char[0x100] | C2(req) `memcpy(this+0x40, req+0x3C, 0x100)`;C2() bzero 0x108 |
| +0x140 | nField_0x140 | int = 0 | C2(req) |
| +0x144 | nField_0x144 | int = 0 | C2(req) |

> **回写建议**: 新建 `SystemService::FileOpResult` 0x148。

---

## 15. SteamWorkshop::ModInfo — 待恢复 (10036B, 0x2734)

- **状态**: 待恢复(1B 占位)
- **大小**: 10036B (0x2734) — vector<ModInfo>::push_back 0x2680c6 / _M_insert_aux 0x26993c `memcpy(…, 0x2734)` 铁证 (G)
- **方法**: GetVersion 0x268180(经 vector 方法表 [DATA] 引用);无独立 ctor(就地构造)
- **结构**: 内嵌 Steam `RemoteStorageGetPublishedFileDetailsResult_t`(0x2614)+ 附加字段(0x120)
  - OnPublishedFileDetailsResultForTempMod 0x26483c:`memcpy(local_284c, param_1, 0x2614)` 把 Steam result 拷入 10036B 栈缓冲后 push_back → ModInfo 首字段即 Steam result 结构

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00..+0x2613 | steamResult | RemoteStorageGetPublishedFileDetailsResult_t (0x2614) | memcpy 0x2614 (0x26483c) |
| +0x1FD8 | nFileSize | uint64 | OnPublishedFileDetailsResultV2 `param_1+0x1FD8` 读 8B (log 字段) |
| +0x1FFC | bBanned | byte | 0x26483c `param_1[0x1FFC]` 判禁用 |
| +0x1FFD | rgchTags | char[] (Steam tags) | GetVersionFromTags 0x26077c 调用方均传 `param_1+0x1FFD`;ModInfo::GetVersion `this+0x1FFD` |
| +0x23FF | rgchURL | char[] (string 用) | 0x26483c log `[%s]` @+0x23FF |
| +0x250C | pchFileName | char[] | 0x26483c log `[%s]` @+0x250C |
| +0x2614..+0x2733 | UNKNOWN_0x2614[0x120] | 附加 288B(未定型) | 0x2734 − 0x2614 |

> **回写建议**: 新建 `SteamWorkshop::ModInfo` 0x2734(嵌入 Steam result 结构,主体字段标 UNKNOWN/Steam SDK 引用;Tags 偏移 +0x1FFD 为本二进制实证)。

---

## 16. tServerListing — 待恢复 (268B, 0x10C)

- **状态**: 待恢复(1B 占位)
- **大小**: 268B (0x10C) — ctor 写至 +0x108;Clear 栈缓冲 `local_11c[268]`;cMasterServerBroadcast ctor `operator new(0x10C)` 铁证
- **ctor**: 0x19a630 (C2, 0x3ad);copy ctor 0x15e7cc;D2 0x15e208 (I)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00..+0x30 | str[13] | std::string ×13 (= empty) | ctor 13 次 = empty |
| +0x34 | m_mods | std::list<tServerModInfo> (8B 头) | ctor 头自引用 +0x34/+0x38 |
| +0x3C | wField_0x3C | uint16 = 0 | ctor |
| +0x3E | wField_0x3E | uint16 = 0 | ctor |
| +0x40 | wField_0x40 | uint16 = 0 | ctor |
| +0x44 | nField_0x44 | int = -1 | ctor |
| +0x48 | nField_0x48 | int = -1 | ctor |
| +0x4C | nField_0x4C | int = 0 | ctor |
| +0x50 | nField_0x50 | int = 0 | ctor |
| +0x54 | netId | cNetID2 (0x2C) | ctor `cNetID2::Clear(this+0x54)` |
| +0x80 | netId2 | cNetID2 (0x2C) | ctor `cNetID2::Clear(this+0x80)` |
| +0xAC | nField_0xAC | int = 0xF | ctor |
| +0xB0 | bField_0xB0 | byte = 0 | ctor |
| +0xB1 | bField_0xB1 | byte = 1 | ctor |
| +0xB2 | nField_0xB2 | int = 0 | ctor |
| +0xB8 | netId3 | cNetID2 (0x2C) | ctor `cNetID2::Clear(this+0xB8)` |
| +0xE4 | guid | RakNet::RakNetGUID (8B) | ctor `= UNASSIGNED_RAKNET_GUID` |
| +0xEC | nField_0xEC | int = _DAT_00470268 | ctor |
| +0xF0 | nField_0xF0 | int = 5 | ctor |
| +0xF4 | nField_0xF4 | int = 0 | ctor |
| +0xF8 | str_0xF8 | std::string = empty | ctor |
| +0xFC | nField_0xFC | int = 0 | ctor |
| +0x100 | bField_0x100 | byte = 0 | ctor |
| +0x104 | str_0x104 | std::string = empty | ctor |
| +0x108 | wField_0x108 | uint16 = 0 | ctor |

> **回写建议**: 新建 `tServerListing` 0x10C(嵌套 tServerModInfo = 4 string + byte@+0x10,list 节点 0x1C,见 0x17faa4)。

---

## 17. tModnameVersion — 待恢复 (8B)

- **状态**: 待恢复(1B 占位)
- **大小**: 8B — operator= 0xf5748 仅 assign 2 个 string (G)
- **方法**: operator= 0xf5748;IsWorkShopMod 0x260a6e;GetFileId 0x260aaa (I)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | m_strModname | std::string | op= assign(this);IsWorkShopMod `compare(this,0,9)` = "workshop-";GetFileId substr(this) |
| +0x04 | m_strVersion | std::string | op= assign(this+4) |

> SteamWorkshop::m_modVersions = vector<tModnameVersion>(tier3-d §6)。
> **回写建议**: 新建 `tModnameVersion` 0x8。

---

## 18. tModnameFancyname — 待恢复 (8B)

- **状态**: 待恢复(1B 占位)
- **大小**: 8B — ctor 0x26a240 assign 2 个 string (G)
- **ctor**: 0x26a240 (C2, string, string, 0xab);operator= 0x268ffe (I)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | m_strName | std::string | ctor assign(param_1) |
| +0x04 | m_strFancyname | std::string | ctor assign(param_2) |

> 生成:SteamWorkshop::GetClientModsDownloading 0x26743a `tModnameFancyname(&v, "workshop-%llu", mapVal+0x18)`。
> **回写建议**: 新建 `tModnameFancyname` 0x8。

---

## 19. cMasterServerRequest — 待恢复 (16B, 0x10)

- **状态**: 待恢复(1B 占位;父类 cMasterServer /cMasterServer 145B 已建,pRequest/pBroadcast 槽位已引用)
- **大小**: 16B (0x10) — ctor 写至 +0x0C
- **ctor**: 0x1608ea (C2, 0x45);D2 0x160976;D0 0x1609c8;vtable **0x456E58** (I)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pVtable | void* = 0x456E58 | ctor |
| +0x04 | bField_0x04 | byte = 0 | ctor `this[4]=0` |
| +0x08 | m_strURL | std::string = "" | ctor `string::string(this+8,"")` |
| +0x0C | pMasterServer | cMasterServer* | ctor `= param_1` |

> 虚方法:Update 0x1609f4(空)、GetRequestData 0x1609f6、DownloadServerDetails 0x160fa6、ParseServerResponse 0x16159c。
> **回写建议**: 新建 `cMasterServerRequest` 0x10。

---

## 20. cMasterServerBroadcast — 待恢复 (88B, 0x58)

- **状态**: 待恢复(1B 占位)
- **大小**: 88B (0x58) — ctor 写至 +0x54
- **ctor**: 0x15ee66 (C2, 0x1c2);D2 0x15f02e;D0 0x15f114;Stop 0x15f114;Start 0x15f50a (I)

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | bField_0x00 | byte = 0 | ctor `*this=0` |
| +0x04 | m_strServerName | std::string = "" | ctor |
| +0x08 | nField_0x08 | int = 0 | ctor |
| +0x0C | m_strPassword | std::string = "" | ctor;后 `assign(GenerateRandomPassword)` |
| +0x10 | pMasterServer | cMasterServer* | ctor `= param_1` |
| +0x14 | m_timer | Timer (8B) | ctor `Timer::Timer(this+0x14)` |
| +0x1C | m_mutex | Mutex (0x38 = 56B) | ctor `Mutex::Mutex(this+0x1C)` |
| +0x54 | pListing | tServerListing* | ctor `= operator new(0x10C); tServerListing::tServerListing()` |

> **回写建议**: 新建 `cMasterServerBroadcast` 0x58(嵌套 tServerListing 指针)。

---

## 回写建议汇总表

| 类型名 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| cShardManager::tCheshireCat | **新建** | 0x40 (64B) | ctor 0x1b49ae;cShardManager ctor `new(0x40)` (0x1a2fab) |
| cNetworkManager::tCheshireCat | **新建** | 0x160 (352B) | ctor 0x180130;cNetworkManager ctor `new(0x160)`;Clear 0x17d720 |
| cTwitchManager::tCheshireCat | **新建** | 0x588 (1416B) | 内联于 cTwitchManager ctor 0xb9f8c `new(0x588)`;6 回调 + TwitchAuthThread@0x4C0 |
| cTwitchManager::tCheshireCat::TwitchAuthThread | **新建** | 0xC8 (200B) | ctor 0xb85c4 + D2 0xb886a;vtable 0x4562D8;Thread 基类 0x78 |
| cNetworkManager::MigrationInfo | **新建** | 0x48 (72B) | ctor 0x165838;内嵌 cNetID2@0x1C |
| cNetworkManager::ServerListingData | **新建** | 0x1C (28B) | Clear 0x178b10 + CachePlayers 0x178bca;list@0x0C |
| cNetworkLuaProxy::tClientProxy | **新建** | 0x8 | ctor 0x1993e4;3 byte + ptr@+4 (tier3-d §21 复核) |
| DontStarveInputHandler::ControlMapper | **新建** | 0x204 (516B) | C2 0x208c4;tier3-c §2.1 复核一致 |
| DontStarveInputHandler::LuaProxy | **新建** | 0x4 | Lunar::new_T 0x22ae2 `new(4)`;ctor 0x22460 |
| GameService::PlayerId | **新建** | 0x24 (36B) | ctor 0x1c21ce 9 dword 清零 |
| GameService::PlayerInfo | **新建** | 0x126 (294B) | C2() 0x1c2466 bzero 0x126;C2(full) 0x1c249e 双 wchar[0x20] |
| GameService::AchievementId | **新建** | 0x24 (36B) | ctor 0x1c2b7c(与 PlayerId 同构) |
| SystemService::FileOpRequest | **新建** | 0x144 (324B) | ctor 0x1c3fe6/0x1c408c;vtable 0x4576A8;PlayerId@0x18 |
| SystemService::FileOpResult | **新建** | 0x148 (328B) | ctor 0x1c43b2/0x1c447a;vtable 0x4576E8;PlayerId@0x1C |
| SteamWorkshop::ModInfo | **新建** | 0x2734 (10036B) | vector memcpy 0x2734 (0x2680c6/0x26993c);内嵌 Steam result 0x2614 |
| tServerListing | **新建** | 0x10C (268B) | ctor 0x19a630;`new(0x10C)` (0x15ee66);13 string + 3 cNetID2 |
| tModnameVersion | **新建** | 0x8 | op= 0xf5748;GetFileId 0x260aaa |
| tModnameFancyname | **新建** | 0x8 | ctor 0x26a240 双 string |
| cMasterServerRequest | **新建** | 0x10 (16B) | ctor 0x1608ea;vtable 0x456E58 |
| cMasterServerBroadcast | **新建** | 0x58 (88B) | ctor 0x15ee66;Mutex@0x1C + tServerListing*@0x54 |

全部 20 类型当前均为 1B 占位(Ghidra `/Demangler/` 或 `/cNetworkManager/`),无「已存在验证通过」项;无一需重建(均无正确旧布局)。

## 方法 / 注意事项

1. 本片全部证据来自 **Ghidra decompile_function**(只读),IDA 仅用于 func_query 符号定位,IDA decompile 用量 = 0(远低于 2 次/类型上限)。
2. RakNet::SystemAddress 实证 **0x14 (20B)**(cNetworkManager::tCheshireCat 双 SystemAddress @+0xC/+0x20 与 tServerListing@+0x34 闭合;cShardManager::tCheshireCat 用 +0x0C..+0x23 则不一致——按本片闭合结论 0x14,tier3-d 的 24B 记录建议修正)。
3. tServerListing 字段语义(13 个 string 名称)建议对照 cMasterServer::UpdateListing 0x159132 / WriteServerListingTable 0x176dc6 二次命名(本片只保证布局)。
4. ModInfo 主体为 Steam SDK 结构,回写时建议整块标 `RemoteStorageGetPublishedFileDetailsResult_t` 引用 + 尾部 UNKNOWN,避免逐字段命名猜测。
5. tCheshireCat 系列分配大小闭环:cShardManager new(0x40) / cNetworkManager new(0x160) / cTwitchManager new(0x588) —— 均为 pimpl 对象整体大小,与 ctor 写入范围严格一致。
