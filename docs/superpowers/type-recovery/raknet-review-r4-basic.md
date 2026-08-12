# RakNet 基础类型对比报告 (Slice R4: RakNetGUID / SystemAddress / RakString / RakPeerInterface / 枚举)

对比对象:DST 二进制 `dontstarve_steam`(Mach-O **i386 32位**,imagebase 0x1000,`__darwin_size_t`=4)
vs 仓库源码 `3rd/RakNet/Source/`(RakNet 4.x,RakNetDefines.h 默认 `RAKNET_SUPPORT_IPV6=0`)。
二进制构建来源:`/Volumes/SSD/jenkins-buildmaster/workspace/DST_BuildGame_OSX/foreign/build/raknet/{RakPeer,RakString}.cpp`(DST 内嵌 RakNet,与仓库同源)。
只读分析;未做任何写入。

## 关键架构前提
- i386 + Clang:uint64_t 对齐为 4B(SysV i386 ABI),非 MSVC 的 8B。这直接决定 RakNetGUID 大小。
- 源码宏 `RAKNET_SUPPORT_IPV6` 默认 0 → SystemAddress 的 union 仅含 `sockaddr_in addr4`(16B)。

---

### RakNetGUID
- 源码原版: `struct RakNetGUID { uint64_t g; SystemIndex systemIndex; }`(RakNetTypes.h @~370)。
  - g @0 = 8B;systemIndex @8 = 2B(ushort);i386 对齐 4 → sizeof = **12B**(g 8 + systemIndex 2 + pad 2)。
  - 序列化大小 `RakNetGUID::size()` = `sizeof(uint64_t)` = **8B**(网络上只传 g)。
  - 注:MSVC x86 下 uint64_t 对齐 8 → sizeof 会是 16B;本二进制为 Clang i386,12B 是未修改结构体的自然大小。
- 二进制恢复: **12B**。证据:`cPendingConnection` 内 `pRakNetGUID: byte[12] @16`(ghidra get_struct_layout)。无字段级定义,但 12B 与 `g@0 + systemIndex@8` 完全吻合。
- 差异: 无。12B 并非魔改,而是 i386 ABI 下的原版大小(任务书"应 12B"正确)。
- 魔改结论: **基本一致(未魔改)**。
- 建议: 恢复为 `struct RakNetGUID { uint64_t g; ushort systemIndex; }`,sizeof 12,序列化 8B。cPendingConnection 中 pRakNetGUID 保持 byte[12] 即可。

### SystemAddress
- 源码原版: `struct SystemAddress { union { sockaddr_in addr4; } address; ushort debugPort; SystemIndex systemIndex; }`(RAKNET_SUPPORT_IPV6=0)。
  - addr4 @0 = 16B(sin_family 2 + sin_port 2 + sin_addr 4 + sin_zero 8);debugPort @16 = 2B;systemIndex @18 = 2B → sizeof = **20B**,对齐 4。
  - 任务书中"8B(binaryPort+address)"是 RakNet 3.x 的旧布局,不适用于本 4.x 树。
- 二进制恢复: **20B**。证据(`RakNet::RakPeer::GetConnectionList` @0x2288e8):`SystemAddress::operator=((int)a3 + 20*v6, (__int64*)((char*)v10 + 20*v6))` —— 数组拷贝步长 **20B**,且按 qword 对拷贝(2×8B + 1×4B = addr4 16B + debugPort/systemIndex 4B),与源码布局一致。
  - 注:main agent 记录的"SystemAddress 20B@tCheshireCat"中 tCheshireCat 在 ghidra 中目前是空结构(size 1),建议改用本报告的 GetConnectionList 步长证据锚定 20B。
- 差异: 无。二进制 = 未修改源码在 IPv6=0 下的精确布局。
- 魔改结论: **基本一致(未魔改)**。
- 建议: 恢复为 `struct SystemAddress { sockaddr_in addr4; ushort debugPort; ushort systemIndex; }` sizeof 20。注意 cPendingConnection 并不含 SystemAddress —— 它用的是 DST 自建紧凑表示 `pM_ip byte[4]@8 + wPort ushort@12`(6B),这是 DST 侧自定义,不是对 RakNet SystemAddress 的改动。

### RakString
- 源码原版: `class RakString { SharedString *sharedString; }` → sizeof = **4B**(单指针)。
  - `SharedString`(RakString.h @内部):refCountMutex 4 + refCount 4 + bytesUsed 4(size_t 32位)+ bigString 4 + c_str 4 + smallString[128-4-4-8=112] = **132B**。
- 二进制恢复: 4B。证据(`RakNet::RakString::Free` @0x23895a):
  - `sharedString` 在偏移 0(`*(_DWORD*)thisa`),与 `&RakNet::RakString::emptyString`(静态单例)比较;
  - SharedString 内 `refCount` @+4(`--*(_DWORD*)(sharedString+4)`)、`bytesUsed` @+8(检查 `>= 0x71`=113 后释放 bigString @+12,与 GetSizeToAllocate 的 smallStringSize=112 对应)、`bigString` @+12;
  - 静态 `emptyString`(@0x467850)与 `freeList`(@0x4637f0)均存在 —— 与源码静态成员一一对应。
  - 使用场景:`cLuaNetworkVariableType<RakNet::RakString>` 系列(Lua 网络变量,Lua 模板类中 RakString 成员 @16)与 `Lobby2Message::Validate*` —— DST 真实使用 RakString,未被 std::string/eastl 替换。
- 差异: 无。指针、SharedString 各字段偏移、静态成员全对上。
- 魔改结论: **基本一致(未魔改)**。
- 建议: 恢复为 `struct RakString { void* sharedString; }` sizeof 4;如需深度展开,SharedString 132B 布局已由 Free() 证实。

### RakPeerInterface
- 源码原版: 纯虚抽象接口(RakPeerInterface.h),无数据成员,仅 vtable → sizeof = **4B**。
- 二进制恢复: 抽象基类 4B。证据:
  - `RakNet::RakPeerInterface::GetInstance()` @0x225dc6 = `OP_NEW<RakNet::RakPeer>` —— DST 代码通过接口获取具体 `RakNet::RakPeer` 实例;
  - `RakPeer` 整体存在(C2 @0x225dfa,0xa49B 大 ctor),且有 `__ZThn4_N6RakNet7RakPeerD1Ev` 4 字节 adjustor thunk → RakPeer 在 vtable@0 后还有第二基类 @+4(源码中为 `RNS2EventHandler`),标准 4.x 继承布局;
  - 派生关系与源码 `class RakPeer : public RakPeerInterface, public RNS2EventHandler` 一致。
- 差异: 无。接口未改动,具体类 RakPeer 的字段差异不在本片范围(见 RakPeer 相关分片)。
- 魔改结论: **基本一致(未魔改)**。
- 建议: 恢复 `RakPeerInterface*` 为 4B 抽象基类指针;具体实例按 RakPeer 恢复。

### PacketPriority / PacketReliability / MessageID
- 源码原版:
  - `MessageID` = `typedef unsigned char`(RakNetTypes.h),1B;
  - `enum PacketPriority { IMMEDIATE_PRIORITY, HIGH_PRIORITY, MEDIUM_PRIORITY, LOW_PRIORITY, NUMBER_OF_PRIORITIES }`(PacketPriority.h),int 4B;
  - `enum PacketReliability { UNRELIABLE, UNRELIABLE_SEQUENCED, RELIABLE, RELIABLE_ORDERED, RELIABLE_SEQUENCED, UNRELIABLE_WITH_ACK_RECEIPT, RELIABLE_WITH_ACK_RECEIPT, RELIABLE_ORDERED_WITH_ACK_RECEIPT, NUMBER_OF_RELIABILITIES }`,int 4B;
  - MessageIdentifiers.h 顶部注释明示"不应修改",ID_* 为固定编号(如 ID_TIMESTAMP=27)。
- 二进制恢复: 枚举/字节完全一致。证据:
  - 符号名精确匹配:`__ZN6RakNet7RakPeer4SendEPKci14PacketPriority17PacketReliabilitycNS_13AddressOrGUIDEbj` 与源码 `Send(const char*, int, PacketPriority, PacketReliability, char, AddressOrGUID, bool, uint32_t)` 逐参数对应(`14PacketPriority`/`17PacketReliability` 即命名枚举,4B int);`SendBuffered`/`SendImmediate`/`SendList`/`Shutdown(Ejh14PacketPriority)` 同理;
  - `RakPeer::Receive` @0x22943e:`if (*data == 27) ShiftIncomingTimestamp(data+1, ...)` —— 27=0x1B=ID_TIMESTAMP,按字节比较包首字节 → MessageID 语义与编号未变。
- 差异: 无。
- 魔改结论: **基本一致(未魔改)**。
- 建议: 恢复 MessageID 为 byte;枚举按原序(int 4B)。网络协议层 ID_* 编号可直接信任源码。

---

## 汇总表

| 类型 | 原版大小(i386) | 二进制大小 | 差异类型 | 魔改结论 |
|---|---|---|---|---|
| RakNetGUID | 12B(g 8 + systemIndex 2,align 4) | 12B(cPendingConnection.pRakNetGUID byte[12]) | 无(12B=i386 ABI 自然大小;MSVC 下才是 16B) | 基本一致 |
| SystemAddress | 20B(addr4 16 + debugPort 2 + systemIndex 2,IPv6=0) | 20B(GetConnectionList 数组步长 20B) | 无(任务书 8B 属 RakNet 3.x 旧布局,不适用) | 基本一致 |
| RakString | 4B(SharedString*;SharedString=132B) | 4B(Free() 证实 sharedString@0 及静态 emptyString/freeList) | 无 | 基本一致 |
| RakPeerInterface | 4B(纯虚接口,vtable) | 4B 抽象基类;GetInstance→OP_NEW<RakPeer>,__ZThn4_ 次基类 thunk | 无 | 基本一致 |
| PacketPriority/Reliability | 枚举 int 4B;枚举序不变 | 符号名与源码签名逐参数一致 | 无 | 基本一致 |
| MessageID | unsigned char 1B | Receive 按字节比对 ID_TIMESTAMP=27 | 无 | 基本一致 |

## 结论与建议(给主 agent)
1. **基础类型零魔改**:五个基础类型(含两个枚举/typedef)在 DST 二进制中与原版 RakNet 4.x 源码完全一致。此前恢复出的 `rakNetGUID 12B`、`SystemAddress 20B` 数值正确,无需修正;建议把 SystemAddress 的证据锚点从空结构 tCheshireCat 换到 `RakPeer::GetConnectionList`(0x2288e8,步长 20B)。
2. 唯一需要留意的"差异"是 **ABI 层**:二进制为 Clang i386(uint64_t 4B 对齐),若恢复脚本按 MSVC 假设 8B 对齐会算错 RakNetGUID(16B)及任何含 uint64_t 字段的结构。恢复时应统一使用 4B 对齐。
3. DST 侧自定义(非 RakNet 魔改)注意区分:cPendingConnection 用 6B 紧凑 ip/port 对替代 SystemAddress;`cLuaNetworkVariableType<RakString>` 是 DST 封装。这些不应被当成 RakNet 结构体改动。
