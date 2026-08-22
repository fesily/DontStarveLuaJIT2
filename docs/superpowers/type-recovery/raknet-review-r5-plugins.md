# RakNet 插件类对比报告 (Slice R5: NatPunchthroughClient / Lobby2* / PluginInterface2 / FileListTransferCBInterface)

对比对象:DST 二进制 `dontstarve_steam`(Mach-O **i386 32位**,imagebase 0x1000,`__darwin_size_t`=4,uint64_t 对齐 4B)
vs 仓库源码 `3rd/RakNet/Source/`(RakNet 4.x)+ `3rd/RakNet/DependentExtensions/Lobby2/`(Lobby2 插件)。
二进制构建来源与仓库同源(DST 内嵌 RakNet;见 r4 报告引用的 jenkins 构建路径 `.../build/raknet/`)。
全程只读:Ghidra 侧仅用 get_struct_layout / decompile_function / search_functions / search_data_types / get_xrefs_to / read_memory;未做任何写入。

## 关键前提
- 仓库默认宏 `__GET_TIME_64BIT 1`(RakNetDefines.h @22-24、RakNetTime.h @21 强制定义,revisionlog 明示 "RakNetTime is now 64 bit by default")→ `RakNet::Time` = **uint64_t(8B)**。二进制 `GetTime()` 返回 longlong、时间运算全为 64 位(见下),与仓库默认一致。
- `RAKNET_SUPPORT_IPV6=0`(仓库默认)→ SystemAddress = 20B(r4 已证实);`_RAKNET_SUPPORT_TCPInterface=1`(NativeFeatureIncludes.h 默认)→ PluginInterface2 含 `TCPInterface* tcpInterface` 成员。
- i386 ABI(uint64_t 对齐 4):RakNetGUID = 12B(SystemAddress 20B 由 r4 证实,本片内部互验通过)。
- `DataStructures::List` = 12B(3×4:listArray/listSize/allocationSize);`DataStructures::Queue` = 16B(array/head/tail/allocation_size,DS_Queue.h @56-60)。
- std::map(GCC 4.x i386)= 24B(_Rb_tree_header 16B + _M_node_count 4B + allocator 补齐)。

---

### NatPunchthroughClient
- 源码原版: `class NatPunchthroughClient : public PluginInterface2`(NatPunchthroughClient.h @~112)。成员按声明序:
  - 基类 PluginInterface2 = vptr 4 + rakPeerInterface 4 + tcpInterface 4 = **12B**;
  - `struct SendPing sp`:nextActionTime(Time=8) + targetAddress(20) + facilitator(20) + internalIds[10](200) + targetGuid(12) + weAreSender(1) + pad3 + attemptCount(4) + retryCount(4) + punchingFixedPortAttempts(4) + sessionId(2) + sentTTL(1) + pad1 + testMode(4) = **284B = 0x11C**;
  - `unsigned short mostRecentExternalPort`(2B);
  - `PunchthroughConfiguration pc`:TIME_BETWEEN_PUNCH_ATTEMPTS_INTERNAL(Time 8) + TIME_BETWEEN_PUNCH_ATTEMPTS_EXTERNAL(8) + 8×int(32) + retryOnFailure(bool 1) = 49 → align 4 = **52B**;
  - `NatPunchthroughDebugInterface* natPunchthroughDebugInterface`(4B);
  - `DataStructures::List<AddrAndGuid> failedAttemptList`(12B);
  - `DataStructures::Queue<DSTAndFac> queuedOpenNat`(16B);
  - `unsigned short portStride`(2B);enum `hasPortStride`(4B);`RakNet::Time portStrideCalTimeout`(8B)。
  - 合计:12 + 0x11C + 2 + 52 + 4 + 12 + 16 + 2 + 4 + 8 = **0x190 = 400B**。
- 二进制恢复: **0x190 = 400B**(cNatTraversal @0 的 `pNatPunchthroughClient: byte[400]`)。Ctor `RakNet::NatPunchthroughClient::NatPunchthroughClient` @0x00219678 + Update @0x00219f04 逐字段锚定:
  - 0x00 vptr(vtable 0x0045b0e8);0x04 rakPeerInterface(Update 中 `*(int**)(this+4)` 调 vtable+0xdc);0x08 tcpInterface;
  - 0x0C sp.nextActionTime(8B,Update 以 `*(longlong*)(this+0xc)` 64 位读写);0x14 targetAddress(20B,SystemAddress ctor @0x14);0x28 facilitator(20B);0x3C internalIds[10](步长 0x14=20B,`attemptCount*0x14 + 0x3c` 索引);0x104 targetGuid(12B);0x110 weAreSender;0x114 attemptCount;0x118 retryCount;0x11C punchingFixedPortAttempts;0x120 sessionId(2B);0x122 sentTTL;0x124 testMode(switch 的 case 0..7 与源码 enum 顺序 TESTING_INTERNAL_IPS→PUNCHING_FIXED_PORT 逐一对应)→ sp = 0x0C..0x128;
  - 0x128 mostRecentExternalPort(2B,ctor 置 0);
  - 0x12C pc = 52B:0x12C=15 / 0x134=50(两个 64 位 Time,高字 @0x130/0x138 在 64 位加法中被引用:`nextActionTime += pc[0x134]` 时高字加 `pc[0x138]`)、0x13C=2 / 0x140=8 / 0x144=30 / 0x148=2 / 0x14C=100 / 0x150=200 / 0x154=200 / 0x158=5(与源码 ctor 默认值全同)、0x15C retryOnFailure=false;
  - 0x160 natPunchthroughDebugInterface(4B);0x164 failedAttemptList(12B);0x170 queuedOpenNat(16B);0x180 portStride(2B);0x184 hasPortStride=1(=UNKNOWN_PORT_STRIDE,与源码 enum 一致);0x188 portStrideCalTimeout(8B,Update 与 GetTime 高字比较)→ 止于 0x190。
- 差异: **无**。0x12C/0x134 的"额外 4 字节"实为 64 位 Time 的高字(仓库默认 `__GET_TIME_64BIT=1`),并非新增字段;若按 32 位时间假设计算才会得到 0x180,属假设错误而非魔改。
- 魔改结论: **基本一致(未魔改)**。二进制 0x190 与仓库源码(默认宏)逐字段、逐默认值吻合,含容器大小、枚举值、对齐。
- 建议: cNatTraversal 的 `pNatPunchthroughClient` 展开为完整 NatPunchthroughClient 布局(0x190),字段名/类型按上表;`RakNet::Time` 一律 8B。`sp` 可恢复为命名 struct SendPing(0x11C)。

### PluginInterface2
- 源码原版: `class PluginInterface2`(PluginInterface2.h)。数据成员:vptr(虚析构等 17 个虚函数)+ `RakPeerInterface* rakPeerInterface` + `TCPInterface* tcpInterface`(`_RAKNET_SUPPORT_TCPInterface=1` 默认)→ **12B**。
- 二进制恢复: **12B**(两处独立证据):
  - cSteamPunchthroughPlugin 多继承第二基类 `pPluginInterface2: byte[12] @4`,ctor @0x001beae6 显式调用 `PluginInterface2::PluginInterface2((PluginInterface2*)this+4)` 并写第二 vtable @0x004575bc → 子对象 12B(vptr+2 指针);
  - NatPunchthroughClient 基类 0..0x0C(见上)。
- 差异: 无。
- 魔改结论: **基本一致(未魔改)**。
- 建议: 恢复 PluginInterface2 = 12B(vptr + rakPeer + tcp);不必依赖单独 struct,可内联于各派生类基区。

### Lobby2Callbacks / Lobby2Client / Lobby2Plugin
- 源码原版:
  - `struct Lobby2Callbacks`(DependentExtensions/Lobby2/Lobby2Message.h @533):vptr(~120 个 MessageResult 虚函数)+ `uint32_t callbackId` + 静态 `nextCallbackId` → **8B**;
  - `class Lobby2Plugin : public PluginInterface2`:orderingChannel(1)+ packetPriority(4)+ msgFactory(4)+ callbacks List(12) = 12+24 = **36B**;
  - `class Lobby2Client : public Lobby2Plugin`:serverAddress(SystemAddress 20)+ callback(4) = 36+24 = **60B**。
- 二进制恢复:
  - cSteamPunchthrough = **70B**,基区 0..8 = **Lobby2Callbacks 精确 8B**:vptr @0(vtable 0x004572a8)+ nCallbackId @4;ctor @0x001bdafa 执行 `callbackId = nextCallbackId++`(`PTR_nextCallbackId_00450a60` 静态自增),与 `Lobby2Callbacks() {callbackId=nextCallbackId++;}` 一字不差。
  - **Lobby2Plugin/Lobby2Client 在二进制中不存在**:cSteamPunchthrough 直接继承 Lobby2Callbacks;cSteamPunchthroughPlugin 直接继承 PluginInterface2(无 orderingChannel/msgFactory/callbacks 段)。
- 差异: Lobby2 服务端消息框架(DependentExtensions,非 RakNet 核心)未被 DST 采用;仅保留了 Lobby2Callbacks 作为回调基类,并派生 DST 自有类。基类部分无改动。
- 魔改结论: Lobby2Callbacks **基本一致(未魔改)**;Lobby2Plugin/Lobby2Client **不适用(DST 未使用该层次,属 DST 侧选择,非魔改)**。
- 建议: cSteamPunchthrough 恢复为 `struct cSteamPunchthrough : Lobby2Callbacks`,基区 8B;整体 70B 的其余字段为 DST 自定义(见下节)。

### cSteamPunchthroughPlugin(多继承示例)
- 源码原版: 无对应类(Lobby2Plugin 层次未被使用)。对照物 = 源码 PluginInterface2 子对象 12B。
- 二进制恢复: **196B**(get_struct_layout;ctor @0x001beae6):
  - 0x00 基类A:vptr 4B(仅 vtable 的类,ctor 先写 `PTR_vtable_00450a70+8` 再改主 vtable)[INFERENCE: 应为 steamworks 回调基类,非 RakNet 类型];
  - 0x04 **PluginInterface2 子对象 12B**(vptr @0x004575bc + rakPeer + tcp)→ 与源码 PluginInterface2 完全一致;
  - 0x10 / 0x28 `CCallback<cSteamPunchthroughPlugin,P2PSessionRequest_t/ConnectFail_t,false>` 各 24B(steamworks,ctor 显式构造);
  - 0x40 / 0x58 / 0x70 / 0x94 / 0xAC 五个 std::map 各 24B(ctor 按 `_Rb_tree` 头初始化:节点指针 @+4..+0x10 自指、计数 @+0x14 清零):addressToSteamID / steamIDToAddress / idleTimers / timers2 / timers3;
  - 0x88=1、0x8C=-1、0x90=0 三个 int(DST 状态字段)。
  - 合计 4+12+48+120+12 = **196B** ✓。
- 差异: 二进制中 PluginInterface2 子对象与源码一致;其余为 DST 自有字段(steam P2P 会话表/定时器)。
- 魔改结论: 插件基类部分**基本一致**;整体为 DST 自定义扩展类。
- 建议: 恢复为 `struct cSteamPunchthroughPlugin { void* baseVtable; PluginInterface2 pluginInterface2; CCallback cb1, cb2; std::map m_addressToSteamID, m_steamIDToAddress, m_idleTimers; int f0x88, f0x8C, f0x90; std::map m_timers2, m_timers3; }`(196B)。

### FileListTransferCBInterface / cNetworkFileTransferCB
- 源码原版: `class FileListTransferCBInterface`(FileListTransferCBInterface.h):**无数据成员**,仅虚函数(虚析构 + OnFile + OnFileProgress + Update + OnDownloadComplete + OnDereference)→ **4B(vptr)**。
- 二进制恢复: **4B**,`cNetworkFileTransferCB = { pVtable }`,派生类未新增任何字段;仅实现虚函数(存在 ~cNetworkFileTransferCB @0x001657bc)。
- 差异: 无。
- 魔改结论: **基本一致(未魔改)**。
- 建议: 恢复 `struct cNetworkFileTransferCB { void* vtable; }`(4B);其内嵌的 OnFileStruct/FileProgressStruct/DownloadCompleteStruct 与 RakNet 侧一致,不在本片范围。

### cNatTraversal(DST 派生类,附带)
- 二进制: **408B**(get_struct_layout):base NatPunchthroughClient 400B @0 + `pDebugInterface` 4B @400 + `nField_0x194` 4B @404(ctor 置 5)。
- 注:ctor @0x00161b7a 对 `this->pDebugInterface` 直接解引用写 vtable(0x004509dc+8)并传给 SetDebugInterface → 该"指针"实为**内嵌的 cNatPunchthroughDebugInterfaceImpl 对象(4B,vtable only)**,建议把恢复字段从指针改为内嵌对象。`nField_0x194=5` = MAXIMUM_NUMBER_OF_INTERNAL_IDS_TO_CHECK 同值[INFERENCE]。
- 结论: DST 自有派生,基类与上节一致。

---

## 汇总表

| 类型 | 原版大小 | 二进制大小 | 差异类型 | 魔改结论 |
|---|---|---|---|---|
| PluginInterface2 | 12B(vptr+rakPeer+tcp) | 12B(两处子对象证据) | 无 | 基本一致 |
| NatPunchthroughClient | 0x190 = 400B(Time 64 位,仓库默认宏) | 0x190 = 400B(cNatTraversal 基区 byte[400]) | 无(0x190 即原版;0x180 是错误地假设 32 位 Time) | 基本一致 |
| Lobby2Callbacks | 8B(vptr+callbackId+静态 nextCallbackId) | 8B(cSteamPunchthrough 基区;nextCallbackId 自增证实) | 无 | 基本一致 |
| Lobby2Plugin / Lobby2Client | 36B / 60B | 二进制不存在该类层次 | DST 未采用(DST 侧选择) | 不适用(非魔改) |
| cSteamPunchthroughPlugin | —(DST 自定义;PI2 子对象 12B 为对照) | 196B(PI2 @4 子对象 12B 与源码一致) | DST 自定义扩展(steam 会话表/CCallback) | 基类一致,整体自定义 |
| cSteamPunchthrough | —(DST 自定义;Lobby2Callbacks 8B 为基类) | 70B | DST 自定义扩展 | 基类一致,整体自定义 |
| cNetworkFileTransferCB / FileListTransferCBInterface | 4B(vtable only,无数据成员) | 4B(仅 pVtable) | 无 | 基本一致 |
| cNatTraversal | —(DST 派生) | 408B = 400 + 4(内嵌 debug 接口)+ 4(int=5) | DST 自定义 | 基类 NatPunchthroughClient 一致 |

## 结论与建议(给主 agent)
1. **四个目标类型零魔改**。NatPunchthroughClient 二进制 0x190 与仓库源码(默认 `__GET_TIME_64BIT=1`)逐字段吻合:sp(0x11C)、pc(52B,含两个 64 位 Time)、容器大小(List 12B / Queue 16B)、枚举值(testMode 0..7、hasPortStride=1)全部对上。**此前"0x190 vs 原版"的疑惑来自假设 32 位 Time;仓库默认即 64 位,无需修正恢复结果,反而应把 RakNet::Time 恢复为 8B**。
2. 恢复修正建议:(a) cNatTraversal 的 `pDebugInterface` 应为内嵌 cNatPunchthroughDebugInterfaceImpl(4B)而非指针(ctor 直接对其解引用写 vtable);(b) 若有按 0x180 恢复 NatPunchthroughClient 的旧结果,应改为 0x190 布局(上表逐偏移);(c) cSteamPunchthroughPlugin 的 `byte[12] pPluginInterface2` 可命名为 PluginInterface2 子对象(vptr@4 + rakPeer@8 + tcp@12)。
3. 二进制时间语义:GetTime() 返回 64 位、时间比较为 64 位,网络包中时间戳 8B —— 与仓库 `__GET_TIME_64BIT=1` 一致,非 DST 改动。
