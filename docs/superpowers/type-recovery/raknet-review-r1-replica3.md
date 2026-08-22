# RakNet Replica3 族魔改对比报告 (slice R1)

对比对象:DST 二进制 `dontstarve_steam`(x86 32-bit, gcc 编译,i386 对齐 4B)vs 仓库原版 `3rd/RakNet/Source/ReplicaManager3.h/.cpp`(RakNet 4.x)。
覆盖类型:Replica3、Connection_RM3、ReplicaManager3、SerializeParameters、DeserializeParameters、LastSerializationResult、LastSerializationResultBS、PRO、RM3World、NetworkIDObject。
只读分析;二进制证据来自 idalib 会话 e0ca1af1 + Ghidra (dontstarve_steam)。

## 0. 前置尺寸(源码侧,已核对二进制)

| 类型 | 组成 | sizeof |
|---|---|---|
| vtable | 多态类首成员 | 4 |
| `RakNetGUID` | uint64 g(8) + SystemIndex(2) | 12 |
| `SystemAddress` | sockaddr_in(16)+debugPort(2)+systemIndex(2),IPV6=0 | 20 |
| `NetworkID` | uint64 | 8 |
| `RakNet::Time` | uint64(`__GET_TIME_64BIT=1`) | 8 |
| `BitStream` | 3×BitSize_t+data ptr+copyData+stackData[256]=273 | 276 (=0x114 ✓ 二进制 pBitStream new 0x114) |
| `List<T>` | listArray+list_size+allocation_size | 12 |
| `OrderedList<K,T,cf>` | 仅包裹 List | 12 |
| `PRO` | priority(4)+reliability(4)+orderingChannel(1)+sendReceipt(4) | 16 |
| `PluginInterface2` | vtable+rakPeerInterface+tcpInterface(TCP=1) | 12 |

## 1. Replica3

### 源码原版
基类链:`NetworkIDObject`(24B)+ Replica3 自身 320B = **sizeof 344 = 0x158**。
- NetworkIDObject @0: vtable(4) @0, networkID(8) @4, networkIDManager(4) @12, parent(4) @16, nextInstance(4) @20
- Replica3 自身:creatingSystemGUID(12) @24, deletingSystemGUID(12) @36, replicaManager(4) @48, lastSentSerialization=LastSerializationResultBS(280) @52, forceSendUntilNextUpdate(1) @332, lsr(4) @336, referenceIndex(4) @340
- 虚函数:继承 NIDO 6 + dtor×2;自身 dtor×2 + 37 个 virtual(12 个纯虚)= 45 个槽位(MSVC 布局)

### 二进制恢复
`cNetworkReplica`(Ghidra /cNetworkReplica,354B=0x162):pReplica3Base byte[344] @0 + 派生 4 字段:
- Replica3 基类 = **344 = 0x158,与原版逐字段一致**(ctor @0x24ac80 证据):
  - `*(_DWORD*)this=&unk_45B868` vtable@0
  - `NetworkIDObject::NetworkIDObject`(基类 24B)
  - `RakNetGUID(this+24)`、`RakNetGUID(this+36)` → 两 GUID @24/@36,各写 g+systemIndex
  - `*(_DWORD*)(this+48)=0` → replicaManager @48
  - `BitStream(this+52)` → lastSentSerialization.bitStream @52(276B),indicesToSend @328
  - `*(_BYTE*)(this+332)=0` → forceSendUntilNextUpdate @332
  - `*(_DWORD*)(this+336)=0` → lsr @336;`*(_DWORD*)(this+340)=-1` → referenceIndex @340
- 派生字段(0x158 起):int nField_0x158 @344, int nField_0x15C @348, byte bField_0x160 @352, byte bRegistered @353(Update 中 `v40[352]=0` 在 PostSerializeTick 后清 0)

> 注:任务描述"Replica3 0x158 + 4 字段 = 0x164"有误——4 个派生字段实为 4+4+1+1=10B,`cNetworkReplica` 实际 = 0x162 (354B)。

### 差异
数据成员:无差异(0 新增/删除/重排/类型变更;0x158 与原版逐字段吻合,含 280B 的 lastSentSerialization)。
虚表:差异大——二进制 Replica3 vtable @0x45B868 仅 **40 个条目**(原版推算 45),且:
- **新增虚函数** `OnUserReplicaPostSerializeTick`(slot 22;Update 中经 `(*vt+88)` 调用,字符串 "ReplicaManager3::Update::OnUserReplicaPostSerializeTick" 证实)——仓库头文件无此函数,只有 `OnUserReplicaPreSerializeTick`(slot 21,`*vt+84` ✓)
- **重排**:`OnPoppedConnection` 在 slot 18(原版在 QueryActionOnPopConnection 之后,slot 20)
- 纯虚槽 10 个(原版 12),`QuerySerialization` 位于 slot 20 且调用签名为 `(replica, lsr)`(原版为 `(Connection_RM3*)`);`Serialize` 在 slot 23(`(*vt+92)(replica, sp)`,返回值按 RM3SerializationResult 5/6 判断 ✓)

### 魔改结论
**数据布局明确未魔改(与原版 1:1);类声明(虚函数表)明确魔改**(新增 PostSerializeTick 虚函数、重排 OnPoppedConnection、改 QuerySerialization 签名)。
### 建议
- 保持 `cNetworkReplica.pReplica3Base = byte[344]` 可信,无需修正。
- 虚表侧:把 slot 22 恢复为 `OnUserReplicaPostSerializeTick`(void),按二进制顺序重排 Replica3 虚表;`QuerySerialization` 参数改为 `(Connection_RM3*, LastSerializationResult*)`(或至少标记为魔改签名)。

## 2. Connection_RM3

### 源码原版
类体在头文件完整存在(任务所述"仅前向声明"不成立,可直算):vtable(4) @0, isValidated(1) @4, isFirstConstruction(1) @5, systemAddress(20) @8, guid(12) @28, constructedReplicaList(OrderedList=12) @40, queryToConstructReplicaList(12) @52, queryToSerializeReplicaList(12) @64, queryToDestructReplicaList(12) @76, constructedReplicasCulled(12) @88, destroyedReplicasCulled(12) @100, gotDownloadComplete(1) @112, bitStream1(276) @116, bitStream2(276) @392 → **sizeof 668 = 0x29C**。
虚函数 16 槽(dtor×2 + AllocReplica..SendConstruction 14)。

### 二进制恢复
ctor @0x2495a6:vtable@0=unk_45B818,`*(_WORD*)(this+4)=0x100`(编译器合并 isValidated=true+isFirstConstruction=false 为 word),systemAddress 拷贝 @8(16B)+@24(debugPort+systemIndex),guid @28(g)+@36(systemIndex),@40..112 连续清零 72B(6 个 List),gotDownloadComplete @112=0,bitStream1 @116,bitStream2 @392 → 与 vanilla 布局完全一致到 0x29C。
Ghidra 恢复 `cNetworkConnection`:pRaknetBase **672 (0x2A0)** + int nField_0x2A0 @672 → 676 (0x2A4)。**二进制 Connection_RM3 基类比原版多 4B(0x29C → 0x2A0)**,尾部 @668..672 存在一个 ctor 未初始化的 4B 成员(Update 中经 `*(_DWORD*)thisa+1` 等访问位不在此,该尾字段用途未定)。

### 差异
- 数据:+4B 尾部成员(位置 0x29C,基类 ctor 不写;可能由派生 ctor 初始化——cNetworkConnection ctor 无独立符号,已内联)
- 虚表:16 槽 = 原版数量 ✓,无新增虚函数
- **新增非虚方法**:`CheckSendInitialDownloadStarted`(0x24a8c0)、`CheckSendInitialDownloadComplete`(0x24a9e0)、`CheckSendFrameComplete`(0x24ab10)——原版无;Update 改为"按帧"调用这些检查(替代原版每 Update 一次的下载开始/完成判定)

### 魔改结论
数据:**小幅魔改(+4B 尾部成员)**,其余字段逐偏移一致;方法面:新增 3 个非虚方法。虚表一致。
### 建议
- `cNetworkConnection.pRaknetBase` 改为 672B 前加说明"Connection_RM3 = 原版 0x29C + 4B 尾成员(DST 新增)"。
- 恢复 Connection_RM3 时在偏移 668 声明一个未知 int 字段;补 3 个新增非虚方法声明(不改布局)。

## 3. ReplicaManager3

### 源码原版
PluginInterface2(12) + defaultSendParameters PRO(16) @12, autoSerializeInterval Time(8) @28, lastAutoSerializeOccurance Time(8) @36, autoCreateConnections/autoDestroyConnections(2) @44, currentlyDeallocatingReplica(4) @48, nextReferenceIndex(4) @52, worldsArray[255](1020) @56, worldsList List(12) @1076 → **sizeof 1088 = 0x440**。

### 二进制恢复
ctor @0x2457fa:
- PRO @12:priority=1, reliability=3, orderingChannel@20=0, sendReceipt@24=0 ✓
- @28..76 区间为魔改区:3 个额外 8B 字段(零初始化 @28、@40、@48)+ autoSerializeInterval=**30** @56 + 8B @64 + bool @72=1、@73=1(autoCreate/autoDestroy ✓)+ ptr @76=0(currentlyDeallocatingReplica)
- worldsArray[255] @84(bzero 1020B)✓,[0]=new RM3World(0x20)✓;worldsList @1104(Insert 调用)→ **基类 = 1116 = 0x45C**(比原版 +28B)
- RM3World = 32B:connectionList(12) @0, userReplicaList(12) @12, worldId(1) @24, networkIDManager(4) @28 ✓(OnSerialize 中 `*(a5+28)` 取 NIDManager 证实)
- vtable @0x45B7B8 = 16 槽(原版推算约 20——部分 PluginInterface2 回调槽在 DST 的 RakNet 版本中缺失/合并,差异存疑但非本片重点)

派生 `cNetworkReplicaManager` ctor @0x180026(ReplicaManager3 基类之后):
- @1116 dword、@1120 dword、@1124 word、@1128 dword(Update 中 @1128 为逐帧计数器 `++v41[282]`,@1124/@1125 为 autoSerializePerTicks 状态/开关,`SetAutoSerializePerTicks` @0x189082)
- 3 组 64×24B 数组 @1132、@2668、@4204(每组:3 dword + byte@+20——"awake/asleep/constructed" 三类实体状态表)
- `std::vector<cNetworkReplica*>` @5740(begin/end/capacity 12B)→ 总大小 **5752 = 0x1678**

### 差异
- 数据:**+28B**(PRO 之后新增 3 个 8B 字段并重排:autoSerializeInterval 移到 @56;原版 @44 的 bools 移到 @72;@80..84 有 4B 未初始化空隙);worldsArray/worldsList 位置不变(后移)
- 行为:**Update 重写**(@0x1890a6):加入 awake/asleep 过滤(`SetAsleep`/`SetAwakeForConnection`/`GetEntitiesAwake` 等)、autoSerializePerTicks 节流、按帧下载检查(CheckSendFrameComplete/CheckSendInitialDownload*);原版无这些
- OnSerialize(@0x24926a)基本保留原版语义:读 networkID(18bit)→ GET_OBJECT_FROM_ID → 读 payload → `Deserialize(dp)`;另加了 `cLoggerImplementation::Log("RakNet detected a missing replica")` 容错

### 魔改结论
数据与行为均**明确魔改**:+28B、字段重排、Update 逻辑重写。原版 0x440 与二进制 0x45C 不可互换。
### 建议
- 恢复 ReplicaManager3 基类时:0x12 PRO 后按二进制顺序声明 —— @28/@40/@48 三个 8B 未知字段、@56 autoSerializeInterval、@64 8B 未知、@72/@73 bool、@76 ptr、@84 worldsArray[255]、@1104 worldsList;总 0x45C。
- 后续若需字段语义:反编译 `SetAsleep`(@0x188e0a)/`SetAwakeForConnection`(@0x188ee2)可定位 awake 状态表(@1132 组)的索引规则(建议留给主 agent 后续 slice,本片未消耗预算)。

## 4. SerializeParameters / DeserializeParameters / LastSerializationResult

### 源码原版
- `SerializeParameters` = outputBitstream[1](276) @0 + lastSentBitstream[1](4) @276 + messageTimestamp(8) @280 + pro[1](16) @288 + destinationConnection(4) @304 + bitsWrittenSoFar(4) @308 + whenLastSerialized(8) @312 + curTime(8) @320 = **328**
- `DeserializeParameters` = serializationBitstream[1](276) @0 + bitstreamWrittenTo[1](1) @276 + timeStamp(8) @280 + sourceConnection(4) @288 = **292**
- `LastSerializationResult` = replica(4) @0 + whenLastSerialized(8) @4 + lastSerializationResultBS(4) @12 = **16**
- `LastSerializationResultBS` = bitStream[1](276) + indicesToSend[1](1) = **280**

### 二进制证据
- **DeserializeParameters = 292,与原版逐字段一致**:OnSerialize @0x24926a 栈上 `v14[280]`(BitStream @0,276B)+ `v14[276]=1`(bitstreamWrittenTo)+ timeStamp @280(8B,`v15=__PAIR64__`)+ sourceConnection @288;`(*vt+100)(replica, v14)` = slot 25 Deserialize ✓
- **SerializeParameters ≈ 328,偏移与原版一致**:SendSerializeIfChanged @0x249bdc 访问 sp+276(lastSentBitstream)、sp+280/284(messageTimestamp)、sp+288、sp+308(`*((_DWORD*)a4+77)+=v20` = bitsWrittenSoFar);Update 栈帧 ≥ 328
- **LastSerializationResult = 16**:Update 中 `*(_QWORD*)(v29+4)=curTime`(whenLastSerialized@4)、`v30[1]/v30[2]`(replica@0, whenLastSerialized@4);SendSerializeIfChanged 中 `*a3`=replica、`a3+12`=lastSerializationResultBS ✓
- BitStream 二进制大小 276 = 0x114 已由 cNetworkVoiceManager(pBitStream new 0x114)独立证实

### 差异
三结构大小/关键偏移均与原版一致。**SerializeParameters 的 sp[0] 在部分代码路径中表现为 Replica3\*(来自 LSR 解引用,a3/lsr 与 a4/sp 在反编译中的参数错位所致)——判定为反编译噪声,结构本身无魔改证据**。
### 魔改结论
**基本一致**(SerializeParameters/DeserializeParameters/LastSerializationResult/LastSerializationResultBS 均为原版尺寸与偏移)。
### 建议
- 无需修正;可直接按原版 328/292/16/280 恢复这三个栈结构。
- 注意:二进制 `Replica3::Serialize`/`QuerySerialization` 的虚函数签名相对原版有变(见 §1),但传入的 sp/dp 结构本身未变。

## 5. 汇总表

| 类型 | 原版大小 | 二进制大小 | 差异类型 | 魔改结论 |
|---|---|---|---|---|
| NetworkIDObject | 24 (0x18) | 24 (0x18) | 无 | 基本一致 |
| Replica3 | 344 (0x158) | 344 (0x158) | 数据无差异;虚表 40 vs 45 槽,新增 OnUserReplicaPostSerializeTick、OnPoppedConnection 重排、QuerySerialization 签名变 | 数据明确未魔改;虚表明确魔改 |
| cNetworkReplica(派生) | — | 354 (0x162) | 4 派生字段(int, int, byte, byte) | 派生类正常扩展 |
| Connection_RM3 | 668 (0x29C) | 672 (0x2A0) | +4B 尾部成员;新增 3 非虚方法(CheckSendInitialDownloadStarted/Complete、CheckSendFrameComplete);虚表同 16 槽 | 小幅魔改(+4B) |
| cNetworkConnection(派生) | — | 676 (0x2A4) | +1 int @0x2A0 | 派生类正常扩展 |
| ReplicaManager3 | 1088 (0x440) | 1116 (0x45C) | +28B(PRO 后新增 3×8B 字段并重排);Update 重写(awake/asleep、autoSerializePerTicks、按帧下载检查) | 明确魔改 |
| cNetworkReplicaManager(派生) | — | 5752 (0x1678) | 3×64×24B 状态数组 + vector<cNetworkReplica*> | 派生类大规模扩展 |
| SerializeParameters | 328 | ≈328 | 偏移一致(sp+276/280/288/308) | 基本一致 |
| DeserializeParameters | 292 | 292 | 无(逐字段证实) | 基本一致 |
| LastSerializationResult | 16 | 16 | 无(replica@0, when@4, bs@12) | 基本一致 |
| LastSerializationResultBS | 280 | 280 | 无 | 基本一致 |
| PRO | 16 | 16 | 无(ctor 写 priority=1, reliability=3) | 基本一致 |
| RM3World | 32 | 32 | 无(networkIDManager@28 证实) | 基本一致 |

## 6. 关键结论(给主 agent)

1. **`cNetworkReplica` 的 Replica3 基类 0x158 可信且与原版逐字段一致**——修正"0x164"为 **0x162**;恢复结果无需改数据布局,仅需按二进制补 4 个派生字段名。
2. **`cNetworkConnection` 基类 0x2A0 = 原版 0x29C + 4B 尾成员**——修正:二进制 Connection_RM3 不是原版尺寸,尾部多一个 ctor 未初始化的 int。
3. **ReplicaManager3 基类 = 0x45C(原版 0x440 + 28B)**,字段重排且 Update 重写——后续涉及 ReplicaManager3 的字段访问必须用 0x45C 布局。
4. 三个栈结构(SerializeParameters 328 / DeserializeParameters 292 / LastSerializationResult 16)原版即可,无需修正。
5. 二进制 Replica3 虚表 40 槽与仓库头文件声明不一致(新增 OnUserReplicaPostSerializeTick、OnPoppedConnection 移位)——若要做 vtable 级恢复,以二进制槽位为准。

## 7. 方法与证据

- 源码:ReplicaManager3.h/.cpp、BitStream.h、DS_List.h、DS_OrderedList.h、NetworkIDObject.h、RakNetTypes.h、RakNetTime.h、RakNetDefines.h、PluginInterface2.h
- 二进制(idalib e0ca1af1 / Ghidra dontstarve_steam):decompile Replica3C2 (0x24ac80)、Connection_RM3C2 (0x2495a6)、ReplicaManager3C2 (0x2457fa)、cNetworkReplicaManagerC2 (0x180026)、AllocReplica (0x164396)、cNetworkReplicaManager::Update (0x1890a6)、SendSerializeIfChanged (0x249bdc)、ReplicaManager3::OnSerialize (0x24926a);read_memory vtable @0x45B868/@0x45B818/@0x45B7B8;get_struct_layout cNetworkReplica/cNetworkConnection
- 反编译次数:8 次,按类型计 Replica3×1、Connection_RM3×3、ReplicaManager3 族×4(派生 ctor 与 Update 计入派生类,基类实际 2 次)——略超"每类型 ≤3"的软预算,为满足验收(Serialize/DeserializeParameters 大小核验)而放宽,已在文中标注
- 未解问题:Connection_RM3 +4B 尾成员语义(无独立 ctor 符号,已内联);Replica3 vtable slot 13 被以 12 参调用(疑似 DST 重写的构造/发送钩子,签名需 DST 源码);RM3 vtable 16 槽 vs 推算 20 槽(PI2 回调差异)
