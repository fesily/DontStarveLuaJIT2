# RakNet RPC4 魔改对比审查 — slice R3

**审查对象**: `RakNet::RPC4` (RPC4Plugin) 及其消息格式,二进制侧由 `cNetworkRPCManager::cNetworkRPCManager` (0x180258) 中 `pRPC4 = operator_new(0x150)` 创建的 RPC4 对象。
**二进制**: `dontstarve_steam` (Mach-O i386, gcc, image_base 0x1000),ghidra + idalib(e0ca1af1) 只读。
**源码**: `3rd/RakNet/Source/RPC4Plugin.h` / `RPC4Plugin.cpp` / `PluginInterface2.h` / `DS_Hash.h` / `DS_OrderedList.h` / `BitStream.h` / `MessageIdentifiers.h` / `PacketPriority.h`。
i386 32 位:指针 4B,对齐 4B。

---

## 一、原版来源 sizeof 推导

### 基类链
`RPC4 : public PluginInterface2`(单继承,无虚基)。
`PluginInterface2` 成员(原版):
- vtable(17 个虚函数)→ 4B
- `RakPeerInterface *rakPeerInterface` → 4B
- `TCPInterface *tcpInterface`(本构 `_RAKNET_SUPPORT_TCPInterface==1`)→ 4B
- 基类合计 **12B**(0x00 vtable,0x04 rakPeerInterface,0x08 tcpInterface)

### 容器大小(源码实测)
- `DataStructures::Hash<...>` = `Node **nodeList;` + `unsigned int size;` = **8B**
- `DataStructures::OrderedList<...>` = 内嵌 `DataStructures::List`(`T *listArray; unsigned list_size; unsigned allocation_size`) = **12B**
- `RakNet::BitStream` = `numberOfBitsUsed(4) + numberOfBitsAllocated(4) + readOffset(4) + data*(4) + copyData(1) + stackData[256]` = 273 → 对齐 **276B = 0x114**(与二进制 `cNetworkVoiceManager` 的 `new(0x114)` 一致,佐证容器尺寸计算正确)

### RPC4 数据成员(按声明顺序)
| # | 成员 | 类型 | 大小 | 偏移 |
|---|---|---|---|---|
| 1 | `localSlots` | Hash<RakString,LocalSlot*,256> | 8 | 0x0C |
| 2 | `registeredNonblockingFunctions` | Hash<RakString,fn,64> | 8 | 0x14 |
| 3 | `registeredBlockingFunctions` | Hash<RakString,fn,64> | 8 | 0x1C |
| 4 | `localCallbacks` | OrderedList<MessageID,LocalCallback*> | 12 | 0x24 |
| 5 | `blockingReturnValue` | BitStream | 0x114 | 0x30 |
| 6 | `gotBlockingReturnValue` | bool(对齐 4) | 4 | 0x144 |
| 7 | `nextSlotRegistrationCount` | unsigned int | 4 | 0x148 |
| 8 | `interruptSignal` | bool(对齐 4) | 4 | 0x14C |

**原版 sizeof = 12(基类+vtable) + 8+8+8+12+0x114+4+4+4 = 336 = 0x150**

---

## 二、二进制侧恢复

### RPC4 构造 (0x21fd4e)
```
PluginInterface2::PluginInterface2(this);
*(this) = &PTR_RPC4_0045b568;          // RPC4 vtable @0x45b568
this+0x0C=0; this+0x10=0;              // localSlots.nodeList/size
this+0x14=0; this+0x18=0;              // registeredNonblockingFunctions
this+0x1C=0; this+0x20=0;              // registeredBlockingFunctions
this+0x24=0; this+0x28=0; this+0x2C=0; // localCallbacks (List 3 dwords)
BitStream::BitStream(this+0x30);       // blockingReturnValue @0x30
this[0x144]=0;                         // gotBlockingReturnValue
this+0x148=0;                          // nextSlotRegistrationCount
this[0x14C]=0;                         // interruptSignal
```
**全部 8 个成员偏移与原版逐字节一致,size 0x150。**

### RPC4::OnReceive (0x22185c,~0x764B) — 消息解析
- `CMP data[0],0x4A`(ID_RPC_PLUGIN);不等 → 走 `localCallbacks`(RegisterLocalCallback)二分查找(`this+0x24` listArray / `this+0x28` size)。
- 相等 → `BitStream(packet->data,length,false)` + `IgnoreBytes(2)`。
- `data[1]==0x2`(ID_RPC4_SIGNAL)→ 读压缩 RakString 槽名 → `GetIndexOf(this+0x0C)`(localSlots)→ 遍历 slotObjects 逐个调用函数指针。
- `data[1]==0`(ID_RPC4_CALL)→ 读压缩函数名 + **读 1 bit 阻塞标志**;bit=1 → 查 `this+0x1C`(registeredBlockingFunctions),bit=0 → 查 `this+0x14`(registeredNonblockingFunctions);命中 → 以 `(userData, returnData, packet)` 调用函数指针;未命中 → 回 `ID_RPC_REMOTE_ERROR(0x49)+RPC_ERROR_FUNCTION_NOT_REGISTERED(0)`。
- `data[1]==1`(ID_RPC4_RETURN)→ `blockingReturnValue@0x30.Reset(); .Write(bsIn); gotBlockingReturnValue@0x144=true`。
- 阻塞返回包:构造 `AddressOrGUID(SystemAddress*)`(0x342024),`SendUnified(bs, IMMEDIATE_PRIORITY(0), RELIABLE_ORDERED(3), 0, addrOrGuid, false)`(0x21f1d8)。

### RPC4 vtable @0x45b568
17 个 PluginInterface2 虚函数 + 虚析构 D1/D0 双槽 = 18 槽 + 2 个 0 终止。已确认覆盖:`~RPC4`(D0 `0x220120`→D1 `0x21fe68`→operator delete)、`OnAttach`(0x2217b4)、`OnReceive`(0x22185c);其余空实现默认虚函数被 ICF 折叠为共享 1 字节 stub(OnDetach/Update/OnRakPeerStartup/OnNewConnection 等)。

### cNetworkRPCManager ctor (0x180258)
`pRPC4 = operator_new(0x150); RPC4::RPC4(pRPC4);` 随后调用 29 次 `RPC4::RegisterSlot(pRPC4, <单字符槽名>, ReceiveXxx, 0)`,槽名为 `'0'..'L'`(0x30..0x4C,来自 `ppSlotNames` 数组),映射到 `ReceiveLuaRPC / ReceiveLuaModRPC / ReceiveResumeRequest / … / ReceiveAchievementNotification`。同时 `pBitStream = operator_new(0x114); BitStream::BitStream(...)`。

---

## 三、差异与魔改结论

### <RakNet::RPC4>
- **源码原版**: 成员表见上,基类 PluginInterface2(12B)+ 8 成员,`sizeof = 0x150`。vtable 17 虚函数(虚析构 + OnAttach/OnReceive 覆盖)。
- **二进制恢复**: `new(0x150)`;ctor 逐字段零初始化 @0x0C/0x10/0x14/0x18/0x1C/0x20/0x24/0x28/0x2C/0x30/0x144/0x148/0x14C;vtable @0x45b568 17 虚函数 + 虚析构双槽;OnReceive 用 `0x0C/0x14/0x1C/0x24/0x30/0x144` 与源码容器语义完全吻合;dtor(D1 0x21fe68)清理 localSlots/localCallbacks(符号:OP_DELETE<LocalSlot>/<Hash::Node>/<LocalCallback>)。
- **差异**: 布局 **零差异**(字段名、类型、顺序、偏移、大小全部一致)。
- **魔改结论**: **RPC4 类本身基本一致 / 未做布局魔改**(大小 0x150 == 原版 0x150,无新增/删除/重排字段)。
- **建议**: cNetworkRPCManager 的 `pRPC4` 恢复为 `RakNet::RPC4*`(Tier 4 对象指针)、大小 0x150 正确,无需修正。

### 消息格式
- **源码原版**: `data[0]=ID_RPC_PLUGIN(0x4A)`,`data[1]=ID_RPC4_CALL(0)/ID_RPC4_RETURN(1)/ID_RPC4_SIGNAL(2)`(匿名枚举),随后 `WriteCompressed(RakString 函数名)`,CALL 再跟阻塞标志 bit;错误响应 `ID_RPC_REMOTE_ERROR(0x49)+RPC_ERROR_FUNCTION_NOT_REGISTERED(0)`。
- **二进制**: 与源码**完全一致**(0x4A/0x49 常量、0/1/2 子类型、压缩 RakString、阻塞 bit、错误码 0)。
- **差异**: 仅阻塞返回包发送优先级 `0`(IMMEDIATE_PRIORITY)vs 源码 `HIGH_PRIORITY(1)`;普通 CALL/SIGNAL 发送优先级 `1`(HIGH,与源码一致)。
- **魔改结论**: 消息格式**基本一致**(仅阻塞返回优先级一处微调,不影响布局)。

### 应用层(非 RakNet 内核改动)
- `cNetworkRPCManager` 用**单字符槽名 `'0'..'L'`(29 个)注册 Lua RPC 槽**代替人类可读函数名 —— 这是 Klei 在 RPC4 之上自定义的 RPC 分发方案(槽名压缩省带宽),**不改变 RPC4 类布局**,属应用层使用模式。

---

## 四、汇总表

| 类型 | 原版大小 | 二进制大小 | 差异类型 | 魔改结论 |
|---|---|---|---|---|
| RakNet::RPC4 | 0x150 (336B) | new 0x150 (336B) | 无(逐字段一致) | 基本一致(未布局魔改) |
| PluginInterface2(基类) | 0x0C (12B) | 0x0C (12B,rakPeer@0x04+tcp@0x08) | 无 | 一致 |
| RPC4 消息格式 | ID_RPC_PLUGIN(0x4A)+子类型 0/1/2 | 同左 | 阻塞返回优先级 0≠1 | 基本一致(微调) |
| cNetworkRPCManager(pRPC4) | — | 0x14,pRPC4@0x00 | 应用层 | 29 个单字符槽注册,非内核改动 |

**结论**: `RakNet::RPC4` 在 DST 二进制中与仓库原版 RakNet 4 源码布局**完全一致(0x150)**,魔改发生在应用层(cNetworkRPCManager 用单字符槽名注册 29 个 Lua RPC 槽),RPC4 类与消息格式均未做结构性改动。已恢复的 `cNetworkRPCManager` 布局(0x14,pRPC4@0x00)建议维持,无需修正。