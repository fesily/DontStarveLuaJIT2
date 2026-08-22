# RakNet 魔改对比 Review 汇总 (2026-08-08)

> 5 个只读对比 agent(R1-R5)对比二进制 RakNet 布局 vs 仓库原版源码(3rd/RakNet/Source/, RakNet 4.x, 2014 Oculus VR)。
> 分片报告:raknet-review-r1-replica3.md / r2-bitstream.md / r3-rpc4.md / r4-basic.md / r5-plugins.md
>
> **源码迁移状态 (2026-08-10):** 三处魔改已回写到 `3rd/RakNet/Source/ReplicaManager3.h/.cpp`。
> - `Replica3::OnUserReplicaPostSerializeTick` 虚函数 + `Update` 调用 + `Replica3Composite` 转发
> - `Connection_RM3::UNKNOWN_0x29C`(+4B → 0x2A0) + `CheckSendInitialDownloadStarted/Complete/CheckSendFrameComplete`
> - `ReplicaManager3` 成员按二进制 0x45C 布局(`UNKNOWN_0x1C/24/2C/34` + 字段后移); ctor 同步初始化
> i386 布局自检: ReplicaManager3=1116(0x45C)、Connection_RM3=672(0x2A0)。未命名字段仍为 `UNKNOWN_*`。
>
> **Ghidra 正式 struct (2026-08-10, program=`dontstarve_steam`):**
> - `BitStream` 276 · `RakNetGUID` 12 · `SystemAddress` 20 · `PRO` 16 · `PluginInterface2` 12 · `NetworkIDObject` 24 · `RakNetList` 12
> - `LastSerializationResultBS` 280 · `LastSerializationResult` 16 · `SerializeParameters` 328 · `DeserializeParameters` 292 · `RM3World` 32
> - `Replica3` 344 · `Connection_RM3` 672 · `ReplicaManager3` 1116 · `cNetworkReplicaManager` 5752
> - 已接线: `cNetworkReplica.base=Replica3` · `cNetworkConnection.base=Connection_RM3` · `cNetworkComponent.replica3/bitStream`

## 核心结论

**用户判断正确**:DST 魔改了 RakNet,但**魔改集中在 Replica3 族(虚表/管理器)**,大部分核心类型(网络传输层)未魔改。

## 逐类型对比结果

| 类型 | 原版 | 二进制 | 结论 |
|---|---|---|---|
| BitStream | 276B | 276B | ✅ 完全一致(布局 1:1) |
| RPC4 | 0x150 | 0x150 | ✅ 一致(仅阻塞返回用 IMMEDIATE 优先级) |
| RakNetGUID | 12B | 12B | ✅ 一致(Clang i386 4B 对齐,非 MSVC 16B) |
| SystemAddress | 20B | 20B | ✅ 一致(RAKNET_SUPPORT_IPV6=0) |
| RakString | 4B | 4B | ✅ 一致(真 RakNet 实现,非 eastl 替换) |
| RakPeerInterface | 4B | 4B | ✅ 一致(抽象接口) |
| PacketPriority/Reliability/MessageID | — | — | ✅ 一致 |
| NatPunchthroughClient | 0x190 | 0x190 | ✅ 一致(Time=8B 是 __GET_TIME_64BIT=1) |
| PluginInterface2 | 12B | 12B | ✅ 一致 |
| Lobby2Callbacks | 8B | 8B | ✅ 一致 |
| FileListTransferCBInterface | 4B | 4B | ✅ 一致 |
| SerializeParameters | 328B | ≈328B | ✅ 基本一致 |
| DeserializeParameters | 292B | 292B | ✅ 一致 |
| LastSerializationResult | 16B | 16B | ✅ 一致 |
| **Replica3** | 0x158 | 0x158 | ⚠️ **数据一致,虚表魔改**(40槽 vs 45,新增 PostSerializeTick@22,槽移位) |
| **Connection_RM3** | 0x29C | **0x2A0** | ⚠️ **+4B 尾成员**(魔改添加,语义未定) |
| **ReplicaManager3** | 0x440 | **0x45C** | ⚠️ **+28B + 字段重排**(魔改,新增 3×8B 字段) |

## 魔改点详述

### 1. Replica3 虚表(明确魔改)
- 40 虚函数槽 vs 原版 ~45
- **新增 `OnUserReplicaPostSerializeTick`**(slot 22,仓库头文件无此函数)
- `OnPoppedConnection` 移位至 slot 18
- `QuerySerialization` 签名改为 `(replica, lsr)` — DST 重写构造/发送钩子

### 2. Connection_RM3(+4B)
- 原版 0x29C → 二进制 0x2A0,尾部 +4B 成员
- 基类 ctor 不初始化(语义未定,可能是 DST 附加状态)
- 新增 3 个非虚方法:CheckSendInitialDownloadStarted/Complete/CheckSendFrameComplete

### 3. ReplicaManager3(+28B)
- 原版 0x440 → 二进制 0x45C
- PRO@12 之后新增 3×8B 字段(@28/@40/@48),autoSerializeInterval 移到 @56
- Update 重写:awake/asleep 系统、SetAutoSerializePerTicks、按帧下载检查

## 对恢复结果的影响(主 agent 修正确认)

| 项 | 状态 |
|---|---|
| cNetworkReplica 354B(0x162) | ✅ 正确(4 派生字段 10B) |
| cNetworkConnection 676B(0x2A4) | ✅ 正确(基类 0x2A0 + int) |
| cNetworkRPCManager 20B | ✅ 正确(pRPC4 0x150 指针) |
| cNatTraversal 408B | ✅ 正确(pDebugInterface 内嵌 4B 已建) |
| cNetworkVoiceManager 20B | ✅ 正确(BitStream 0x114 指针) |
| cNetworkComponent BitStream@0x194 | ✅ 正确(276B 原版) |
| **RakNet::Time = 8B** | ⚠️ 时间戳/超时字段按 8B 处理(新认知) |
| **ABI: Clang i386, uint64 4B 对齐** | ⚠️ 恢复用 4B 对齐(非 MSVC 8B) |

## 建议(后续可选)

1. **为 RakNet::BitStream 建正式 struct**(6 字段 276B)— 提升序列化函数反编译可读性
2. **Replica3/Connection_RM3/ReplicaManager3 按二进制布局建模**(Tier 4 段)— 需时再做
3. 魔改的虚表槽(PostSerializeTick)若需精确,查 DST 游戏侧源码(不在本仓库)
