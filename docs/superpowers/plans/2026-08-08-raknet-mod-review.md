# RakNet 魔改对比 Review 计划

> 背景:仓库含原版 RakNet 4.x 源码(`3rd/RakNet/Source/`, 2014 Oculus VR, BSD)。二进制 `dontstarve_steam` 深度集成 RakNet,但 DST **魔改**了部分数据结构(如 Replica3 基类在二进制 = 0x158/344B,原版成员仅 ~40B + vtable)。
> 目标:对比「源码原版布局 vs 二进制恢复布局」,识别每个 RakNet 类型的魔改点,修正/确认我们的恢复结果。

## 已确认的魔改信号

| 类型 | 原版(源码) | 二进制(恢复) | 差异 |
|---|---|---|---|
| Replica3 基类 | ~40B 数据 + vtable(creatingGUID/deletingGUID/replicaManager/lastSentSerialization/lsr/referenceIndex) | **0x158 = 344B**(cNetworkReplica 基类段) | **巨大差距 — 魔改确认** |
| Connection_RM3 | 原版类定义缺失(仅前向声明) | **0x2A0**(cNetworkConnection 基类) | 需从 cpp 反推 |

## Review 方法(每类型)

1. **源码基准**:从 `3rd/RakNet/Source/*.h` 提取类成员定义,计算原版 sizeof(注意 32位 i386 指针 4B、std::vector/eastl 差异)
2. **二进制布局**:用已恢复的 struct + IDA/Ghidra 反编译 ctor/dtor 确认字段偏移
3. **对比**:逐字段比对原版 vs 二进制,识别:
   - 新增字段(魔改添加)
   - 删除字段
   - 字段重排/类型变更
   - 内联子对象展开
4. **输出**:每类型差异表 + 魔改结论

## Review 范围(二进制中实际使用的 RakNet 类型)

| 分片 | 类型 |
|---|---|
| R1 Replica3 族 | Replica3、Connection_RM3、ReplicaManager3、SerializeParameters、DeserializeParameters、LastSerializationResult |
| R2 BitStream | BitStream(276B 内嵌于 cNetworkComponent)、BitStream_MSB 等 |
| R3 RPC4 | RPC4Plugin、RPC4、cNetworkRPCManager 依赖 |
| R4 基础 | RakNetGUID、SystemAddress、RakString、PacketPriority/Reliability、RakPeerInterface |
| R5 网络组件 | NatPunchthroughClient、Lobby2、PluginInterface2、FileListTransferCBInterface |

## 执行

- 5 个只读对比 agent(每分片 1 个),读源码 + 反编译二进制,产出 `raknet-review-<slice>.md`
- 主 agent 汇总 `raknet-review.md`,识别需修正的恢复结果
- 有差异的 struct 由主 agent 统一回写修正

## 约束

- 源码阅读:`read`/`grep` 3rd/RakNet/Source/ 对应 .h
- 二进制:id alib-mcp 会话 e0ca1af1 + ghidra-mcp 只读
- 每类型 decompile ≤3 次
- 报告中文,符号英文
