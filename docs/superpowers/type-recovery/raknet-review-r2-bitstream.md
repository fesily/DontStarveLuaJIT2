# RakNet 对比审查 R2:BitStream

分片:RakR2_BitStream(只读,无任何 Ghidra/IDA 写入)
对比对象:`RakNet::BitStream`(3rd/RakNet/Source/BitStream.h / BitStream.cpp vs dontstarve_steam macOS i386)
预算:decompile 3/3 次(BitStream 默认 ctor 0x1F4DE6、3 参 C1 0x1F4F70、3 参 C2 0x1F4EDA)

## 源码原版(3rd/RakNet/Source/BitStream.h)

- 无基类、无虚函数(全部方法非虚,STATIC_FACTORY 为静态)→ 无 vtable,无基类偏移。
- `BitSize_t` = `uint32_t`(RakNetTypes.h:101);`BITSTREAM_STACK_ALLOCATION_SIZE` = 256(RakNetDefines.h:66)。
- 数据成员(私有,按声明顺序,BitStream.h:925-934):

| 偏移 | 成员 | 类型 | 大小 |
|------|------|------|------|
| 0x00 | `numberOfBitsUsed` | BitSize_t(u32) | 4 |
| 0x04 | `numberOfBitsAllocated` | BitSize_t(u32) | 4 |
| 0x08 | `readOffset` | BitSize_t(u32) | 4 |
| 0x0C | `data` | unsigned char* | 4 |
| 0x10 | `copyData` | bool | 1 |
| 0x11 | `stackData[256]` | unsigned char[256] | 256 |

- sizeof 估算:0x11 + 256 = 273 → 对齐 4 → **276 (0x114)**。注意 bool/uchar 对齐均为 1,`copyData` 与 `stackData` 之间无填充(内嵌缓冲从 +0x11 开始,不是 +0x14)。

## 二进制恢复

反编译/反汇编证据(均只读):
- 默认 ctor `__ZN6RakNet9BitStreamC1Ev` @0x1F4DE6:
  `[this+0]=0`(numberOfBitsUsed)、`[this+4]=2048=256<<3`(numberOfBitsAllocated)、`[this+8]=0`(readOffset)、`[this+0xC]=this+0x11`(data=stackData)、`[this+0x10]=1`(copyData=true)。
- 3 参 ctor `__ZN6RakNet9BitStreamC2EPhjb` @0x1F4EDA:
  `[this+0]=len<<3`、`[this+8]=0`、`[this+0x10]=copyData`、`[this+4]=len<<3`;`len>0xFF` → `rakMalloc_Ex(len,"…/foreign/build/raknet/BitStream.cpp",110)` 存入 `[this+0xC]`;`len<=0xFF` → `data=this+0x11` 且 `[this+4]=2048`;`len==0` → `data=0`;`!copyData` → `data=_data`。
- dtor `__ZN6RakNet9BitStreamD2Ev` @0x1F4FAA:
  `copyData([this+0x10])!=0 && [this+4]>0x801(2049)` → `rakFree_Ex([this+0xC],"BitStream.cpp",0x88=136)`。
- 二进制类大小:276B(0x114),由 `cNetworkVoiceManager::cNetworkVoiceManager` @0x18DA0C 直接证实:`operator new(0x114)` 后调用 BitStream ctor,指针存 `[ebx+4]`。

布局(六个字段全部与原版逐字节一致):+0x00 numberOfBitsUsed / +0x04 numberOfBitsAllocated / +0x08 readOffset / +0x0C data / +0x10 copyData / +0x11 stackData[256] / sizeof 276。

## cNetworkComponent+0x194 内嵌 BitStream 验证

- ctor `__ZN17cNetworkComponentC2Ev` @0x5ADEC:`lea ebp,[esi+194h]; call __ZN6RakNet9BitStreamC1Ev` → 在 `this+0x194` 就地构造 BitStream;随后 `mov [esi+2A8h],0`(= 0x194+0x114,即 nSerializeState)。
- ghidra 已恢复 cNetworkComponent(684B=0x2AC):`+404(0x194) | 276B | pBitStream`、`+680(0x2A8) | 4B | nSerializeState` —— 与反汇编完全吻合。
- 该成员是**按值内嵌**的完整 BitStream(含 256B 内嵌缓冲),非指针;ghidra 字段名 `pBitStream` 有误导。

## 差异

- 逐字段对比:0 差异。字段顺序、偏移、初始化常量(2048、0x801 阈值)、malloc/栈切换边界(`>0xFF` vs 源码 `<256`,语义等价)、以及 `rakMalloc_Ex`/`rakFree_Ex` 的文件:行号(`BitStream.cpp`:110 / :136)均与仓库源码 1:1。
- 二进制中存在 `_guard_variable_for_RakNet::BitStream`(guard 变量)与 Demangler 空壳类型,但 IDA/Ghidra 均未正式定义该结构(仅 stub)。
- "变体"排查:func_query/type_query/xrefs 全量扫描未发现任何 BitStream 派生类或改版布局;所有使用均为原版 BitStream,仅分配方式不同——内嵌成员(cNetworkComponent+0x194)、堆 `new`(cNetworkVoiceManager+4)、栈对象(cNetworkManager/cShardManager/cGiftingManager/cEntity::SerializeTags 等)、指针只读视图(3 参 ctor 包装 Packet::data,如 cShardManager 各 Handler)。

## 魔改结论

**基本一致(未魔改)**。二进制 BitStream 与原版 RakNet 4.x 布局完全一致,大小 276B = 原版 sizeof。

任务简报中 "cNetworkComponent+0x194 的 276B BitStream 是魔改证据" 的**前提不成立**:276B 恰好等于原版 `sizeof(RakNet::BitStream)`(0x11+256=273,4 对齐→276),并非魔改导致。若此前按其他值(如 272/280)估算原版大小,应以本报告推导的 276(0x114)为准。

## 建议

1. 修正恢复结果:`cNetworkComponent.pBitStream` 改名为 `bitStream`,类型由 `byte[276]` 改为正式 `RakNet::BitStream` 结构体(6 字段,276B,对齐 4)。
2. 在 Ghidra/IDA 中定义 `RakNet::BitStream`(字段见上表),可显著提升全部序列化/反序列化函数(cEntity、cTransformComponent、cPhysicsComponent、cShardManager、cNetworkRPCManager 等)反编译的可读性;定义依据已由 ctor/dtor 反汇编锁定,风险低。
3. cNetworkVoiceManager+0x04 为 `RakNet::BitStream*`(堆上 0x114),维持已恢复结果。
4. 主 agent 汇总时无需为 BitStream 增加"魔改"处理;其布局可信,可直接用于其余分片的偏移推算。

## 汇总表

| 类型 | 原版大小 | 二进制大小 | 差异类型 | 魔改结论 |
|------|---------|-----------|---------|---------|
| RakNet::BitStream | 276 (0x114) | 276 (0x114) | 无(布局/ctor/dtor 1:1) | 基本一致(未魔改) |
| cNetworkComponent+0x194 内嵌 BitStream | 276 | 276(0x194..0x2A8) | 使用方式特殊(按值内嵌),类本身无差异 | 原版 BitStream,非魔改 |
| BitStream 变体 | — | 不存在 | 全量扫描无派生/改版类 | 无变体 |
