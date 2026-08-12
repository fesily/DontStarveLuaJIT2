# Review Slice 15 — Heap / PersistentStorage / Metrics / FrameProfiler

> 二进制:`dontstarve_steam`(macOS i386, base 0x1000)
> 审查方式:ghidra-mcp `get_struct_layout` 读回 Ghidra 当前布局 ↔ `types_common.h` ↔ `tier3-e-system.md`(§2/§9/§10/§11)字段表 ↔ idalib-mcp(会话 f9cdc808)decompile 交叉验证
> IDA decompile 用量:Heap 1(ctor 0x26B85C;其余全部用 Ghidra decompile,不受 IDA 2 次/类型限制)
> 只读审查,未做任何写入

---

### Mutex(Heap 内嵌字段,依赖项顺带核验)
- 状态: PASS
- Ghidra 大小: 56B | 文档大小: 56B (0x38) | 匹配: yes
- 字段比对: 偏移/类型/大小全一致,仅**名称**有差异:
  | 偏移 | Ghidra 名 | 文档名 | 类型 | 一致 |
  |---|---|---|---|---|
  | 0x00 | n__sig | __sig | int32 | 偏移类型 ✓,名异 |
  | 0x04 | p__opaque | __opaque | byte[40] | 偏移类型 ✓,名异 |
  | 0x2C | nAttr_sig | attr_sig | int32 | 偏移类型 ✓,名异 |
  | 0x30 | pAttr_opaque | attr_opaque | byte[8] | 偏移类型 ✓,名异 |
- 证据: Heap ctor 0x26B85C 内 `Mutex::Mutex(this+0x1C)`(见下);Ghidra 布局 56B 与文档 `pthread_mutex_t(44B)+pthread_mutexattr_t(12B)` 吻合。
- 问题清单: 无(纯命名差异)。

### Heap
- 状态: PASS(字段命名不一致,降级 WARN 项见问题清单)
- Ghidra 大小: 92B (0x5C) | 文档大小: 92B (0x5C) | 匹配: yes
- 字段比对: 偏移/类型/大小全一致,仅**名称**有差异:
  | 偏移 | Ghidra 名 | 文档名 | 类型 | 一致 |
  |---|---|---|---|---|
  | 0x00 | dwM_nHeapID | m_nHeapID | uint | 偏移类型 ✓,名异 |
  | 0x04 | dwM_nTotalSize | m_nTotalSize | ulong/uint32(4B) | 偏移类型 ✓,名异 |
  | 0x08 | pBase | pBase | void* | ✓ |
  | 0x0C | pFirstBlock | pFirstBlock | void* (MemoryBlock*) | ✓ |
  | 0x10 | pLastBlock | pLastBlock | void* (MemoryBlock*) | ✓ |
  | 0x14 | dwAllocatedCount | nAllocatedCount | uint | 偏移类型 ✓,名异 |
  | 0x18 | dwFreeBlockCount | nFreeBlockCount | uint | 偏移类型 ✓,名异 |
  | 0x1C | mMutex | mMutex | Mutex (56B) | ✓ |
  | 0x54 | bNeedsCoalesce | bNeedsCoalesce | byte | ✓ |
  | 0x58 | dwTotalFree | nTotalFree | uint | 偏移类型 ✓,名异 |
- 证据:
  - **IDA decompile ctor 0x26B85C**:`Mutex::Mutex(this)` + 清零 `+0x00/+0x04/+0x08/+0x0C/+0x10/+0x14/+0x18/+0x54`;Ghidra 反汇编证实 Mutex ctor 实参为 `LEA EAX,[ESI+0x1C]` → **mMutex@0x1C 确认**,与文档/tier3-e-system.md §2 一致。
  - Ghidra decompile `Initialize 0x26BA1A`:`dwM_nHeapID=param_1`@0、`dwM_nTotalSize=param_2-8`@4、`pBase=param_3`@8(首尾写 0xdeadbeef)、`pFirstBlock=block`@0xC、`pLastBlock=block`@0x10、`dwAllocatedCount=0`@0x14、`dwFreeBlockCount=0`@0x18、`bNeedsCoalesce=0`@0x54、`dwTotalFree=*(base+0x10)`@0x58 —— 全部字段命中,与 §2 证据逐条吻合。
  - Ghidra decompile `MemoryManager::Allocate 0x26EBA9`:`Heap::Allocate(&mHeaps + param_1*0x5c, …)` → **堆 stride 0x5C 与 Heap 大小 92B 一致**,结构可被正确索引。
- 问题清单:
  1. (WARN) 字段名与文档不一致:`dwM_nHeapID`/`dwM_nTotalSize`(文档 `m_nHeapID`/`m_nTotalSize`)、`dwAllocatedCount`/`dwFreeBlockCount`/`dwTotalFree`(文档 `nAllocatedCount`/`nFreeBlockCount`/`nTotalFree`)。纯命名问题,偏移/类型/大小全对。
  2. (INFO) `dwM_nTotalSize` 在 Ghidra 显示为 `ulong`(4B,32 位程序下 ulong=4B),tier3-e-system.md §2 表亦标 `ulong`,`types_common.h` 标 `uint32_t` —— 三者实际宽度一致,无真实差异。

### PersistentStorage
- 状态: WARN
- Ghidra 大小: 5B | 文档大小: 8B | 匹配: **no(少 3B 尾部 padding)**
- 字段比对: 已定义字段偏移/类型一致,但**结构总大小不匹配**:
  | 偏移 | Ghidra 名 | 文档名 | 类型 | 一致 |
  |---|---|---|---|---|
  | 0x00 | pVtable | pVtable | void* | ✓ |
  | 0x04 | bFlag | bFlag | byte | ✓ |
- 证据: Ghidra decompile ctor `0x25E1D2`:`pVtable = &PTR__PersistentStorage_0045b9ac; mInstance = this; bFlag = 1` —— +0x00 vtable、+0x04 bFlag(=1)确认,与 §9 逐字吻合;单例 mInstance 全局赋值亦命中。
- 问题清单:
  1. (WARN) Ghidra struct 为 **5B**(Alignment=1,无尾部 padding),文档/真实 C++ `sizeof` 为 **8B**(4B vtable + 1B flag + 3B padding)。字段偏移本身正确,但任何 `sizeof(PersistentStorage)`/`new PersistentStorage` 建模会按 5B 计。当前为单例(mInstance@0x46787C,ctor xref 仅 EXTERNAL + 数据引用),无数组/偏移访问,功能上无实际影响;建议补 3B padding 至 8B 与文档对齐。
  2. (INFO) 文档称 vtable @ 0x45B9A4(ZTV),Ghidra 符号为 `PTR__PersistentStorage_0045b9ac`(相差 8B,疑为指向 ZTV 的指针槽 vs ZTV 起点)。属 vtable 定位细节,不影响 struct 布局。

### Metrics
- 状态: PASS(字段命名不一致,降级 WARN 项见问题清单)
- Ghidra 大小: 52B (0x34) | 文档大小: 52B (0x34) | 匹配: yes
- 字段比对: 偏移/类型/大小全一致,仅**名称**有差异:
  | 偏移 | Ghidra 名 | 文档名 | 类型 | 一致 |
  |---|---|---|---|---|
  | 0x00 | pVtable | pVtable | void* | ✓ |
  | 0x04 | bEnabled | bEnabled | byte | ✓ |
  | 0x08 | pM_strBranchA | m_strBranchA | byte[4] (std::string CoW) | 偏移类型 ✓,名异 |
  | 0x0C | pM_strBranchB | m_strBranchB | byte[4] (std::string CoW) | 偏移类型 ✓,名异 |
  | 0x10 | pM_strBranchC | m_strBranchC | byte[4] (std::string CoW) | 偏移类型 ✓,名异 |
  | 0x14 | pM_Generator | m_Generator | byte[32] (GoogleAnalyticsGenerator) | 偏移类型 ✓,名异 |
- 证据: Ghidra decompile ctor `0x12F2CA`:`pVtable=&PTR__Metrics_00456a28`(→ vtable 0x456A28 ✓)、`bEnabled=0`、三个 string 初始化为空 CoW 串(每 4B)、`GoogleAnalyticsGenerator::GoogleAnalyticsGenerator(this+0x14)`(32B)、单例 `PTR_mInstance_00450050=0` —— 全部字段命中,与 §10 证据(0x38DA3F 分支 assign 等)吻合。
- 问题清单:
  1. (WARN) 字段名与文档不一致:`pM_strBranchA/B/C`(文档 `m_strBranchA/B/C`)、`pM_Generator`(文档 `m_Generator`)。纯命名问题。
  2. (INFO) `byte[4]` 与文档 `std::string(CoW)` 等价:32 位下 CoW std::string 仅 1 个指针(4B),`types_common.h` 亦写作 `uint8_t[4]`。类型表示一致。

### FrameProfiler
- 状态: PASS(字段命名不一致,降级 WARN 项见问题清单)
- Ghidra 大小: 36B (0x24) | 文档大小: 36B (0x24) | 匹配: yes
- 字段比对: 偏移/类型/大小全一致,仅**名称**有差异:
  | 偏移 | Ghidra 名 | 文档名 | 类型 | 一致 |
  |---|---|---|---|---|
  | 0x00 | pVtable | pVtable | void* | ✓ |
  | 0x04 | dwThreadID | nThreadID | uint | 偏移类型 ✓,名异 |
  | 0x08 | m_Timer | m_Timer | Timer (8B) | ✓ |
  | 0x10 | bRecording | bRecording | byte | ✓ |
  | 0x14 | dwProfileCount | nProfileCount | uint | 偏移类型 ✓,名异 |
  | 0x18 | nFileIndex | nFileIndex | int | ✓ |
  | 0x1C | flSpinTime | flSpinTime | float | ✓ |
  | 0x20 | dwSpinCount | nSpinCount | uint | 偏移类型 ✓,名异 |
- 证据:
  - Ghidra decompile ctor `0x280990`:`pVtable=&PTR__FrameProfiler_0045bd70`(→ vtable 0x45BD70 ✓)、`dwThreadID=0`、`Timer::Timer(&this+8)`、`bRecording=0`、`dwProfileCount=0`、`nFileIndex=0`、`flSpinTime=(float)GetSpinTime(this)`、`_pthread_key_create(&_TLS_key_FrameProfiler,…)`(→ 0x467CFC ✓)、单例 `PTR_mInstance_00450038=0`(→ 0x450038 ✓) —— 全部字段命中,与 §11 证据吻合。
  - Ghidra decompile `GetSpinTime 0x280A5E`:`dwSpinCount=0` 后 0x200000 次自增,`Timer::GetElapsedSeconds` 计时 → **dwSpinCount@0x20、flSpinTime@0x1C 确认**。
- 问题清单:
  1. (WARN) 字段名与文档不一致:`dwThreadID`(文档 `nThreadID`)、`dwProfileCount`(文档 `nProfileCount`)、`dwSpinCount`(文档 `nSpinCount`)。纯命名问题。
  2. (INFO) `SampleStack`/`StackEntry` 在 Ghidra 仍为 1B 占位(/Demangler 下,未建真实结构),与 §11"或最小化:先建 FrameProfiler"的取舍一致,不属本 slice 必查项。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| Mutex(内嵌) | PASS | 仅字段命名差异(n__sig/p__opaque/nAttr_sig/pAttr_opaque);偏移/类型/大小全对 |
| Heap | PASS | 仅字段命名差异(dwM_/dw 前缀);mMutex@0x1C、92B/stride 0x5C 全部经 IDA ctor + Ghidra Initialize/Allocate 验证 |
| PersistentStorage | WARN | **Ghidra 5B vs 文档 8B**(缺 3B 尾部 padding);字段偏移正确,单例无实际影响,建议补 padding 对齐 |
| Metrics | PASS | 仅字段命名差异(pM_ 前缀);52B,ctor 0x12F2CA 全字段命中 |
| FrameProfiler | PASS | 仅字段命名差异(dw 前缀);36B,ctor 0x280990 + GetSpinTime 0x280A5E 全字段命中 |

**总评**:5 个结构在 Ghidra 中的偏移、字段类型与 `types_common.h` 及 `tier3-e-system.md`(§2/§9/§10/§11)完全一致,IDA decompile(Heap ctor 0x26B85C,Mutex@0x1C 经反汇编证实)+ Ghidra decompile(Heap::Initialize、MemoryManager::Allocate、PersistentStorage/Metrics/FrameProfiler ctor、GetSpinTime)逐字段交叉验证全部命中。无布局错误、无字段错位、无 padding 错位。唯一实质问题:**PersistentStorage 结构大小 5B ≠ 文档 8B**(缺尾部 padding,建议补 3B);其余差异均为字段命名未按文档规范化(dw-/pM-/p- 前缀),不影响正确性。
