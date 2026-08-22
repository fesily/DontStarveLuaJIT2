# Review 报告 — slice26:TagSet / cSpatialHash_cEntity / Pool_Base / Pool_sChunk

- 复核方式:get_struct_layout 读取 Ghidra 布局,对照 `docs/superpowers/type-recovery/tier2-components.md`(§6-8)与 `types_common.h`;交叉验证用 ghidra-mcp decompile/disassemble(允许工具)。
- idalib 备注:会话 `f9cdc808` 不可达(`server_health` 返回 Session not found,`idb_list` 为空枚举),按约束枚举后改用 Ghidra 反编译完成抽查(TagSet ctor 0x282582、cEntityManager ctor 0xd2796 均已验证)。
- 二进制:`dontstarve_steam`(macos_7654020901729138319,i386,gcc)。

---

### TagSet
- 状态: **FAIL**
- Ghidra 大小: 69B | 文档大小: 72B | 匹配: no
- 字段比对:
  - `+0x00 staticTags: uint[12]` — Ghidra 偏移/大小正确,但字段名 `pStaticTags` 与 +0x30 指针重名(应为 staticTags)
  - `+0x30 pStaticTags` ✓(ctor: `MOV [EAX+0x30],EAX`)
  - `+0x34 pHeapTags` ✓(ctor: `MOV [EAX+0x34],0`)
  - `+0x38 nStaticCount` — Ghidra 为 `byte`;文档按 int32 描述。二进制证据:**byte**(SortTags/AddTag 均 byte 读写,语义为"已排序"标志,非计数)→ Ghidra 类型正确,文档类型有误
  - `+0x3C nHeapCount` — Ghidra 为 `byte`;**实际为 dword int32**(标签总数 m_num,ctor/AddTag/SortTags/MoveToHeap/ResizeHeap 全部 dword 访问)→ **Ghidra 类型错误**
  - `+0x40 nHeapCapacity` — Ghidra 为 `byte`;**实际为 dword int32**(m_heapsize)→ **Ghidra 类型错误**
  - `+0x44 nField_0x44` — Ghidra 为 `byte`;证据为 byte(copy ctor/AddTag 置 1)→ Ghidra 正确,文档按 int32 有误
  - 缺失 `0x45..0x47` 尾部 3B padding(对齐 1 → 无隐式填充)→ 69B vs 实际占用 72B
- 证据:
  - ctor `0x282582` disasm:`MOV dword [EAX+0x3c],0` / `MOV dword [EAX+0x40],0` / `MOV byte [EAX+0x38],0` / `MOV byte [EAX+0x44],0`
  - AddTag `0x282800`:`*(uint*)&bHeapCount` 与 `*(uint*)&bHeapCapacity` dword 读写、`bStaticCount=0` byte 写、`m_num` 作数组下标
  - MoveToHeap `0x282c02` / ResizeHeap `0x282d10`:`*(uint*)&bHeapCapacity` dword;SortTags `0x283060`:`bStaticCount` byte 比较 + `bHeapCount` dword
  - 占用验证:cEntity `tagset @ 0x60..0xA8 = 72B`(Ghidra cEntity 中 dwPristineTagHashes @ 0xA8)、Pool<cEntity> 槽步长 0xFC(252=cEntity)——均要求 TagSet 实际 72B
- 问题清单:
  1. `bHeapCount`(0x3C)/`bHeapCapacity`(0x40)类型应为 int32/uint,现为 byte — 反汇编 dword 访问证据充分
  2. 结构缺 3B 尾 padding,69B 与真实占用 72B 不符(tier2 回写备注"69B+3pad"未落实到 Ghidra 定义)
  3. cEntity.pTagset 仍为 `byte[72]`,未引用本 TagSet 类型(大小一致但类型未闭合)
  4. 数组字段名 `pStaticTags` 与 +0x30 指针重名(文档名 staticTags)
  5. 文档 §6 将 0x38/0x44 描述为 int32 计数与二进制(byte)不符;0x38 实际是排序标志而非 static count

### cSpatialHash_cEntity
- 状态: **PASS**
- Ghidra 大小: 40B | 文档大小: 40B | 匹配: yes
- 字段比对:
  - `+0x00/+0x04/+0x08` pBucketVec_begin/end/cap(3×ptr)✓ 与文档 "+0..+8 sBucketHolder vector 头" 一致
  - `+0x0C..+0x20` RBTree 头:nMap_color@12 / pMap_parent@16 / pMap_left@20 / pMap_right@24 / nMap_nodeCount@28 ✓(文档 "+12..+28 RBTree 头" 略不精确:实为 5 字段 12..32)
  - `+0x20` nField_0x20 ✓(ctor 清零)
  - `+0x24` flCellSize = **16.0f**(0x41800000)✓
- 证据:
  - cEntityManager ctor `0xd2796`:`operator new(0x28)`=40B;写 +0/+4/+8/+0x10/+0x14/+0x18/+0x1C/+0x20 清零,+0x18/+0x1C 指向 +0x10(nil 节点模式),`MOV [EAX+0x24],0x41800000`=16.0f;结果存 cEntityManager+0xF8(pSpatialHash)
  - cEntityManager dtor `0xd2e92`:`_M_erase(+0xC)`(RBTree)+ `~vector(+0)` + delete → 与布局一致
- 问题清单: 无实质问题。备注:nMap_color(0xC)ctor 未初始化;+0x1C 在 ctor 中被写入指针值,"nodeCount" 语义待定(不影响布局)。

### Pool_Base
- 状态: **WARN**
- Ghidra 大小: 36B | 文档大小: 36B | 匹配: yes
- 字段比对:
  - `+0x00` pVtable ✓(ctor 写 PTR_vtable+8)
  - `+0x04` pFirstChunk ✓ / `+0x08` pCurrentChunk ✓ / `+0x0C` nChunkSize ✓(=0x64=100)
  - `+0x10..+0x20` 计数/状态 5 字段 ✓(ctor:+0x10/0x18/0x1C/0x20=0,+0x14=1;GetNew/AllocNewChunk 使用 +0x10/+0x14/+0x1C/+0x20)
- 证据:
  - Pool ctor `0xd85cc`(与 cEntityManager 实际调用点 `0x340740` 同体,COMDAT 重复实例):vtable、+4=新 sChunk、+8=chunk->pData、+0xC=chunkSize、+0x14=1
  - GetNew `0xd57f6`:+0x10 计数、+0x14×+0xC 判满、+0x8 取对象并推进、+0x1C 自增、+0x20 峰值
  - AllocNewChunk `0xd824e`:沿 sChunk pNext(+4)遍历、new(8) 新块、+0x14 自增
  - 跨实例一致性:Pool<PathfinderComponent> GetNew `0x8eaca` / AllocNewChunk `0x8eb5e` 结构完全相同 → Pool<T,FakeLock> 恒为 36B
- 问题清单:
  1. **cEntityManager.pEntityPool 为 `byte[40]` @ +0xD0**(tier0-core 亦记 40B),比 Pool_Base 大 4B;pool+0x24 在 ctor/GetNew/AllocNewChunk/dtor 中均无任何访问 → Pool_Base 36B 与嵌入点 40B 不一致(应补 UNKNOWN_0x24 或将 pEntityPool 改 Pool_Base+4B pad,需定夺)
  2. `+0x14` 语义为 chunk 计数(ctor=1、AllocNewChunk 自增、GetNew 用作容量判据),名 `nFreeCount` 不准确;`+0x10` 为已分配计数
  3. 文档引用 Pool ctor `0xd85cc`,cEntityManager ctor 实际 CALL `0x340740`(同函数不同 COMDAT 副本,无布局影响)

### Pool_sChunk
- 状态: **PASS**
- Ghidra 大小: 8B | 文档大小: 8B | 匹配: yes
- 字段比对: `+0x00` pData ✓ / `+0x04` pNext ✓
- 证据:
  - sChunk ctor `0xd82bc`:new(8);pData = `operator_new(chunkSize*0xFC)`(0xFC=252=cEntity);槽位首字链式串接;pNext(+4)=0
  - AllocNewChunk `0xd824e` 经 pNext 遍历块链表 → pData/pNext 偏移确认
- 问题清单: 无

---

## 汇总表

| 类型 | 状态 | 主要问题 |
|---|---|---|
| TagSet | FAIL | Ghidra 69B ≠ 实际/文档 72B(缺 3B 尾 padding);bHeapCount(0x3C)/bHeapCapacity(0x40)应为 int32 却为 byte;cEntity 仍以 byte[72] 内嵌未引用该类型;数组字段名与指针重名;文档 0x38/0x44 类型描述与二进制不符 |
| cSpatialHash_cEntity | PASS | 无(40B,cellSize@36=16.0f 经 cEntityManager ctor 0xd2796 验证;RBTree 头 0x1C 语义待定) |
| Pool_Base | WARN | 结构本身 36B 正确;但 cEntityManager 嵌入 byte[40],差 4B(0x24)未定义;+0x14 命名(nFreeCount)语义应为 chunk 计数 |
| Pool_sChunk | PASS | 无(8B,pData+pNext,sChunk ctor 0xd82bc 验证) |

## 附:context 清单补充复核(Mutex / cHashedString / cHashedStringCSL / cEntityComponent)

| 类型 | 状态 | Ghidra | 文档 | 比对 |
|---|---|---|---|---|
| Mutex | PASS | 56B:n__sig@0,p__opaque[40]@4,nAttr_sig@44,pAttr_opaque[8]@48 | 56B:sig@0,opaque[40]@4,attr_sig@0x2C,attr_opaque[8]@0x30 | 一致;ctor 0x272f5c:pthread_mutex_init(this)+pthread_mutexattr_init(&nAttr_sig) 验证 44B+12B 拆分 ✓ |
| cHashedString | PASS | 8B:dwHash@0,pBuf@4 | 8B:hash@0,buf@4 | 一致 |
| cHashedStringCSL | PASS | 8B:dwHash@0,pCstr@4 | 8B:hash@0,cstr@4 | 一致 |
| cEntityComponent | PASS | 16B:p__vtf@0,bAwakeFlag@4,pad[3]@5,pVec_component@8,pEntity@12 | 16B:同 | 一致 |

(注:该 4 类型未做 decompile 抽查——除 Mutex ctor 0x272f5c 外,布局与文档完全一致且类型平凡;若主 agent 分配给了其他分片,以该分片报告为准。)
