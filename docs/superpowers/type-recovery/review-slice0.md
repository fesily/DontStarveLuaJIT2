# Review Slice 0 — Mutex / cHashedString / cHashedStringCSL / cEntityComponent

> 范围:回写到 Ghidra 的 struct 布局与 `types_common.h` + 分片报告的一致性审查。
> 方法:`get_struct_layout` 读 Ghidra 布局 → 与 `types_common.h` 比对 → 与 tier0-core.md / tier2-components.md / tier3-b-map.md 比对 → Ghidra decompile 抽查 ctor/Set 交叉验证。
> 注:idalib-mcp 会话 `f9cdc808` 不可达(`idb_list` 返回空,无任何已打开会话),故交叉验证改用 Ghidra `decompile_function`(只读工具列表内),未违反只读约束。

---

### Mutex
- 状态: PASS
- Ghidra 大小: 56B | 文档大小: 56B | 匹配: yes
- 字段比对: 无偏移/类型差异。仅命名风格差异(内容一致):
  - `n__sig` vs 文档 `__sig`(0x00, int32)
  - `p__opaque[40]` vs 文档 `__opaque[40]`(0x04, byte[40])
  - `nAttr_sig` vs 文档 `attr_sig`(0x2C, int32)
  - `pAttr_opaque[8]` vs 文档 `attr_opaque[8]`(0x30, byte[8])
- 证据: ctor `0x272f5c` 反编译:
  - `pthread_mutexattr_init(&this->nAttr_sig)` → attr 区从 +0x2C 起(12B);
  - `pthread_mutexattr_settype(&nAttr_sig, 2)` → 递归锁;
  - `pthread_mutex_init((pthread_mutex_t*)this, &attr)` → mutex 区 +0 起(44B);
  - 断言源路径 `source/systemlib/posix/mutex.cpp` 与 tier0-core.md 记录一致。
  - 结论:pthread_mutex_t 44B(+0..+0x2B)+ pthread_mutexattr_t 12B(+0x2C..+0x37)= 56B,与文档完全一致。
- 问题清单: 无布局问题。备注:Ghidra 中无独立 `CriticalSection` struct(仅 /Demangler 1B 占位),文档中 CriticalSection 是 C 级 typedef 别名,不构成问题。

### cHashedString
- 状态: PASS
- Ghidra 大小: 8B | 文档大小: 8B | 匹配: yes
- 字段比对: 无偏移/类型差异。命名差异:`dwHash` vs 文档 `hash`(0x00, uint32);`pBuf` vs 文档 `buf`(0x04, char*)。
- 证据:
  - `cHashedString::Set @ 0x283c94`:`this->dwHash = Util::Hash(str); this->pBuf = 0;` → 写 +0/+4,确认 hash@0、buf@4 布局;
  - `NodeAddress` ctor `0xc51f4`:`cHashedString::Set(&local, str)` + `vector<cHashedString>::push_back`(元素 8B),与 tier3-d-network.md 记录一致;
  - `mEmptyString`(0x45099c 指针,对象 0x463f84)被 60+ 处 READ(AddTag 0xe186a、HasTag 0xe2406、cEntity 0xce337、cPrefab 0xf5c31 等),为 8B 全局。
  - 结论:hash@0 + buf@4 = 8B,与文档一致。
- 问题清单: 无布局问题。备注:Set 的该变体将 pBuf 置 0(仅算 hash 不保留串),属值语义非布局;mEmptyString 内存内容读起来像 {指针, 指针} 而非 {0, ptr},疑为数据段 PIC 指针间接或标签误导,不影响 8B 布局结论,建议后续核查数据值(低优先)。

### cHashedStringCSL
- 状态: PASS
- Ghidra 大小: 8B | 文档大小: 8B | 匹配: yes
- 字段比对: 无偏移/类型差异。命名差异:`dwHash` vs 文档 `hash`(0x00, uint32);`pCstr`(char*) vs 文档 `cstr`(const char*)(0x04)——const 限定 Ghidra 不跟踪,等价。
- 证据:
  - `cPrefab::cPrefab @ 0xf5bf6`:`cHashedStringCSL local_34; local_34.dwHash=0; local_34.pCstr=*mEmptyString; cHashedStringCSL::Set(&local_34, this->pName); this->dwNameHash_dwHash=local_34.dwHash; this->pNameHash_pCstr=local_34.pCstr;` → 8B 对象 {dwHash@0, pCstr@4} 整体拷贝到 cPrefab+0x08,与 tier3-b-map.md(`0xf5cb0 Set(&local, *(char**)EDI)` → `0xf5cbb [EDI+8]=local 8B`)一致;
  - Ghidra 反编译以 cHashedStringCSL 类型解析 local_34,字段读写按 {dwHash, pCstr} 展开。
  - 结论:与 cHashedString 同布局(hash@0 + cstr@4 = 8B),与文档一致。
- 问题清单: 无。

### cEntityComponent
- 状态: PASS
- Ghidra 大小: 16B | 文档大小: 16B | 匹配: yes
- 字段比对: 无差异(名称/偏移/类型全部一致):
  - `p__vtf` @ 0x00 (void*)
  - `bAwakeFlag` @ 0x04 (byte)
  - `p_pad05[3]` @ 0x05 vs 文档 `pad05[3]`(仅命名前缀差异)
  - `pVec_component` @ 0x08 (void*)
  - `pEntity` @ 0x0C (cEntity*)
- 证据:
  - `cEntityComponent::cEntityComponent @ 0xd2646`:`p__vtf = &PTR__cEntityComponent_004565d8; bAwakeFlag = 0; pVec_component = 0; pEntity = 0;` → 逐字段确认 vtable@0 / bAwakeFlag@4 / pVec_component@8 / pEntity@0xC;
  - `MapComponentBase` ctor `0x46ec6`:`CALL 0xd2646`(基类 ctor)后 `(this->base).p__vtf = &PTR__MapComponentBase_004550f8` → base@+0 为 vtable,派生覆写正常,与 tier3-b-map.md 一致;
  - tier0-core.md:`pEntity @ 0x0C 由 cEntity::vec_components (0x44) 语义确认;bAwakeFlag @ 0x04`,Ghidra struct 与其吻合。
  - 结论:16B 布局与文档完全一致。
- 问题清单: 无。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| Mutex | PASS | 无(字段命名风格与文档不同,内容一致) |
| cHashedString | PASS | 无(mEmptyString 数据值疑点,低优先,非布局) |
| cHashedStringCSL | PASS | 无 |
| cEntityComponent | PASS | 无 |

**结论**:4/4 全部 PASS。Ghidra 回写布局与 `types_common.h` 及分片报告在大小、偏移、类型上完全一致;差异仅限字段命名风格(Hungarian 前缀 vs 文档朴素名)与 const 限定,均为外观性问题。IDA 交叉验证因会话不可达改用 Ghidra 反编译完成,证据充分。
