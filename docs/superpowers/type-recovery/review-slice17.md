# Review Slice 17 — cWriter / ZipSaver / cBaseFactory / IPCSignals

- 审查对象:回写到 Ghidra 的 struct 布局 vs `types_common.h` vs `tier3-e-system.md`
- 二进制:dontstarve_steam (macOS i386, base 0x1000, Ghidra 当前程序;idalib session f9cdc808)
- 方法:get_struct_layout + 文档比对 + Ghidra/IDA decompile 交叉验证(IDA 用量:IPCSignals 2 次、cBaseFactory 1 次,共 3 次,符合每类型 ≤2 约束)
- 全程只读,未做任何写入

## 汇总

| 类型 | 状态 | 主要问题 |
|---|---|---|
| cWriter | PASS | 无。pVtable 为推断(全内联,无 ZTV),与分片报告一致 |
| ZipSaver | PASS | 无。字段名 pZipFile vs zipFile 仅命名差异 |
| cBaseFactory | WARN | 分片报告 "vtable @ 0x450788" 表述不准:0x450788 是数据指针槽(值 0x460EC0),实际 vtable 在 0x460EC0,D0 写 vptr=0x460EC8。不影响布局 |
| IPCSignals | PASS | 无。map 头按 _Rb_tree 6 字段展开,与文档 [6] 数组等价 |

## 详细比对

### cWriter
- 状态: PASS
- Ghidra 大小: 16B | 文档大小: 16B (0x10) | 匹配: yes
- 字段比对: 无不一致。
  - +0x00 pVtable (void*) — Ghidra `pVtable` == 文档 `void* pVtable`
  - +0x04/+0x08/+0x0C m_buffer (std::vector<char>, 3×4B) — Ghidra `pM_buffer_begin/end/cap` == 文档 `void* m_buffer[3]`
- 证据: `TagSet::Write(cWriter&)` 0x282A76(Ghidra decompile):对 `param_1 + 4` 调 `std::vector<char>::push_back`(内层循环 4 次),证实 vector<char> 位于 +0x04;+0x00 存在 4B 非 vector 前缀。与分片报告第 21 节完全一致。
- 问题清单: 无。注:pVtable 语义为推断(该类型全内联、无 ZTV 符号,分片报告亦标注 "UNKNOWN 地址"),偏移本身有 4B 前缀佐证,不构成错误。

### ZipSaver
- 状态: PASS
- Ghidra 大小: 4B | 文档大小: 4B | 匹配: yes
- 字段比对: 无偏移/类型不一致。字段名 `pZipFile`(Ghidra)vs `zipFile`(文档)为命名差异,非布局差异。
- 证据: `ZipSaver::ZipSaver(char const*)` 0x27508C(Ghidra decompile):`this->pZipFile = minizip::_zipOpen(param_1, 0)`,确认唯一字段句柄位于 +0x00。
- 问题清单: 无。

### cBaseFactory
- 状态: WARN
- Ghidra 大小: 60B | 文档大小: 60B (0x3C) | 匹配: yes
- 字段比对: 无布局不一致。
  - +0x00 pVtable (void*) — Ghidra `pVtable` == 文档 `void* pVtable`
  - +0x04 criticalSection (Mutex 56B) — Ghidra `criticalSection: Mutex` == 文档 `Mutex criticalSection`;Mutex 56B 与 tier0-core 一致,4+56=60 闭合
- 证据: D0 0xD858C 双工具确认:
  - Ghidra: `this->pVtable = PTR_vtable_00450788 + 8; CriticalSection::~CriticalSection((CriticalSection*)&this->criticalSection);`
  - IDA: `*(_DWORD*)thisa = &unk_460EC8; CriticalSection::~CriticalSection(this); operator delete(v2);`
  - read_memory 0x450788 = `c0 0e 46 00` = 0x00460EC0 ⇒ Ghidra `PTR_vtable_00450788 + 8` = 0x460EC8 = IDA `&unk_460EC8`,两工具完全一致
- 问题清单:
  1. [文档问题] 分片报告第 22 节 "vtable @ 0x450788" 表述不准:0x450788 是存放 vtable 指针的数据槽(值 0x460EC0),对象 vptr 实际指向 0x460EC8(vtable 起始 +8,Itanium ABI 跳过 offset-to-top/typeinfo)。不影响 struct 布局,建议主 agent 在证据链中修正该地址表述。

### IPCSignals
- 状态: PASS
- Ghidra 大小: 56B | 文档大小: 56B (0x38) | 匹配: yes
- 字段比对: 无偏移/大小不一致。文档用不透明 `int32_t m_handlers[6]` / `int32_t m_signals[6]`,Ghidra 按 `std::_Rb_tree` 头展开为 6 字段(pad/color/parent/left/right/count),两者偏移等价:
  - +0x00 pVtable — Ghidra `pVtable` == 文档 `void* pVtable`;dtor 写 `&unk_45BA78` == 分片报告 vtable @ 0x45BA78
  - +0x04..+0x1B m_handlers map(24B)— Ghidra `nM_handlers_pad@4/color@8/parent@0xC/left@0x10/right@0x14/count@0x18` == 文档 `int32_t m_handlers[6]`;map 基 +0x04、头(color)@ +0x08,与分片报告 "map1 头 @ +0x08(map 基 +4)" 吻合
  - +0x1C bEnabled (byte) — Ghidra `bEnabled` == 文档 `uint8_t bEnabled`
  - +0x20..+0x37 m_signals map(24B)— Ghidra `nM_signals_pad@0x20/color@0x24/.../count@0x34` == 文档 `int32_t m_signals[6]`;map 基 +0x20、头 @ +0x24,与分片报告 "map2 头 @ +0x24" 吻合
- 证据:
  - ctor 0x2701DC(Ghidra):写 `pVtable = &PTR__IPCSignals_0045ba78`,初始化 map1(左右=parent=0,color=0,count=0,left=right=&color)与 map2 同构,`bEnabled = 0` — 全部偏移命中
  - getOrCreateSignal 0x2703D0(IDA):`if (*(_BYTE*)(a1 + 28))` = bEnabled @ +0x1C;`_Rb_tree::find(a1 + 32, a2) == a1 + 36` = map2 @ +0x20、end = map基+4 @ +0x24;`map::operator[](v5=a1+32)` — 全部偏移命中
  - dtor 0x2702D4(IDA):写 vptr = &unk_45BA78;`_M_erase(thisa+4, *((void**)thisa+3))` 清 map1;`sem_close(*(sem_t**)(*((DWORD*)thisa+11)+20))` 遍历 map2 值后 `_M_erase(thisa+32, *((void**)thisa+10))` 清 map2 — map1@+4、map2@+0x20 双双命中
- 问题清单: 无。注:bEnabled(+0x1C)与 m_signals(+0x20)之间的 3B padding 未命名,属正常对齐,文档一致。
