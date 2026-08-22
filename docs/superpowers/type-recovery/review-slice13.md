# Review Slice 13 — DatagramHeaderFormat / Socket / NodeAddress / Timer

审查方式:get_struct_layout 读取 Ghidra 回写布局 → 与 docs/superpowers/../../3rd/dst/game_decompiler/types_common.h 及 tier3-d-network.md / tier3-e-system.md 字段表比对 → decompile 交叉验证(全部使用 Ghidra decompile_function,IDA 共享预算 0 次)。

## 审查结果

### DatagramHeaderFormat
- 状态: **PASS**
- Ghidra 大小: 15B | 文档大小: 15B (0x0F) | 匹配: **yes**
- 字段比对: 无实质不一致。字段名仅前缀风格差异(pN24_0x00 vs n24_0x00、dwN32_0x04 vs n32_0x04、bB_0x09.. vs b_0x09..),偏移/类型/大小全部一致。
  - 0x00 byte[3] pN24_0x00 ↔ n24_0x00[3] ✓
  - 0x04 uint dwN32_0x04 ↔ n32_0x04 ✓
  - 0x08 bFullHeader ✓ | 0x09 bB_0x09 ✓ | 0x0A bB_0x0A ✓ | 0x0B bB_0x0B ✓ | 0x0C bB_0x0C ✓ | 0x0D bB_0x0D ✓ | 0x0E bB_0x0E ✓
- 证据:
  - Serialize 0x243bca (G):写 1 bit hasFullHeader → 分支按 bFullHeader 写 bB_0x09/bB_0x0A/bB_0x0C/bB_0x0D 标志位 → 24 bits 写 `pN24_0x00[0..2]`(+0..+2)→ 32 bits 写 `dwN32_0x04`(+4,网络序 ReverseBytes)。与文档序列化描述逐条吻合。
  - Deserialize 0x242cfc (G):首 bit 读入 `bB_0x0E`(+0xE),再读 bFullHeader(+8)、bB_0x09(+9)、bB_0x0A(+0xA)、bB_0x0C(+0xC)、bB_0x0D(+0xD),随后回填 3 bytes pN24_0x00 与 32 bit dwN32_0x04。与文档字段表完全一致。
  - 注意:Serialize/Deserialize 的字节序分支中出现 `field_0x3`(pN24_0x00 数组第 3 字节的别名),与 pN24_0x00[2] 同址,非额外字段,无问题。
- 问题清单: 无

### Socket
- 状态: **WARN**
- Ghidra 大小: 25B | 文档大小: 28B (0x1C) | 匹配: **no(大小不一致;字段布局一致)**
- 字段比对: 全部字段偏移/名称/类型一致:
  - 0x00 nM_fd ↔ m_fd (int) ✓
  - 0x04 nM_lastError ↔ m_lastError (int) ✓
  - 0x08 nField_0x08 ✓ | 0x0C nField_0x0C ✓
  - 0x10 pUNKNOWN_0x10 byte[8] ↔ UNKNOWN_0x10 8B ✓
  - 0x18 bBlocking (byte) ✓
- 证据:
  - ctor 0x1b6fea (G):`nM_lastError=0; nM_fd=0; nField_0x0C=0; nField_0x08=0; bBlocking=1` —— 与文档"ctor 字段=0、+0x18=1"完全一致。
  - dtor 0x1b7032 (G):`if (nM_fd != 0) shutdown(nM_fd, 2); nM_fd = 0` —— 与文档 dtor 证据吻合。
  - TCPConnect 0x1b7086 (G):签名 `__thiscall TCPConnect(Socket* this, ...)`,Ghidra 已正确应用 Socket 类型。
- 问题清单:
  1. **大小不一致**:文档声明 28B (0x1C),Ghidra struct 为 25B(0x19)。文档自身字段表求和即 25B(4×int@0/4/8/0xC + 8B@0x10 + 1B@0x18 = 0x19),tier3-d 摘要表 0x1C (28B) 与此矛盾。ctor/dtor/Serialize 均无任何写入超过 0x18 的证据,0x1C 疑为分配舍入(如 `new(0x1C)`)而非真实字段。ctor 唯一引用为 DATA 0x4f273a(无代码 xref,未定位分配点,无法进一步证实 0x1C 分配)。建议:文档大小改为 25B,或补 3B 尾部 padding 至 0x1C 并标注 UNKNOWN;不影响字段正确性。
  2. 对齐:alignment=1(Ghidra),int 字段 4B 对齐但 struct 未要求 4 对齐 —— 与 25B 大小自洽,合理。

### NodeAddress
- 状态: **PASS**
- Ghidra 大小: 12B | 文档大小: 12B (0x0C) | 匹配: **yes**
- 字段比对: 一致。Ghidra 将 m_path 展开为 3 个 void* 指针(pM_path_begin / pM_path_end / pM_path_cap),即 std::vector<cHashedString> 三指针表示,与文档 `void* m_path[3]`(vector<cHashedString> 12B)语义完全等价,且更精确。
- 证据: ctor 0xc51f4 (G):`pM_path_begin=0; pM_path_end=0; pM_path_cap=0` 后按 '.' 分隔 getline + `cHashedString::Set` + `std::vector<cHashedString>::push_back(this)` —— 与文档"ctor 清 3 dword 后按 '.' 分段 push_back"吻合。
- 问题清单: 无

### Timer
- 状态: **PASS**
- Ghidra 大小: 8B | 文档大小: 8B | 匹配: **yes**
- 字段比对: 一致。Ghidra dwStartTick (uint)@0x00 / dwStartTickHi (uint)@0x04 ↔ 文档 nStartTick (uint32)@0x00 / nStartTickHi (uint32)@0x04,合并即 uint64。名称前缀风格差异(dw/n)仅命名习惯,无实质问题。
- 证据: ctor 0x274798 (G):`TVar1 = (Timer)mach_absolute_time(); *this = TVar1;` —— 8 字节整体写入 +0,即 `*(uint64_t*)this = mach_absolute_time()`,与文档完全一致。
- 问题清单: 无

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| DatagramHeaderFormat | PASS | 无;字段名仅前缀风格差异,Serialize/Deserialize 逐字段验证通过 |
| Socket | WARN | 大小:文档 28B (0x1C) vs Ghidra 25B (0x19);文档自身字段表求和为 25B,0x1C 疑为分配舍入,字段偏移/类型全部正确 |
| NodeAddress | PASS | 无;vector 三指针展开与 m_path[3] 等价 |
| Timer | PASS | 无;uint64 整体写入与两 uint32 字段一致 |
