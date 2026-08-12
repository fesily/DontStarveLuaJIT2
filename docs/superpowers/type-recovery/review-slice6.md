# Type Recovery Review — Slice 6 (WindowMoveEvent / ResizeEvent / Control / cLineEditor)

- 评审人: Review6
- 日期: 2026-08-08
- 程序: dontstarve_steam (Mach-O x86:LE:32, imagebase 0x1000, Ghidra + IDA session f9cdc808 同基址)
- 对照文档: `types_common.h`(L441-446)、`tier3-c-input.md`(§1.7, §2.1, §3)
- 方法: Ghidra `get_struct_layout` ↔ 文档字段表 ↔ idalib decompile 交叉验证(本片共用 4 次 decompile,各类型 ≤2)

---

### WindowMoveEvent
- 状态: **PASS**
- Ghidra 大小: 16B | 文档大小: 0x10 (16B) | 匹配: yes
- 字段比对: 一致(仅命名差异:pVptr↔vptr,语义等价)

| 偏移 | Ghidra | 文档 | 一致 |
|---|---|---|---|
| +0x00 | pVptr (void*) | vptr (void*) | ✓ |
| +0x04 | nType (int) | nType (int32_t) | ✓ |
| +0x08 | nX (int) | nX (int32_t) | ✓ |
| +0x0C | nY (int) | nY (int32_t) | ✓ |

- 证据: IDA `Main` @ 0xcfa8,SDL_WINDOWEVENT subtype 4 分支:`v36[0]=&unk_45DB34`(+0 vptr,0xd227)、`v36[1]=2`(+4 nType=WindowMoveEvent 枚举值,0xd216)、`v36[2]=v48`(+8 nX,0xd22b)、`v36[3]=v49`(+0xC nY,0xd22f),与文档 vtable 槽 0x45DB34 完全吻合。消费点 `WindowManager::HandleEvent` @ 0x1d1464:`v3=a3[1]`(+4 分派),v3==2 分支读 `a3[2]`(+8,写 window_x)、`a3[3]`(+0xC,写 window_y)。构造/消费双端偏移一致。
- 问题清单: 无

### ResizeEvent
- 状态: **PASS**
- Ghidra 大小: 16B | 文档大小: 0x10 (16B) | 匹配: yes
- 字段比对: 一致(命名差异:pVptr↔vptr;nWidth/nHeight↔nW/nH,语义等价)

| 偏移 | Ghidra | 文档 | 一致 |
|---|---|---|---|
| +0x00 | pVptr (void*) | vptr (void*) | ✓ |
| +0x04 | nType (int) | nType (int32_t) | ✓ |
| +0x08 | nWidth (int) | nW (int32_t) | ✓ |
| +0x0C | nHeight (int) | nH (int32_t) | ✓ |

- 证据: IDA `Main` @ 0xcfa8,SDL_WINDOWEVENT subtype 5 分支:`v37[0]=&unk_45DB44`(+0 vptr,0xd337)、`v37[1]=1`(+4 nType=ResizeEvent 枚举值,0xd326)、`v37[2]=v48`(+8 宽,0xd33b)、`v37[3]=v49`(+0xC 高,0xd33f),与文档 vtable 槽 0x45DB44 吻合。消费点 `HandleEvent` @ 0x1d1464 v3==1 分支读 `a3[2]`(+8)→ `WindowManager::Resize`(0x1d0b42),+0xC 高度经编译器栈传递(__size)。偏移正确。
- 问题清单: 无

### Control
- 状态: **PASS**
- Ghidra 大小: 16B | 文档大小: 16B | 匹配: yes
- 字段比对: 一致(命名差异:dwId/dwType/dwInput/dwInput2 ↔ nId/nType/nInput/nInput2,均为 uint32)

| 偏移 | Ghidra | 文档 | 一致 |
|---|---|---|---|
| +0x00 | dwId (uint) | nId (uint32_t) | ✓ |
| +0x04 | dwType (uint) | nType (uint32_t) | ✓ |
| +0x08 | dwInput (uint) | nInput (uint32_t) | ✓ |
| +0x0C | dwInput2 (uint) | nInput2 (uint32_t) | ✓ |

- 证据: IDA `DontStarveInputHandler::C2` @ 0x1b208,0x1b471-0x1c603 共 73 次 `push_back`(vector @ +0x34,reserve 73 @ 0x1b46c),每项为 4-DWORD 栈结构:digital 填 `{id,1,input,0}`(如 0x1b471: {2,1,36,0}),analog 填 `{id,2,input1,input2}`(如 0x1b817: {47,2,2,0};0x1b869: {48,2,2,1})。type 1=digital / 2=analog 与文档一致。
- 问题清单: 无

### cLineEditor
- 状态: **PASS**
- Ghidra 大小: 1028B (0x404) | 文档大小: 0x404 (1028B) | 匹配: yes
- 字段比对: 一致(命名差异:pSBuffer↔sBuffer、fInsertMode↔bInsertMode;vecHistory 文档写作 `void*[3]`,Ghidra 展开为 begin/end/cap 三指针,布局等价)

| 偏移 | Ghidra | 文档 | 一致 |
|---|---|---|---|
| +0x000 | pSBuffer (char[1000]) | sBuffer (char[1000]) | ✓ |
| +0x3E8 | nCursorPos (int) | nCursorPos (int32_t) | ✓ |
| +0x3EC | nLength (int) | nLength (int32_t) | ✓ |
| +0x3F0 | nHistoryCount (int) | nHistoryCount (int32_t) | ✓ |
| +0x3F4 | fInsertMode (bool) | bInsertMode (bool) | ✓ |
| +0x3F8 | pVecHistory_begin (void*) | vecHistory[0] | ✓ |
| +0x3FC | pVecHistory_end (void*) | vecHistory[1] | ✓ |
| +0x400 | pVecHistory_cap (void*) | vecHistory[2] | ✓ |

- 证据: IDA `cLineEditor::C2` @ 0x281e68:`__bzero(this, 1004)`(0x281e99,清零 0x000..0x3EC 含缓冲+nCursorPos)、`*(_BYTE*)(this+1012)=1`(0x281e9e,bInsertMode=1)、vector 三 DWORD @ +0x3F8 置 0(0x281e70/7a/84)。`SetString` @ 0x281f44:`strncpy(dst, src, 0x3E7)`(0x281f60,缓冲上限 999+1)、`*(this+1004)=len`(0x281f7a,nLength)、`*(this+1000)=len`(0x281f80,nCursorPos)。+0x3F4 后 3 字节隐式 padding 至 +0x3F8,总大小 0x404 正确。
- 问题清单: 无

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| WindowMoveEvent | PASS | 无(字段命名 pVptr/vptr 仅风格差异) |
| ResizeEvent | PASS | 无(nWidth/nHeight vs nW/nH 仅命名差异) |
| Control | PASS | 无(dw* vs n* 前缀仅命名差异) |
| cLineEditor | PASS | 无(vecHistory 三指针展开 vs void*[3] 布局等价) |

## 附注(非问题)
- 四个结构在 Ghidra 中均显示 `Alignment: 1`(写回工具创建属性)。因所有字段偏移本身即自然对齐(4 的倍数)且大小与文档一致,对二进制布局无影响;Control 位于堆 vector、cLineEditor 嵌入 cTextEditWidget+0x18、事件对象堆分配,均无嵌入错位风险。若后续嵌入到非 4 对齐偏移处需留意。
- 交叉验证 IDA decompile 共 4 次(Main 0xcfa8、DontStarveInputHandler C2 0x1b208、cLineEditor C2 0x281e68、SetString 0x281f44、HandleEvent 0x1d1464 — 事件对共享 Main/HandleEvent,各类型均 ≤2 次)。
