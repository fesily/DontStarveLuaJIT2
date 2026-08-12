# Review 报告 — Slice 4: cInputKeyEvent / cInputMouseButtonEvent / cInputMouseMoveEvent / cInputGestureEvent

- 日期: 2026-08-08
- 评审方式: ghidra-mcp `get_struct_layout`(dontstarve_steam, Mach-O x86:LE:32) ↔ `docs/superpowers/../../3rd/dst/game_decompiler/types_common.h` + `tier3-c-input.md`;关键字段用 idalib-mcp(f9cdc808)decompile 抽查构造点。
- 只读评审,未做任何写入。
- 基类 `cGameEvent`(8B, vptr@0 + nType@4)已在 Ghidra 存在,与本分片 4 个事件类的头部布局一致。

---

### cInputKeyEvent
- 状态: **WARN**
- Ghidra 大小: 13B | 文档大小: 16B (0x10) | 匹配: **no**
- 字段比对:
  - 偏移/类型全部一致: `pVptr`(void*)@0、`nType`(int)@4、`nKey`(int)@8、`fPressed`(bool)@0xC。
  - 命名差异(仅命名,不影响布局): Ghidra `pVptr`/`fPressed` vs 文档 `vptr`/`bPressed`。
  - **大小差异**: Ghidra 结构 alignment=1,size=13,缺少尾部 3B padding;文档声明为 0x10(4 字节对齐尾部填充)。
- 证据: IDA `DontStarveInputHandler::OnInputEvent` @ 0x1d6dc case 4/5/6(构造 cInputKeyEvent):
  - `v35[0] = &unk_45DF0C` → vptr = 0x45DF0C(与文档 vtable vptr 0x45DF0C 一致)
  - `v35[1] = 1` → nType = 1(与文档类型 tag 表一致:cInputKeyEvent = 1)
  - `v35[2] = v8(a3[2])` → nKey @ +8
  - `v36 = 1/0` → bPressed @ +0xC
  - 栈对象实际占用 16B:v35[3] 于 ebp-64h,char v36 于 ebp-58h,下一栈槽 v37 于 ebp-54h(ebp-57h..ebp-55h 为 3B 填充)→ 对象区间 ebp-64h..ebp-51h = 0x10,编译器按 16B 分配。
- 问题清单:
  1. 结构大小 13B 与文档/实际 ABI 0x10 不符,缺尾部 3B padding,alignment 应为 4。若 Ghidra 用该结构定义栈变量,会把 16B 对象误判为 13B,影响相邻栈槽分析。建议补尾部填充或设 alignment=4。
  2. 字段名 `fPressed` 与文档 `bPressed` 不一致(bool 前缀约定),`pVptr` vs `vptr` 亦不同(次要)。

### cInputMouseButtonEvent
- 状态: **PASS**
- Ghidra 大小: 24B | 文档大小: 24B (0x18) | 匹配: yes
- 字段比对: 无不一致。`pVptr`@0、`nType`@4、`nButton`@8、`fPressed`(bool)@0xC、`flX`(float)@0x10、`flY`(float)@0x14,偏移/类型与文档逐一对应(bool 后 3B padding 到 float 对齐,合理)。
- 证据: IDA `OnInputEvent` @ 0x1d6dc case 7/8:
  - `v41[0] = &unk_45DF1C` → vptr = 0x45DF1C(与文档一致)
  - `v41[1] = 3` → nType = 3(与文档 tag 表一致:cInputMouseButtonEvent = 3)
  - `v41[2] = v5(a3[2])` → nButton @ +8
  - `v42 = 1/0` → bPressed @ +0xC
  - `v43 = (float)(int)a3[4]` → flX @ +0x10
  - `v44 = v25(浮点差值)` → flY @ +0x14
  - 栈对象 ebp-3Ch..ebp-24h = 0x18 连续 24B,与结构大小一致。
- 问题清单: 无(仅 `fPressed` vs `bPressed` 命名风格差异,同前,非布局问题)。

### cInputMouseMoveEvent
- 状态: **PASS**
- Ghidra 大小: 16B | 文档大小: 16B (0x10) | 匹配: yes
- 字段比对: 无不一致。`pVptr`@0、`nType`@4、`nX`(int)@8、`nY`(int)@0xC,偏移/类型与文档一致,无 padding 需求。
- 证据: IDA `OnInputEvent` @ 0x1d6dc case 9:
  - `v45[0] = &unk_45DF2C` → vptr = 0x45DF2C(与文档 vptr 一致;文档 §1.3 已注记该 vtable 槽异常:指向 __const 字符串池,属常量池布局产物,不影响布局)
  - `v45[1] = 0` → nType = 0(与文档 tag 表一致:cInputMouseMoveEvent = 0)
  - `v45[2] = *(a2+160)` → nX @ +8
  - `v45[3] = *(a2+164)` → nY @ +0xC
  - 对象 v45[0..3] 恰好 16B。
- 问题清单: 无。注意文档 §1.3 注明真实大小可能 ≥0x10(栈槽 36B 仅前 16B 被写,可能含未观测 dx/dy 字段)——Ghidra 当前 0x10 与文档最低承诺一致,未超写,不构成错误。

### cInputGestureEvent
- 状态: **PASS**
- Ghidra 大小: 12B | 文档大小: 12B (0x0C) | 匹配: yes
- 字段比对: 偏移/类型一致:`pVptr`@0、`nType`@4、`nEGesture`(int)@8(命名 `nEGesture` vs 文档 `eGesture`,仅命名差异)。
- 证据: IDA `cGame::ProcessGesture` @ 0x13886:
  - `v3[0] = &unk_45DBCC` → vptr = 0x45DBCC(与文档 vptr 一致)
  - `v3[1] = 6` → nType = 6(与文档 tag 表一致:cInputGestureEvent = 6)
  - `v3[2] = a2` → eGesture @ +8
  - 对象 v3[3] = 12B = 0x0C,与结构大小一致。
- 问题清单: 无。

### 基类 cGameEvent(关联核查)
- 状态: **PASS**
- Ghidra 大小: 8B | 文档大小: 8B | 匹配: yes
- 字段比对: `pVptr`(void*)@0、`nType`(int)@4,与文档一致。
- 证据: 4 个事件类的构造点均按 `[vptr@0, nType@4, ...]` 顺序写栈对象,与 cGameEvent 基类头一致;DispatchEvent 按 [+4] 取类型查表。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| cInputKeyEvent | WARN | 大小 13B ≠ 文档 0x10,缺尾部 3B padding(alignment=1);栈对象实际 16B。字段偏移/类型全部正确 |
| cInputMouseButtonEvent | PASS | 无(仅 `fPressed`/`bPressed` 命名风格差异) |
| cInputMouseMoveEvent | PASS | 无(文档已注记 vtable 槽异常与可能 ≥0x10 大小,均非布局错误) |
| cInputGestureEvent | PASS | 无(仅 `nEGesture`/`eGesture` 命名差异) |
| cGameEvent(基类) | PASS | 无 |

## 结论
4 个事件类中 3 个 PASS,1 个 WARN。所有字段的偏移与类型均与 types_common.h / tier3-c-input.md 一致,并经 IDA 构造点交叉验证(OnInputEvent 0x1d6dc 覆盖 Key/MouseButton/MouseMove,ProcessGesture 0x13886 覆盖 Gesture)。唯一实质问题:cInputKeyEvent 在 Ghidra 中为 13B(alignment 1),而文档与编译器实际栈分配均为 0x10,缺 3B 尾部填充,建议修正(仅记录,未修改)。
