# Review Slice 24 — VFXEffectEmitter / ParticleEmitter / PostProcessor / VideoNode

- 审查时间: 2026-08-08
- 审查人: Review24
- 只读审查(未做任何 Ghidra/IDA 写入)
- 方法: Ghidra `get_struct_layout` ↔ `docs/superpowers/../../3rd/dst/game_decompiler/types_common.h` ↔ `tier3-a-rendering.md` 字段表;IDA(decompile,会话 f9cdc808)ctor/dtor 交叉验证
- IDA decompile 次数: VFXEffectEmitter ctor×1、ParticleEmitter ctor×1、PostProcessor ctor×1+dtor×1、VideoNode ctor×1(均 ≤2/类型)

---

### VFXEffectEmitter
- 状态: PASS
- Ghidra 大小: 128B | 文档大小: 128B | 匹配: yes
- 字段比对: 无不一致。Ghidra 与 types_common.h 均为 `pVtable@0x00 + pUNKNOWN_0x04[124]`(完全一致);tier3-a-rendering.md §19 的详细字段全部位于 UNKNOWN 区域内,无字段错位(末字段 nMaxParticles@0x7C + 4B = 0x80 = 128,恰好封口)
- 证据: IDA decompile ctor 0xbcf3e(1 次):
  - `*thisa = off_456358` → vtable @0x00 ✓
  - `thisa+2 = 1.0f` → flMaxLifetime @0x08 ✓;`thisa+3 = 0` → flAge? @0x0C ✓
  - `QWORD(thisa+4)=Vector3::Zero` + `thisa+6=0` → flAcceleration @0x10..0x1B ✓
  - `thisa+10 = Zero[8]` → nField_28 @0x28 ✓
  - `byte+44 = 1` → bRotation @0x2C ✓;`dword+45=0`、`word+49=0` → nField_2D @0x2D/0x31 ✓
  - `thisa+19/+20 = Vector2::One` → flUVFrameSize @0x4C ✓;`thisa+21 = 3` → nBlendMode @0x54 ✓
  - `thisa+22/+23 = 0` → pColourEnvelope/pScaleEnvelope @0x58/0x5C ✓(ctor 置 0,CompleteInit 0xbd144 填充)
  - `thisa+25/+26 = 0` → dwTextureHandle/dwEffectHandle @0x64/0x68 ✓;`thisa+28 = 0` → nField_70 @0x70 ✓
  - `thisa+29/+30 = 0` → pNode/pParticleBuffer @0x74/0x78 ✓(ctor 置 0,CompleteInit 分配);`thisa+31 = 32` → nMaxParticles @0x7C ✓
- 问题清单: 无

### ParticleEmitter
- 状态: PASS
- Ghidra 大小: 136B | 文档大小: 136B | 匹配: yes
- 字段比对: 无不一致。Ghidra 与 types_common.h 均为 `pVtable@0x00 + pUNKNOWN_0x04[132]`(完全一致);tier3-a-rendering.md §21 详细字段在 UNKNOWN 区域内自洽(末字段 nMaxParticles@0x84 + 4B = 0x88 = 136,封口);报告声称的 cEntityComponent 基类 @0x04(16B)与 vtable@0x00 并存无冲突
- 证据: IDA decompile ctor 0x5e1fc(1 次):
  - 先调 `cEntityComponent::cEntityComponent`(基类 16B @0x04..0x0F)✓;`*thisa = off_4556D8` → vtable @0x00 ✓
  - `thisa+4 = 1.0f` → flMaxLifetime @0x10 ✓;`thisa+5..8 = 0` → nField_14..20 @0x14..0x20 ✓
  - `QWORD(thisa+36)=Zero` + `thisa+11 = Zero[8]` → flAcceleration @0x24..0x2F ✓
  - `byte+48 = 1` → bRotation @0x30 ✓;`dword+49=0`、`byte+53=0` → nField_31 @0x31/0x35 ✓
  - `thisa+20/+21 = Vector2::One` → flUVFrameSize @0x50 ✓;`thisa+22 = 3` → nBlendMode @0x58 ✓
  - `thisa+23/+24 = 0` → nField_5C/60 @0x5C/0x60 ✓;`thisa+26/+27 = 0` → flUVWidth/Height @0x68/0x6C ✓(ctor 0,SetRenderResources 0x5e668 填充)
  - `thisa+29 = 0` → nField_74 @0x74 ✓;`thisa+30 = 3` → nRenderLayer @0x78 ✓
  - `thisa+31/+32 = 0` → pNode/pParticleBuffer @0x7C/0x80 ✓(ctor 置 0);`thisa+33 = 32` → nMaxParticles @0x84 ✓
- 问题清单: 无

### PostProcessor
- 状态: WARN
- Ghidra 大小: 136B | 文档大小: 136B | 匹配: yes(大小);字段 @0x00 语义不符
- 字段比对:
  - **@0x00: Ghidra/types_common.h 标为 `pVtable`(void*) — 错误**。该类型**无 vtable**:ctor 首写 `*(DWORD*)a1 = 3`(0xb6903),且整个 ctor/dtor 从不按 vtable 解引用。@0x00 应为 `uint nField_00`(初值 3)。报告 §22 亦明确"无 vtable"。属写入时把非多态类首字段误标为 vtable 指针。
  - 其余字段:报告字段表与 IDA ctor/dtor 全部一致(见证据),且都在 Ghidra `pUNKNOWN_0x04[132]` 区域内(末字段 bField_84@0x84 + 1B ≤ 0x88,封口)。
- 证据: IDA decompile ctor 0xb68ce + dtor 0xb702a(共 2 次):
  - ctor: `a1 = 3`(@0x00,非 vtable);`a1+1 = a2` → pRenderer @0x04 ✓;`a1+2 = Add(vertdesc)` → dwVertDescHandle @0x08 ✓;`a1+3 = CreateVB(10,6,20)` → dwVertexBufferHandle @0x0C ✓;`a1+4/+5=-1` → nField_10/14 ✓;`a1+6/+7=0` → nField_18/1C ✓;`a1+8..11=-1` → nField_20..2C ✓(注:随后 `a1+10`(+0x28)被覆写为 colour_cube 纹理句柄、`a1+11`(+0x2C)被覆写为 RT 句柄,报告表未注明此覆写,属轻微不完整);循环写 -1 @0x4C/0x50/0x54/0x58 → bloom handles ✓;`a1+23=0`、`a1+24=1.0f`、`a1+25=0` → nField_5C/flField_60/nField_64 ✓;`QWORD(a1+13)=Zero` + `a1+28=MEMORY[0x465640]` → flOffset @0x68 ✓;`a1+29..31=1.0f` → flField_74/78/7C ✓;`a1+32=a3` → pEventDispatcher @0x80 ✓;`byte+132=0` → bField_84 @0x84 ✓;`a1+12/+13/+14` 依次 Load blurh/blurv/colourcube → @0x30/0x34/0x38 ✓;`a1+15..18 = off_4562B4[4]` → dwEffectHandle[4] @0x3C..0x48 ✓
  - dtor: Release RT @+0x2C(this+11,renderer+416)、tex @+0x28(this+10,renderer+396)、vertdesc @+0x08、vb @+0x0C、effects @+0x30/0x34/0x38/0x3C..0x48(renderer+412)→ 与 ctor 赋值一致
- 问题清单:
  1. [WARN] Ghidra struct 与 types_common.h 的 @0x00 字段误标为 `void* pVtable`;实际无 vtable,应为 `uint nField_00`(ctor 写 3)。类型为非多态。
  2. [WARN] tier3-a-rendering.md §22 dtor 摘要行有误:原文"Release RT(+0x44 via renderer+416)、tex(+0x40 via +396)"应为 **RT @+0x2C、tex @+0x28**(dtor 实际 this+11/this+10);+0x40/+0x44 实为 effect 句柄数组成员。
  3. [INFO] 报告表"nField_20..2C = -1"未注明 +0x28/+0x2C 在 ctor 中后续被覆写为 colour_cube 纹理/RT 句柄(dtor 证实)。

### VideoNode
- 状态: FAIL
- Ghidra 大小: 276B | 文档大小: 276B(注释 0x114)| 匹配: 大小 yes;**字段声明与头部布局 no**
  - ⚠ types_common.h 字段声明实际求和 = **265B**,≠ 注释 0x114(276B),文档自相矛盾。
- 字段比对(相对对象头,IDA ctor 0xc883a 为基准):
  - **0x00: vtable**。ctor `*this = off_456558`(0xc8879)→ vtable 在 **0x00**。Ghidra/types_common.h 却为 `base[80] @0x00 + pVtable @0x50` — **头部整体 +4 错位**;SceneGraphNode 基类先写自己 vtable@0x00,VideoNode ctor 再覆写为 off_456558,复用同一槽位。正确切分应为 `pVtable@0x00 + base[76]`。
  - **0x50: flSize(Vector2,8B)**。ctor `QWORD(this+20) = Vector2::Zero`(0xc890a)→ 0x50..0x57。Ghidra/types_common.h 标在 **0x54**(pSize/flSize[8])— 错位;0x54..0x5B 属未知区。
  - **0x58..0x93: UNKNOWN[60]**。Ghidra 未建模(0x5C..0x93 空洞);types_common.h `UNKNOWN_0x58[60]` 因头部错位落在 0x5C..0x97,**与 decoderHandles@0x94 重叠**。
  - **0x94/0x98/0x9C: decoderHandles[3]**。ctor `this+37=v4[4]`、`this+38=v4[2]`、`this+39=v4[6]` ✓。Ghidra `pDecoderHandles[3] @0x94` ✓ **正确**;types_common.h 因重叠实际在 0x98(错)。
  - **0xA0..0xAF / 0xB0 / 0xB4 / 0xB8**:nField_A0/A4/A8/AC(this+40..43 = 0)、tint(this+44 = Colour::White)、nField_B4(this+45 = 0)、name(std::string 4B,this+46 = empty_rep+12)✓。Ghidra 全部正确(dwTint@0xB0 ✓)。types_common.h 因 decoderHandles 错位,这些字段名与其实际位置差 +4(名 0xA0 实 0xA4 等)。
  - **0xC0: timer(8B,非 32B)**。ctor `Timer::Timer(this+192)`(0xc88c3)= 0xC0;types_common.h 的 Timer 为 8B({u32,u32})。**Ghidra 未建模该字段**(0xBC..0xD7 空洞);types_common.h `timer[32]` 大小错误(32B 会覆盖 ioCallbacks@0xD8),报告 §15 "Timer (32B?)" 的问号猜测亦不成立。
  - **0xD8/0xDC: IoFopenRead/IoFopenClose**。ctor `this+54 = IoFopenRead`、`this+55 = IoFopenClose` ✓。Ghidra `pIoCallbacks[8] @0xD8` ✓ 正确;types_common.h ioCallbacks 因 timer[32] 落在 0xE0(错)。
  - **0xEC/0xF0/0xF4(this+59..61 = -1)、0xF8(bField=1,byte+248)、0x100..0x110(this+64..68 = 0)** 全部 ✓。Ghidra 正确;types_common.h 自 bField_0xF8 起与名差 +4(bField_0xF8 实 0xF4)。
- 证据: IDA decompile ctor 0xc883a(1 次);Ghidra 侧已有函数 0xc883a 定义。报告 §15 字段表与 ctor 逐项吻合(除 timer 大小疑问),问题集中在**回写(Ghidra struct + types_common.h)的头部 4 字节错位**与**文档字段声明求和 ≠ 276B**。
- 问题清单:
  1. [FAIL] Ghidra struct 头部错位:`base[80]@0x00 + pVtable@0x50 + pSize[8]@0x54`;应改为 `pVtable@0x00 + base[76] + flSize(Vector2)@0x50`。pVtable 必须回到 0x00(ctor 证据),flSize 在 0x50。
  2. [FAIL] types_common.h 与 Ghidra 同样错位,且 `UNKNOWN_0x58[60]` 与 `decoderHandles[3]` 重叠(实 0x5C..0x97 vs 应 0x58..0x93)。
  3. [FAIL] types_common.h 字段声明求和 265B ≠ 注释 0x114(276B);且 `timer[32]` 应为 8B(标准 Timer,与 ioCallbacks@0xD8 冲突)。
  4. [WARN] Ghidra struct 缺 timer 字段(@0xC0,8B)。
  5. [INFO] 报告 §15 "Timer (32B?)" 建议更正为 8B Timer。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| VFXEffectEmitter | PASS | 无 |
| ParticleEmitter | PASS | 无 |
| PostProcessor | WARN | @0x00 误标 `pVtable`(实际无 vtable,uint=3);报告 dtor 摘要的 RT/tex 偏移错误(+0x44/+0x40 应为 +0x2C/+0x28) |
| VideoNode | FAIL | Ghidra/文档头部 +4 错位(vtable 应在 0x00,flSize 在 0x50);文档 `UNKNOWN_0x58[60]` 与 decoderHandles 重叠、`timer[32]` 应为 8B、声明求和 265B≠276B;Ghidra 缺 timer@0xC0 字段 |

注:本分片仅 3 个 IDA decompile 调用(其中 PostProcessor 用了 ctor+dtor 2 次,其余各 1 次),未超出"每类型 ≤2"共享预算。
