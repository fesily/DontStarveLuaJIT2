# Review Slice 21 — Shader / HWEffect / Effect / EffectManager 回写一致性审查

> 审查对象:回写到 Ghidra(dontstarve_steam, macOS i386, base 0x1000)的 struct 布局
> 对照文档:`docs/superpowers/../../3rd/dst/game_decompiler/types_common.h` + `tier3-a-rendering.md` §16-17
> 交叉验证:idalib-mcp 会话 f9cdc808(同二进制 dontstarve_steam)
> 方法:get_struct_layout 读 Ghidra 布局 → 与文档比对 → IDA decompile 抽查 ctor/dtor/使用函数
> 状态:只读审查,未做任何写入

## 审查结论速览

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| Shader | PASS | 无 |
| HWEffect | FAIL | Ghidra 大小 156B ≠ 实际 160B,缺偏移 0x9C 的初始化标志字段;types_common.h 与分片报告大小记载互相矛盾 |
| Effect | WARN | 总大小 164B、name@0xA0 正确;但内嵌 base(HWEffect)缺 0x9C 字段,156..160 被建模成隐式 padding |
| EffectManager | PASS | 无 |

---

### Shader
- 状态: PASS
- Ghidra 大小: 24B | 文档大小: 24B(types_common.h `// 0x18`;tier3-a-rendering.md §16 24B)| 匹配: yes
- 字段比对: 无差异。Ghidra `{pVtable@0, nHandle@4, pName[4]@8, nField_0x0C@0xC, nField_0x10@0x10, nField_0x14@0x14}` 与 types_common.h `{void* pVtable; int32_t nHandle; uint8_t name[4]; int32_t nField_0x0C/0x10/0x14}` 及报告字段表 `{vtable@0, int nHandle@4(-1), std::string name@8, +0xC=0, +0x10=0, +0x14=0}` 完全一致。次要:偏移 0x0C 实为可被释放的指针(dtor 检查后 operator delete),Ghidra 记为 int,建议 void* —— 仅类型语义,非布局问题。
- 证据: `Shader::~Shader` (0x1c6520):vtable@0 = unk_457778;`__glewDeleteShader(*(this+1))` → nHandle@4;`*(this+3)` 非零则 `operator delete` → 指针@0xC;`*(this+2)` 走 `_M_destroy` → std::string name@8。所有偏移吻合。
- 问题清单: 无

### HWEffect
- 状态: FAIL
- Ghidra 大小: 156B | 文档大小: 160B(tier3-a-rendering.md §16 标题 "164B / 160B / 24B"、回写建议 "HWEffect 160B"、tier3-gamestuff.md 关键子类型 "HWEffect 160B";**但 types_common.h 记为 `// 0x9C` = 156B,文档自相矛盾**)| 匹配: no
- 字段比对: 偏移 0x00..0x98 全部字段名/偏移/类型与 types_common.h、报告字段表一致(vsShader@4 / psShader@0x1C / pShaderData@0x34 / shaderName@0x38 / nShaderDataSize@0x3C / glProgram@0x40 / paramMap1@0x48(28B) / paramMap2@0x64(28B) / paramData@0x80 / paramInfo@0x8C / UNKNOWN_str@0x98)。**缺失偏移 0x9C 的 4B 字段**(初始化状态标志)——Ghidra 与 types_common.h 均把 HWEffect 记为 156B,报告字段表同样止于 0x98(即其 160B 结论与自身字段表不自洽)。命名差异(仅前缀):Ghidra `dwShaderDataSize/dwGlProgram` vs 文档 `nShaderDataSize/glProgram`,偏移与类型相同。
- 证据: `HWEffect::Init` (0x1c6c0c):`*((_DWORD*)thisa+39) = 1`(置位 +0x9C),三个 Init 子步骤成功后 `= 0`,返回 `flag == 0` —— +0x9C 是 HWEffect 真实字段(语义:初始化状态,0=成功,非0=失败);`EffectManager::DoLoad` (0x1c54d4):`new 0xA4` 后读 `*((_DWORD*)v3+39)`(+0x9C),非零则调 vtable dtor 并返回 0;`Effect::Effect` (0x1c6604):在 +0xA0 构造 std::string name。→ HWEffect 实际占用 0x00..0xA0 = **160B(0xA0)**。
- 问题清单: (1) Ghidra HWEffect 大小 156B ≠ 二进制实际 160B;(2) 缺字段(建议名 bInitialized / nInitState)@0x9C;(3) types_common.h(0x9C=156B)与 tier3-a-rendering.md/tier3-gamestuff.md(160B)对该类型大小记载不一致。

### Effect
- 状态: WARN
- Ghidra 大小: 164B | 文档大小: 164B(types_common.h `// 0xA4`;tier3-a-rendering.md 164B(0xA4))| 匹配: yes
- 字段比对: Ghidra `{base(HWEffect 156B)@0, pName[4]@160}` 与 types_common.h `{HWEffect base; uint8_t name[4]}`、报告 `name @0xA0` 一致。唯一问题:Ghidra 中 base 为 156B,Effect 内 156..160 呈现为隐式 padding,而二进制实际该区域是 HWEffect.bInitialized@0x9C —— Effect 的字节足迹(164B)与 name 偏移(0xA0)均正确,但字段级建模继承了 HWEffect 缺字段问题。
- 证据: `Effect::Effect` (0x1c6604):调 HWEffect ctor → vtable = unk_457788 → `std::string::string((char*)thisa+160)`(name@0xA0);`EffectManager::DoLoad` (0x1c54d4):`operator new(0xA4)` 分配 164B,`Effect::Effect` 构造,`Renderer::InitializeEffect` (0x1d4bf2) 经 vtable slot2 调 `HWEffect::Init`(0x1c6c0c)写 +0x9C 标志。
- 问题清单: 依赖 HWEffect 缺 4B 字段;若 HWEffect 修正为 160B(补 0x9C 字段),Effect 总大小与 pName@0xA0 不变,仍为 164B,布局自动正确。

### EffectManager
- 状态: PASS
- Ghidra 大小: 148B | 文档大小: 148B(types_common.h `// 0x94`;tier3-a-rendering.md §17 "FrameDelayed<Effect> = 148B")| 匹配: yes
- 字段比对: Ghidra 整体 `byte[148]` 占位,与 types_common.h `{uint8_t base[148]}` 一致;文档同样未细分字段,仅给出 FrameDelayedResourceManager 模板布局(cResourceManager 基类 + CriticalSection@0x40 + vec@0x78 + pRenderer@0x90 = 148B),二者无冲突。
- 证据: `EffectManager::DoLoad` (0x1c54d4):经 `thisa[36]`(= +0x90)取 Renderer,`new 0xA4` 构造 Effect 并调 `Renderer::InitializeEffect(renderer, effect)` —— +0x90 pRenderer 与 FrameDelayed 模板布局吻合。
- 问题清单: 无(占位建模,未细分字段,与文档一致)

---

## 附注

- 本分片审查范围按 Target 为渲染四类型;COOP 模板中残留的 "Mutex/cHashedString/cHashedStringCSL/cEntityComponent" 清单与 Target/Change/Acceptance(tier3-a-rendering.md 尺寸)冲突,以 Target 为准,未审查后者。
- 交叉验证 decompile 用量:Shader 1、HWEffect 2、Effect 1、EffectManager 1(另 1 次 Renderer::InitializeEffect 辅助,非本分片类型),均 ≤2 次/类型。
- 唯一需要主 agent 决策的问题:HWEffect 是否补 4B 字段 @0x9C 并将大小修正为 160B(需写操作,本审查未执行)。
