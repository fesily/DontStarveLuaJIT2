# Review 修复记录 (2026-08-08)

> 28 个并行 review agent 审查 111 个回写类型,主 agent 统一修复。
> Review 报告:`docs/superpowers/type-recovery/review-slice0..27.md`(只读,未修改)。

## 审查结果统计

- **PASS**: ~90 类型(字段偏移/类型/大小与文档一致)
- **FAIL**: 8 类型(布局错误,已修复)
- **WARN**: ~15 类型(多为尾部 padding 缺失或命名风格,已修复 padding)
- 28 份报告全部生成,每类型含:状态、Ghidra vs 文档大小、字段比对、IDA/Ghidra 反编译证据

## FAIL 修复(8 类型)

| 类型 | 问题 | 修复 |
|---|---|---|
| cEntity | 0x50/0x54(worldNode↔UINode)、0xD4/0xD8(network↔transform)字段名与 IDB 基准互换;0xF4 bRetired 命名冲突 | 按 IDB 39 成员重建 252B |
| cInputTextEvent | sText 误作 byte[12],实为 4B CoW string,总 0x14→0x0C | 重建 0x0C |
| DontStarveInputHandler | ref 三字段偏移 -4;缺 mInitVec[16]@0x18、oControlMapper 516B、bWheelState/bState、尾部 3×int;708→720B | 重建 720B |
| PathfinderComponent | map2/searches 偏移 -4/-8(20B RBTree 模型,实际 24B) | 重建 104B,24B map 模型 |
| HWEffect | 缺 bInitState@0x9C,156→160B | 重建 160B |
| VideoNode | 头布局 +4 错位(vtable 应在 0x00);timer 误作 32B 实为 8B | 重建 276B |
| TagSet | counts 误作 byte 实为 int32;69→72B;staticTags 重名 | 重建 72B |
| cGiftingManager | 缺 m_giftItems@0x48、m_unverifiedReceipts@0x60;Mutex_2 偏移错 | 重建 160B |

## WARN padding 修复(7 类型)

| 类型 | 原大小 | 修复后 |
|---|---|---|
| cInputKeyEvent | 13B | 0x10 |
| cTogglePauseEvent | 9B | 0x0C |
| cAccountCommunication | 193B | 0xC4 |
| MapComponent | 397B | 0x190 |
| Atlas | 25B | 0x1C |
| PersistentStorage | 5B | 8B |
| cReader | 17B | 0x14 |

## 未修复的 WARN(低优先,记录不处理)

- ~~cEntityManager: pSimulation 类型 -BAD-~~ **已修复**(2026-08-08:改为 cSimulation*,根因是悬空类型引用,cSimulation 曾被删重建)
- cEntityManager: sizeof 312B vs 309B(对齐,布局正确)、vtable 文档地址(实 0x456624)、vec 块命名(文档精度)
- cNetworkLuaProxy +0x08 容器语义存疑
- cSoundEmitterComponent 字段命名误导(+0x10 实为 FMOD::Event* 数组)
- RenderTargetManager/EffectManager byte[148] 未拆字段
- 各类型 Ghidra 字段名前缀风格差异(cosmetic,不影响布局)
- 文档级:types_common.h QuadTreeNode set 偏移、BitmapFontManager 文档偏移等

## 同步动作

- [x] Ghidra 15 个 struct 修复/重建
- [x] types_common.h 同步(11 处替换 + cEntity 补全)
- [x] 本记录文件
