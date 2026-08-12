# UNKNOWN 字段修复计划 (2026-08-10)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** 修复 143 struct / 483 个 UNKNOWN 字段。方法:用 Ghidra `analyze_struct_field_usage` / `get_field_access_context` 全二进制扫描 struct 字段的引用点,反编译访问代码推断字段语义,统一命名后回写 Ghidra + 同步 types_common.h。

**Architecture:** 只读 agent 分片扫描字段引用 → 每字段产出「语义推断 + 证据(访问点地址/反编译片段)」→ 主 agent 汇总命名规则 → implementer 回写 Ghidra 字段名 + types_common.h。沿用「只读调查 + 统一回写」模式。

**Tech Stack:** ghidra-mcp(analyze_struct_field_usage / get_field_access_context / decompile_function / modify_struct_field / rename_variable)、types_common.h

## Global Constraints

- 目标二进制固定:`dontstarve_steam`(macOS i386)。
- 只读 agent 禁止写 Ghidra;回写由主 agent 派 implementer 串行执行。
- 字段名命名规则(沿用项目惯例):
  - 语义已知 → `p<Name>`/`n<Name>`/`b<Name>`/`dw<Name>`/`fl<Name>`/`w<Name>`(指针/int/bool/uint/float/ushort)
  - 语义仍不明 → 保留 `UNKNOWN_0xXX` 并记录「已扫描无证据」
- 每字段证据必须含:访问点地址 + 反编译片段摘要;无证据不命名。
- `_pad`/`pPad_*`/`p_pad*` 填充字段不扫描(设计决定)。
- UNKNOWN_0xXX(42 个)优先于 nField_0xXX(254 个)处理 — 前者是有名占位,后者是纯数字占位,命名收益前者更高。

## 背景盘点(已确认)

| 类别 | 数量 | 说明 |
|---|---|---|
| UNKNOWN_0xXX | 42 | 显式 UNKNOWN 占位,优先 |
| nField_0xXX | 254 | int 占位 |
| dwField_0xXX | 53 | uint 占位 |
| bField_0xXX | 58 | byte 占位 |
| wField_0xXX | 19 | ushort 占位 |
| flField_0xXX | 14 | float 占位 |
| pField_0xXX | 7 | 指针占位 |
| 其他 | 36 | unnamed/pPad 等 |
| **合计** | **483** | 143 struct |

Top structs:WaveComponent 29、cNetworkManager 18、TextNode 18、DebugRenderComponent 17、tServerListing 17、cSoundEmitterComponent 16、VideoNode 15、cUITransformComponent 15、MiniMapComponent 14

## Phase 1: 分片扫描(5 个只读 agent,每片 ~30 struct)

**Files:**
- Read: docs/superpowers/type-recovery/sync-s{1..5}-*.md(struct 布局)
- 产出: docs/superpowers/type-recovery/unknown-scan-<slice>.md

- [ ] S1 网络: cNetworkManager(18)、cNetworkClientObject2(8)、cShardManager(7)、tServerListing(17)、cSteam*、cPendingConnection、MigrationInfo 等
- [ ] S2 实体: WaveComponent(29)、MiniMapComponent(14)、DebugRenderComponent(17)、RoadManagerComponent(10)、cUITransformComponent(15)、cEntityManager、cSimulation、cTransformComponent 等
- [ ] S3 渲染: Renderer(10)、TextNode(18)、VideoNode(15)、cSoundEmitterComponent(16)、TDataCache*、VFX* 等
- [ ] S4 UI: ControlMapper(9)、cConsoleInput、DontStarveInputHandler、cTextEditWidget 等
- [ ] S5 系统: FileHandle(8)、cInventoryManager、cSoundSystem、cMasterServer、GameServiceImpl 等

**扫描方法(每字段):**
1. `analyze_struct_field_usage(struct_name, address=struct实例地址, program=dontstarve_steam)` 列出字段访问点
2. 关键访问点 `decompile_function` 反编译,看字段如何被读写
3. 命名 + 证据

**输出格式:**
```
### <Struct>.<Field> @ 0xXX
semantic: <建议名> | UNKNOWN (保持)
evidence: <访问点地址 + 反编译摘要>
confidence: high/medium/low
```

## Phase 2: 汇总命名(主 agent)

- [ ] 合并 5 片结果,去重命名冲突,生成 `unknown-naming-table.md`
- [ ] 标注每字段:确定命名 / 待定 / 无证据保持

## Phase 3: 回写

- [ ] implementer 按命名表回写 Ghidra(`modify_struct_field` new_name)+ 同步 types_common.h
- [ ] 验证:get_struct_layout 抽查 + save_program

## 验收

- [ ] 全部 483 字段完成扫描(命名或明确无证据)
- [ ] 命名字段带证据链
- [ ] Ghidra + types_common.h 同步
- [ ] save_program
