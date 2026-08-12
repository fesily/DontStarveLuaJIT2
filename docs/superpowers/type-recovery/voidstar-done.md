# Phase 0-2 汇总 — void* 纠正完成 (2026-08-10)

## 执行模式
Subagent-Driven:6+5+2 轮只读调查 → 5 个 implementer 写 Ghidra → 主 agent 验证。全程 Ghidra 写操作由 implementer 串行执行(会话竞争保护)。

## Phase 0: 同步 types_common.h
- 5 分片 dump(sync-s{1..5}-*.md):242 struct exists / 74 missing(Size=1 占位)
- 合并:129 → **269 struct**(新增 139,跳过 103,8 处 TODO 引用缺失)
- 依赖检查:仅 `int16_t` builtin 白名单缺口(非真实)
- 注:原头文件本身不可编译(129 旧 struct 定义顺序问题),作为文档基线而非编译单元

## Phase 0.5: void* 纠正表
- 5 分片 audit(audit-s{1..5}-*.md):**570 个 void* 字段**
- 判定:确定 163 / 推断 94 / 待定 43 / 跳过 270(vector/vtable/rb-tree/pad)
- 汇总:voidstar-audit.md

## Phase 1: 回写 Ghidra(163/163 成功,0 失败)

| 分片 | 确定 | 成功 | 要点 |
|---|---|---|---|
| S1 网络/RakNet | 36 | 36 | cNetworkManager 管理器指针、Replica3 族、Serialize/Deserialize 参数 |
| S2 实体/场景 | 75 | 75 | cEntity 6、cSimulation 7、cGame Perf 块 19+管理器、MapComponent 5 |
| S3 渲染 | 35 | 35 | Renderer 七管理器 uint→指针、TDataCache 族 11、GameRenderer 5 |
| S4 UI/输入 | 5 | 5 | cUIScreen/cGameScreen.pGame、widget 对象指针 |
| S5 系统/杂项 | 12 | 12 | cApplication 3、PerfIndicator/Pane.pGame、HttpClient2 |

## Phase 2: 验证
- 抽查 5 个关键 struct(cEntity/cSimulation/cGame/Renderer/cNetworkManager):类型全部生效、size 未变
- 反编译冒烟:`cNetworkComponent::Serialize` 完整解析(SerializeParameters*/BitStream 字段/cEntity 成员)
- save_program 成功

## 剩余(记录在案,未执行)
- **推断 94**:需先建类型(Bullet bt*、RakPeerInterface、NetworkIDManager、cEventDispatcher、std::string* 等)
- **待定 43**:无证据,保持 void*
- **跳过 270**:vector/vtable/rb-tree/pad(设计决定)
- **types_common.h 8 处 TODO**:CommandBuffer/RenderState/Matrix4/GameService_PlayerId 等引用缺失

## 产出文件
- docs/superpowers/type-recovery/sync-s{1..5}-*.md(布局 dump)
- docs/superpowers/type-recovery/audit-s{1..5}-*.md(纠正表)
- docs/superpowers/type-recovery/retype-s{1..5}-*.md(回写记录)
- docs/superpowers/type-recovery/voidstar-audit.md(总表)
- docs/superpowers/../../3rd/dst/game_decompiler/types_common.h(269 struct)
- docs/superpowers/type-recovery/sync-merge-report.md(合并记录)
