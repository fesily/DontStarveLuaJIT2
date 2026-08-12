# Phase 0 Step 3 — sync 报告 struct 合并报告

> 日期: 2026-08-10
> 数据源: `sync-s1-net.md` / `sync-s2-entity.md` / `sync-s3-render.md` / `sync-s4-ui.md` / `sync-s5-misc.md`(ghidra-mcp `get_struct_layout`,只读)
> 目标文件: `docs/superpowers/../../3rd/dst/game_decompiler/types_common.h`(仅追加,未改动原有 129 struct 的字段)

## 汇总

| 指标 | 数量 |
|---|---|
| 报告 exists:true 条目 | 245(去重后 242 唯一,3 个重复名) |
| 已在头文件(跳过,未改动) | 103 |
| **新增 struct** | **139** |
| 引用缺失 TODO | 6 类型 / 8 处 |
| 合并后头文件 struct 数 | 129 + 139 = 268(唯一名;物理行 269,`SettingFile` 原有前向声明 + 定义各 1 行) |

## 新增区块分布(按子系统追加)

| 区块 | 来源 | 新增数 |
|---|---|---|
| 网络/RakNet | sync-s1-net.md | 35 |
| 实体/场景 | sync-s2-entity.md | 24 |
| 渲染 | sync-s3-render.md | 45 |
| UI | sync-s4-ui.md | 13 |
| 系统/杂项 | sync-s5-misc.md | 22 |
| **合计** | | **139** |

## 引用缺失 TODO(6 类型 / 8 处)

缺失类型按规则以 `uint8_t[N]`(值/数组)或 `void*`(指针)占位,行尾标注 `// TODO: <Type> not in header`:

| 缺失类型 | 使用处 | 占位形式 |
|---|---|---|
| `RenderState` | `Renderer.renderState` | `uint8_t renderState[372]` |
| `CommandBuffer` | `Renderer.cmdBuf` | `uint8_t cmdBuf[120]` |
| `Matrix4` | `GameRenderer.pMatrices` | `uint8_t pMatrices[1152]`(18×64B) |
| `GameService_PlayerId` | `GameService_PlayerInfo.playerId` / `FileOpRequest.playerId` / `FileOpResult.playerId` | `uint8_t playerId[36]` ×3 |
| `cFreeCamera_sParams` | `cFreeCamera.params` | `uint8_t params[24]` |
| `cTransformationHistory` | `cTransformComponent.pTransformHistory` | `void* pTransformHistory` |

## 无法转换字段清单

即上表 8 处占位字段(布局尺寸按相邻字段偏移差保留,不丢失):

- `Renderer.renderState` — `RenderState`(值类型,372B)→ `uint8_t[372]`
- `Renderer.cmdBuf` — `CommandBuffer`(值类型,120B)→ `uint8_t[120]`
- `GameRenderer.pMatrices` — `Matrix4[18]`(数组,1152B)→ `uint8_t[1152]`
- `GameService_PlayerInfo.playerId` / `FileOpRequest.playerId` / `FileOpResult.playerId` — `GameService_PlayerId`(36B)→ `uint8_t[36]`
- `cFreeCamera.params` — `cFreeCamera_sParams`(24B)→ `uint8_t[24]`
- `cTransformComponent.pTransformHistory` — `cTransformationHistory*`→ `void*`

## 特殊处理说明

- **cFactory**:sync-s5 标注 `exists: false`(Search notes:"cFactory: not found as Structure"),未新增。
- **附录别名区**(sync-s5 "Notes / aliases"):`SoundProjectManager`(64B)、`GameService_PlayerId`(36B)为非主列表条目,未新增;`GameService_PlayerId` 作为引用缺失类型以 TODO 记录。
- **重复条目**:`cNetworkReplicaManager`、`cSteamRichPresence`、`cMasterServerRequest` 各出现 2 次,内容一致,取字段完整者(唯一 242 = 245 − 3)。
- **`(unnamed)` 字段**:`cNetworkRPCManager` 偏移 0x04 的 `BitStream*` 命名为 `unnamed_0x04`。
- **`-BAD-` 基类**:`cDontStarveSim.base_cSimulation` 按字段名解析为 `cSimulation`(头文件已有,412B)。
- **Ghidra `pointer` 类型**(53 处)映射为 `void*`;`undefined1`/`uchar` → `uint8_t`;`undefined4`/`dword` → `uint32_t`;`short` → `int16_t`;`ulonglong` → `uint64_t`。
- **依赖顺序**:各区块内按"被引用类型先定义"拓扑排序;RakNet 基础类型(`BitStream`/`RakNetGUID`/`SystemAddress`/`PRO`/`PluginInterface2`/`NetworkIDObject`/`RakNetList`/`LastSerializationResult`/`LastSerializationResultBS`/`SerializeParameters`/`DeserializeParameters`/`RM3World`)置于网络区块前部。
- **跨区块引用**:`AnimNode`(渲染)→ `SceneGraphNode`(实体/场景),区块顺序自然满足。
- 每个新增 struct 行尾注释含 `// total 0xH = N`(十六进制 + 十进制)。
