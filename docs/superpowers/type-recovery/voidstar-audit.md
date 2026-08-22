# void* 字段纠正总表 (voidstar-audit.md) — 2026-08-10

> 汇总 5 份 audit 分片(只读调查,主 agent 统一回写)。
> 判定:确定=语义明确且类型已在 types_common.h;推断=语义明确但需建类型;待定=无证据;跳过=vector/list/vtable/rb-tree/pad。
> 分片:audit-s1-net / s2-entity / s3-render / s4-ui / s5-misc.md

## 汇总统计

| 分片 | 确定 | 推断 | 待定 | 跳过 | void* 合计 |
|---|---|---|---|---|---|
| S1 网络/RakNet | 36 | 39 | 1 | 50 | 126 |
| S2 实体/场景 | 75 | 33 | 17 | 104 | 229 |
| S3 渲染 | 35 | 3 | 10 | 38 | 86 |
| S4 UI/输入 | 5 | 6 | 6 | 9 | 26 |
| S5 系统/杂项 | 12 | 13 | 9 | 69 | 103 |
| **合计** | **163** | **94** | **43** | **270** | **570** |

## 判定规则

- **确定(163)**:字段名/偏移语义明确 + 目标类型已在 types_common.h → Phase 1 直接 `modify_struct_field`
- **推断(94)**:语义明确但目标类型未建(见下「需建类型清单」)→ Phase 1 先建类型再纠正,或标记 deferred
- **待定(43)**:无证据 → 保留 `void*`,记录在案
- **跳过(270)**:vector 三件套、vtable 指针、rb-tree 节点、pPad_/pField_/pUnknown_ → 不纠正

## 需建类型清单(推断项目标,94 个中涉及)

### S1 网络 (39 推断)
std::string*, RakPeerInterface*, NetworkIDManager*, RPC4*, ReadyEvent*, SnapshotManager*, cNetworkManager::tCheshireCat*, cNetworkManager::ServerListingData*, cShardManager::tCheshireCat*, cTwitchManager::tCheshireCat*, DirectoryDeltaTransfer*, FileListTransfer*, IncrementalReadInterface*, TCPInterface*, CURL*, CURLM*, curl_slist*, ClientThread*, TileGrid*, uint8_t*/uint16_t* buffers

### S2 实体 (33 推断)
Bullet 系(bt*), TileGrid/BoostMap, InputManager/FileManager, cEventDispatcher, cTransformProvider, cSpatialHash\<cEntity\>, 等

### S3 渲染 (3 推断)
Matrix4*, CommandBuffer*, RenderState*(等)

### S4 UI (6 推断)
IInputManager*, IInputDevice*, SDLInputManager*, 等(注:S4 的 missing 结构本身未建)

### S5 系统 (13 推断)
ClientThread*, TwitchAuthThread 相关, cPlayerSaveLocation 依赖, 等

## 执行顺序(Phase 1)

1. 先建「需建类型」中已在 types_common.h 出现的(合并时 8 处 TODO 的类型)
2. 对每个「确定」字段:`modify_struct_field(struct, field, new_type)`
3. 「推断」中目标类型可建且证据强的 → 建类型后纠正;否则 defer
4. 「待定」保留 void*

## 详细表

见各分片文件:
- docs/superpowers/type-recovery/audit-s1-net.md
- docs/superpowers/type-recovery/audit-s2-entity.md
- docs/superpowers/type-recovery/audit-s3-render.md
- docs/superpowers/type-recovery/audit-s4-ui.md
- docs/superpowers/type-recovery/audit-s5-misc.md
