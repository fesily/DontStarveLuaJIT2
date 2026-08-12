# types_common.h TODO 修复报告

- 日期: 2026-08-10
- 文件: docs/superpowers/../../3rd/dst/game_decompiler/types_common.h(仅此文件改动)
- 范围: 6 个缺失类型定义 + 8 处引用更新,删除全部 `// TODO: X not in header` 注释
- 原则: 所有 struct 总 size 保持不变(引用处以同尺寸类型替换)

## 新增类型定义

| 类型 | 大小 | 定义来源 | 布局依据 |
|---|---|---|---|
| `RenderState` | 372B (0x174) | sync-s3-render.md | Renderer.renderState 引用(offset 16→388);无独立 struct,用 opaque 保持尺寸 |
| `CommandBuffer` | 120B (0x78) | sync-s3-render.md | Renderer.cmdBuf 引用(offset 444→564);无独立 struct,用 opaque 保持尺寸 |
| `Matrix4` | 64B (0x40) | sync-s3-render.md | GameRenderer.pMatrices 为 `Matrix4[18]` @564,1152/18=64 → `float m[16]` |
| `GameService_PlayerId` | 36B (0x24) | sync-s5-misc.md | `### GameService_PlayerId` 真实布局:`uint[9] pM_data` |
| `cFreeCamera_sParams` | 24B (0x18) | sync-s2-entity.md | cFreeCamera.params 引用(offset 200→224);无独立 struct,opaque `data[24]` |
| `cTransformationHistory` | 24B (0x18) | tier3-e-system.md §28 | 已验证布局(Init 0x1B7690 + Write 0x1B76D6):RakNet Queue + 2 计数;+0x00 pBuffer / +0x04 dwHead / +0x08 dwTail / +0x0C dwCapacity / +0x10 dwMaxEntries / +0x14 dwTickIntervalMS |
| `cTransformationHistoryCell` | 20B (0x14) | tier3-e-system.md §27 | 附属类型(Queue 元素,ctor 0x1B763C):dwTimeMS / flPosX / flPosY / flPosZ / flRotation |

> cTransformationHistoryCell 为 cTransformationHistory(环形队列)的元素类型,一并补入以便引用链完整。

## 引用更新(8 处)

| 原字段 | 新字段 | 所在 struct | size 核对 |
|---|---|---|---|
| `uint8_t renderState[372]` | `RenderState renderState` | Renderer | 372B→372B,total 0x234 不变 |
| `uint8_t cmdBuf[120]` | `CommandBuffer cmdBuf` | Renderer | 120B→120B |
| `uint8_t pMatrices[1152]` | `Matrix4 pMatrices[18]` | GameRenderer | 1152B→18×64B,total 0x7e8 不变 |
| `uint8_t playerId[36]` | `GameService_PlayerId playerId` | FileOpResult | 36B→36B,total 0x148 不变 |
| `uint8_t playerId[36]` | `GameService_PlayerId playerId` | FileOpRequest | 36B→36B,total 0x144 不变 |
| `uint8_t playerId[36]` | `GameService_PlayerId playerId` | GameService_PlayerInfo | 36B→36B,total 0x126 不变 |
| `uint8_t params[24]` | `cFreeCamera_sParams params` | cFreeCamera | 24B→24B,total 0x14c 不变 |
| `void* pTransformHistory` | `cTransformationHistory* pTransformHistory` | cTransformComponent | 4B→4B,total 0x17c 不变 |

## 定义插入位置(均在引用之前)

- 实体/场景区块:`cTransformationHistoryCell` / `cTransformationHistory` / `cFreeCamera_sParams`(cTransformComponent 之前)
- 渲染区块:`RenderState` / `CommandBuffer` / `Matrix4`(Renderer 之前)
- 系统/杂项区块:`GameService_PlayerId`(FileOpResult 之前)

## 验证

- `grep TODO types_common.h` → 无匹配(8 处 TODO 注释已全部删除,区块规则注释同步更新)
- 6 个新类型名均有定义,8 处引用类型名与定义一一对应
- 各引用 struct 的 `total` 注释与 Ghidra sync 布局(sync-s{2,3,5}-*.md)一致,无尺寸漂移

## 备注

- RenderState / CommandBuffer / cFreeCamera_sParams 在 Ghidra 中无独立结构体布局,按 brief 约定以 opaque 占位保持尺寸;字段语义后续可另行恢复。
- `DontStarveSystemService.m_playerId[36]`、`GameServiceImpl.pPlayerInfo[294]` 非本次 TODO 范围,保持原样。
