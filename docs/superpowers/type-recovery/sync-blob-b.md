# Sync Blob B — Phase B 重建 9 struct 布局同步到 types_common.h

> 输入: task-blob-b-sync-brief.md(同步范围 + 方法)
> 数据源: ghidra-mcp `get_struct_layout`(program=`dontstarve_steam`, 9 个 struct 全部实时拉取)
> 重建依据: retype-blob-b.md(Phase B 全量重建报告)
> 目标文件: `3rd/dst/game_decompiler/types_common.h`(仅此文件 + 本报告)
> 日期: 2026-08-10

## 同步结果

| struct | 变更 | 头文件 size | Ghidra size | 字段数(Ghidra) | 状态 |
|--------|------|------------|-------------|---------------|------|
| GameLibConfig | pField_0x00/pStrs/pNetIds 三 blob 全拆 → 21 字段 | 148B | 148B | 21 | ✓ |
| cShardManager | pField_0x00 → pVtable/nEShardType/…/strWorldSession; m_strList[2] → next/prev | 168B | 168B | 27 | ✓ |
| ParticleEmitter | UNKNOWN_0x04[132] 全拆 → 30 字段(含 cEntityComponent 基类尾) | 136B | 136B | 30 | ✓ |
| tServerListing | pStrs[52] → 13×cStdString(strName..strIntention) | 266B | 266B | 37 | ✓* |
| TDataCacheParticleBufferRenderer | pUNKNOWN_0x48[36] → 9 字段 + pOwner 类型化 | 108B | 108B | 12 | ✓ |
| TDataCacheVideoNode | pUNKNOWN_0x48[52] → 12 字段 + pad + pOwner 类型化 | 124B | 124B | 16 | ✓ |
| ImageNode | pUNKNOWN_0x94[112] → 22 字段 | 260B | 260B | 23 | ✓ |
| TDataCacheRoadManagerNode | pUNKNOWN_0x48[40] → 9 字段 + 尾 pad | 112B | 112B | 13 | ✓ |
| WindowManager | pField_0x04[120] 全拆 + 边界校正(删 pOCurrentModeFlags[12]) | 136B | 136B | 15 | ✓ |

\* tServerListing 尾部存在既知偏移怪癖,见下文「遗留」,非本次拆分引入。

struct 定义数: **278**(不变;`^struct ` 行 281 = 278 定义 + 3 前置声明)

## 关键差异记录

### 1. 新增 3 个前置声明(向后引用)
拆分后字段引用了定义在文件后部的类型,按头文件既有惯例(`struct SettingFile;` 行 347)在 `struct ParticleEmitter` 前新增:
```c
struct ParticleBuffer;         // 定义在行 677
struct ParticleBufferRenderer; // 定义在行 696
struct GameRenderer;           // 定义在行 706
```
指针引用不要求完整定义,前置声明即可;3 行计入 `^struct ` 计数,故 281 行 = 278 定义 + 3 声明。

### 2. pOwner/pRenderer 指针类型化(Ghidra 类型对齐)
- `TDataCacheParticleBufferRenderer.pOwner` void* → `ParticleBufferRenderer*`
- `TDataCacheVideoNode.pOwner` void* → `VideoNode*`(VideoNode 已定义于行 554)
- `TDataCacheRoadManagerNode.pRenderer` void* → `GameRenderer*`
- `WindowManager.pRenderer` void* → `Renderer*`(Renderer 已定义于行 684)
- `cShardManager.pShardBroadcast` void* → `cShardBroadcast*`(定义于行 485)
- `cShardManager.pCheshireCat` 保持 void*(tCheshireCat_Shard 头文件未定义)

### 3. 偏移校验(逐字段 vs Ghidra,含 C++ 自然对齐)
- 9/9 字段数与 Ghidra 一致(21/27/30/37/12/16/23/13/15)。
- 8/9 在 C++ 自然对齐下逐字段偏移 == Ghidra(含隐式 pad 自动复现,如 ImageNode fDepthWrite@0xF5 → pVField_F8@0xF8 的 2B pad)。
- 重命名保留既有头文件命名(m_shardPlayers/m_incomingMigrations 等),与 retype-blob-b「其余 17 字段原样保留」一致。

## 遗留(非本次范围,均未动)

- **cShardManager** bIncomingMigrationActive@0x5C → m_restartMigrations:Ghidra 0x60(隐式 3B pad 0x5D..0x5F),头文件按紧凑排列落 0x5D。尾部字段,Phase B 未重建,旧头文件同此表示。
- **tServerListing** 尾部三项:Ghidra nFlagsBoolPack@0xB2(未对齐 int)/pStr_0x104@0x104(隐式 3B pad)/wField_0x108@0x108;头文件 C++ 自然对齐后为 0xB4/0x101/0x106,size 264 vs Ghidra 266。即 retype-blob-b.md「wField_0x108 截断问题…保持现状」所述,本次保持现状。
- ParticleEmitter `pUNKNOWN_36`(26B)语义待查(不阻塞)。

## 验证

- `grep -c "^struct "` = 281(= 278 定义 + 3 前置声明,无新增/删除 struct 定义)。
- 9 个 struct 字段数逐一 == Ghidra get_struct_layout;8/9 逐字段偏移 == Ghidra(脚本核对,类型 size/对齐表:primitive + cNetID2 44/cStdString 4/ProcessId 4/Mutex 56/Timer 8/cShardBroadcast 4)。
- 旧 blob 字段(pField_0x00/pStrs/pNetIds/pUNKNOWN_0x04/pUNKNOWN_0x48/pUNKNOWN_0x94/pField_0x04/pOCurrentModeFlags)在 9 个 struct 中清零;残留 pUNKNOWN_0x48/pStrs 命中均为范围外 struct(TDataCacheGameRender/TDataCacheWorld/TDataCacheMiniMapComponent/cUnpackModThread),未改动。
- 其他 269 struct 未改动。

## 只写文件

- `3rd/dst/game_decompiler/types_common.h`
- `docs/superpowers/type-recovery/sync-blob-b.md`(本报告)
