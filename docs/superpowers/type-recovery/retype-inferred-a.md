# Phase 1 Inferred A Retype — EXISTS 推断字段回写报告

> 输入: task-inferred-a-brief.md(16 项)+ inferred-types-audit.md「Direct rewrite candidates(EXISTS)」
> 操作: ghidra-mcp modify_struct_field 写回 dontstarve_steam(macOS i386)
> 验证: 全部 12 个涉及 struct 的 get_struct_layout 复核 — 类型已变、字段名保留、size 未变
> 注: 两段式同 S1-S5 — 先按字段名改类型(会清空字段名),再以 `field_name:"offset:0xN"` + new_name 重新落名。嵌套类型名已 search_data_types 确认实际可用名。

## 类型预检(search_data_types)

| 推断类型 | 实际类型 | size | 路径 |
|------|------|------|------|
| cNetworkManager::ServerListingData | `ServerListingData` | 27 | /ServerListingData |
| cNetworkManager::tCheshireCat | `tCheshireCat_Network` | 352 | /tCheshireCat_Network |
| cShardManager::tCheshireCat | `tCheshireCat_Shard` | 64 | /tCheshireCat_Shard |
| cTwitchManager::tCheshireCat | `tCheshireCat_Twitch` | 1409 | /tCheshireCat_Twitch |
| Buffer | `Buffer` | 12 | /Buffer |
| cBaseFactory | `cBaseFactory` | 60 | /cBaseFactory |
| cSpatialHash_cEntity | `cSpatialHash_cEntity` | 40 | /cSpatialHash_cEntity |
| MapLayerManagerComponent | `MapLayerManagerComponent` | 84 | /MapLayerManagerComponent |
| MOTDImageLoader | `MOTDImageLoader` | 16 | /MOTDImageLoader |
| PluginInterface2 | `PluginInterface2` | 12 | /PluginInterface2 |
| pthread_t | `pthread_t` | 4 | /_pthread_t.h/pthread_t |
| SoundProjectManager | `SoundProjectManager` | 64 | /SoundProjectManager |
| Thread | `Thread` | 248 | /Thread |
| TileGrid | `TileGrid` | 28 | /TileGrid |

## 成功 (16/16)

| struct.field | 新类型 | 偏移 |
|------|------|------|
| BinaryBufferWriter.pBuffer | Buffer * | 0x4 |
| cEntityManager.pComponentFactory | cBaseFactory * | 0x88 |
| cEntityManager.pSpatialHash | cSpatialHash_cEntity * | 0xF8 |
| cNetworkManager.pServerListingData | ServerListingData * | 0x1FC |
| cNetworkManager.pCheshireCat | tCheshireCat_Network * | 0x11C |
| cNetworkManager.pAdditionalPlugin | PluginInterface2 * | 0xF0 |
| cShardManager.pCheshireCat | tCheshireCat_Shard * | 0x9C |
| cTwitchManager.pCheshireCat | tCheshireCat_Twitch * | 0x4 |
| MapRenderer.pLayerMgr | MapLayerManagerComponent * | 0x4 |
| cGame.pMOTDImageLoader | MOTDImageLoader * | 0x58 |
| cGame.pSoundProjectManager | SoundProjectManager * | 0x50 |
| Thread.pThread | pthread_t | 0x48 |
| cSimulation.pPhysicsThread | Thread * | 0x190 |
| cNetworkTileRegion.pTileGrid | TileGrid * | 0x16C |
| WorldSimActual.pTileGrid | TileGrid * | 0x8 |
| MapComponent.pNavGrid | TileGrid * | 0x16C |

## 失败清单

无(SKIP_NESTED: 0 / FAIL_SPACE: 0 / FAIL_FIELD: 0)

## 说明

- 第 10 项(cGame.pAdditionalPlugin):实际字段位于 cNetworkManager.pAdditionalPlugin(offset 0xF0),已按 audit 表回写 PluginInterface2 *。
- Thread.pThread:pthread_t 本身即 4 字节指针 typedef(`__darwin_pthread_t` = `_opaque_pthread_t *`),字段按**值**类型 `pthread_t` 回写(非 pthread_t *),与 4 字节布局一致。
- 4 个嵌套类型(cNetworkManager::ServerListingData / 三个 ::tCheshireCat)均以 Ghidra 实际恢复名(根类别下划线形式)引用,全部成功,无 SKIP_NESTED。

## 抽查结果(12 struct, 全部 get_struct_layout 复核)

| struct | size(改前/改后) | 关键字段确认 |
|------|------|------|
| BinaryBufferWriter | 12 / 12 | pBuffer = Buffer * |
| cEntityManager | 309 / 309 | pComponentFactory = cBaseFactory *;pSpatialHash = cSpatialHash_cEntity * |
| cNetworkManager | 5048 / 5048 | pServerListingData = ServerListingData *;pCheshireCat = tCheshireCat_Network *;pAdditionalPlugin = PluginInterface2 * |
| cShardManager | 168 / 168 | pCheshireCat = tCheshireCat_Shard * |
| cTwitchManager | 40 / 40 | pCheshireCat = tCheshireCat_Twitch * |
| MapRenderer | 28 / 28 | pLayerMgr = MapLayerManagerComponent * |
| cGame | 304 / 304 | pMOTDImageLoader = MOTDImageLoader *;pSoundProjectManager = SoundProjectManager * |
| Thread | 248 / 248 | pThread = pthread_t |
| cSimulation | 412 / 412 | pPhysicsThread = Thread * |
| cNetworkTileRegion | 388 / 388 | pTileGrid = TileGrid * |
| WorldSimActual | 36 / 36 | pTileGrid = TileGrid * |
| MapComponent | 400 / 400 | pNavGrid = TileGrid * |

结论:16 个 EXISTS 推断字段全部成功回写,字段名保留、size 未变。已 save_program。
