# Phase 1 S1 Retype — Network/RakNet void* 回写报告

> 输入: audit-s1-net.md 的「确定」判定(36 个)
> 操作: ghidra-mcp modify_struct_field 写回 dontstarve_steam(macOS i386)
> 验证: 每个 struct get_struct_layout 抽查 — 类型已变、字段名保留、size 未变
> 注: modify_struct_field 单独调用会把字段名清空(显示 unnamed),已用 offset:N 定位 + new_name 恢复原字段名,最终布局字段名与 audit 表一致。

## 成功 (36/36)

| struct.field | 新类型 | 偏移 |
|------|------|------|
| cNetworkManager.pNetworkRPCManager | cNetworkRPCManager * | 0xCC |
| cNetworkManager.pNetworkVoiceManager | cNetworkVoiceManager * | 0xD0 |
| cNetworkManager.pNetworkReplicaManager | cNetworkReplicaManager * | 0xD4 |
| cNetworkManager.pSteamFriendsManager | cSteamFriendsManager * | 0xD8 |
| cNetworkManager.pMasterServer | cMasterServer * | 0xF8 |
| cNetworkManager.pNatTraversal | cNatTraversal * | 0xFC |
| cNetworkManager.pClientColourPicker | cClientColourPicker * | 0x104 |
| cNetworkManager.pSimulation | cSimulation * | 0x110 |
| cNetworkManager.pSteamPunchthrough | cSteamPunchthrough * | 0x1B8 |
| cNetworkManager.pSteamRichPresence | cSteamRichPresence * | 0x1364 |
| cNetworkManager.pDedicatedServerProcess1 | cDedicatedServerProcess * | 0x13B0 |
| cNetworkManager.pDedicatedServerProcess2 | cDedicatedServerProcess * | 0x13B4 |
| cNetworkRPCManager.pSlotNames | char * * | 0x8 |
| cNetworkClientObject2.pPlayerEntity | cEntity * | 0x178 |
| cNetworkTileRegion.pNetworkManager | cNetworkManager * | 0x164 |
| cNetworkTileRegion.pMapComponent | MapComponent * | 0x170 |
| cPendingConnection.pServerListing | tServerListing * | 0x60 |
| cSteamPunchthrough.pPlugin | cSteamPunchthroughPlugin * | 0x38 |
| cShardManager.pShardBroadcast | cShardBroadcast * | 0xA4 |
| cAccountManager.pCommunication | cAccountCommunication * | 0x38 |
| cMasterServer.pRequest | cMasterServerRequest * | 0x40 |
| cMasterServer.pBroadcast | cMasterServerBroadcast * | 0x44 |
| cMasterServerBroadcast.pMasterServer | cMasterServer * | 0x10 |
| cMasterServerBroadcast.pListing | tServerListing * | 0x54 |
| cMasterServerRequest.pMasterServer | cMasterServer * | 0xC |
| cLuaNetworkVariable.pEntity | cEntity * | 0xC |
| GetURL.pHttpClient2 | HttpClient2 * | 0x4 |
| Replica3.pReplicaManager | ReplicaManager3 * | 0x30 |
| ReplicaManager3.pCurrentlyDeallocatingReplica | Replica3 * | 0x4C |
| NetworkIDObject.pParent | NetworkIDObject * | 0x10 |
| NetworkIDObject.pNextInstanceForNetworkIDManager | NetworkIDObject * | 0x14 |
| LastSerializationResult.pReplica | Replica3 * | 0x0 |
| LastSerializationResult.pLastSerializationResultBS | LastSerializationResultBS * | 0xC |
| SerializeParameters.pDestinationConnection | Connection_RM3 * | 0x130 |
| DeserializeParameters.pSourceConnection | Connection_RM3 * | 0x120 |

## 失败清单

无(SKIP_NEED_TYPE: 0 / FAIL_SPACE: 0 / FAIL_FIELD: 0)

## 抽查结果(19 struct, 全部 get_struct_layout 复核)

| struct | size(改前/改后) | 关键字段确认 |
|------|------|------|
| cNetworkManager | 5048 / 5048 | 12 字段全部变更为具体指针类型,名字保留 |
| cNetworkRPCManager | 17 / 17 | pSlotNames = char * * |
| cNetworkClientObject2 | 544 / 544 | pPlayerEntity = cEntity * |
| cNetworkTileRegion | 388 / 388 | pNetworkManager / pMapComponent |
| cPendingConnection | 106 / 106 | pServerListing = tServerListing * |
| cSteamPunchthrough | 70 / 70 | pPlugin = cSteamPunchthroughPlugin * |
| cShardManager | 168 / 168 | pShardBroadcast = cShardBroadcast * |
| cAccountManager | 80 / 80 | pCommunication = cAccountCommunication * |
| cMasterServer | 145 / 145 | pRequest / pBroadcast |
| cMasterServerBroadcast | 88 / 88 | pMasterServer / pListing |
| cMasterServerRequest | 16 / 16 | pMasterServer = cMasterServer * |
| cLuaNetworkVariable | 16 / 16 | pEntity = cEntity * |
| GetURL | 8 / 8 | pHttpClient2 = HttpClient2 * |
| Replica3 | 344 / 344 | pReplicaManager = ReplicaManager3 * |
| ReplicaManager3 | 1116 / 1116 | pCurrentlyDeallocatingReplica = Replica3 * |
| NetworkIDObject | 24 / 24 | pParent / pNextInstanceForNetworkIDManager |
| LastSerializationResult | 16 / 16 | pReplica / pLastSerializationResultBS |
| SerializeParameters | 328 / 328 | pDestinationConnection = Connection_RM3 * |
| DeserializeParameters | 292 / 292 | pSourceConnection = Connection_RM3 * |

结论:36 个「确定」字段全部成功回写;「推断/待定/跳过」未触碰。已 save_program。
