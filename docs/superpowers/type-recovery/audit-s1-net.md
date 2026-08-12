# Phase 0.5 Audit S1 — Network/RakNet void* 纠正表

> 输入: sync-s1-net.md (exists:true) + types_common.h + raknet-review*/remaining-f1-net.md/tier3-d-network.md
> 规则: 确定=语义明确且类型已在 types_common.h; 推断=语义明确但需建类型; 待定=无证据; 跳过=vector/list/vtable/rb-tree/pPad_/pField_
> 只读审计, 未写 Ghidra。scout 沙箱 EPERM, 主 agent 物化。

## cNetworkManager
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pStrServerName | 0x34 | void * | std::string* | 推断 (evidence: 字段名 pStr*; types_common.h 无 std::string 结构体) |
| pStrServerDescription | 0x78 | void * | std::string* | 推断 (同上) |
| pStrClanInfo | 0x7C | void * | std::string* | 推断 (同上) |
| pStrServerIntention | 0x80 | void * | std::string* | 推断 (同上) |
| pStrServerPassword | 0x84 | void * | std::string* | 推断 (同上) |
| pStrGameMode | 0x90 | void * | std::string* | 推断 (同上) |
| pStrServerTags | 0x94 | void * | std::string* | 推断 (同上) |
| pNetworkRPCManager | 0xCC | void * | cNetworkRPCManager* | 确定 (evidence: types_common.h + remaining-f1-net.md §3) |
| pNetworkVoiceManager | 0xD0 | void * | cNetworkVoiceManager* | 确定 (evidence: types_common.h + remaining-f1-net.md §5) |
| pNetworkReplicaManager | 0xD4 | void * | cNetworkReplicaManager* | 确定 (evidence: types_common.h + raknet-review-r1) |
| pSteamFriendsManager | 0xD8 | void * | cSteamFriendsManager* | 确定 (evidence: types_common.h + remaining-f1-net.md) |
| pNetworkIDManager | 0xDC | void * | NetworkIDManager* | 推断 (evidence: raknet-review-r1; 未建) |
| pRakPeer | 0xE0 | void * | RakPeerInterface* | 推断 (evidence: raknet-review-r4; 未建) |
| pDirectoryDeltaTransfer | 0xE4 | void * | DirectoryDeltaTransfer* | 推断 (evidence: 字段名语义; 未建) |
| pFileListTransfer | 0xE8 | void * | FileListTransfer* | 推断 (evidence: raknet-review-r5; 未建) |
| pIncrementalReadInterface | 0xEC | void * | IncrementalReadInterface* | 推断 (evidence: 字段名语义; 未建) |
| pAdditionalPlugin | 0xF0 | void * | PluginInterface2* | 推断 (evidence: 插件槽; PI2 已定义, 派生未钉死) |
| pMasterServer | 0xF8 | void * | cMasterServer* | 确定 (evidence: types_common.h + tier3-d) |
| pNatTraversal | 0xFC | void * | cNatTraversal* | 确定 (evidence: types_common.h + sync-s1) |
| pClientColourPicker | 0x104 | void * | cClientColourPicker* | 确定 (evidence: types_common.h + remaining-f1) |
| pSimulation | 0x110 | void * | cSimulation* | 确定 (evidence: types_common.h) |
| pReadyEvent | 0x114 | void * | ReadyEvent* | 推断 (evidence: RakNet::ReadyEvent; 未建) |
| pCheshireCat | 0x11C | void * | cNetworkManager::tCheshireCat* | 推断 (evidence: remaining-f1 §2 new(0x160); 未建) |
| pStrField_0x1A0 | 0x1A0 | void * | std::string* | 推断 (evidence: pStr* 命名) |
| pSnapshotManager | 0x1AC | void * | SnapshotManager* | 推断 (evidence: sync-s1 exists:false; 未建) |
| pStrField_0x1B0 | 0x1B0 | void * | std::string* | 推断 (evidence: pStr* 命名) |
| pStrField_0x1B4 | 0x1B4 | void * | std::string* | 推断 (evidence: pStr* 命名) |
| pSteamPunchthrough | 0x1B8 | void * | cSteamPunchthrough* | 确定 (evidence: types_common.h + remaining-f1 §12) |
| pStrField_0x1F8 | 0x1F8 | void * | std::string* | 推断 (evidence: pStr* 命名) |
| pServerListingData | 0x1FC | void * | cNetworkManager::ServerListingData* | 推断 (evidence: remaining-f1 §6; 未建嵌套) |
| pStrDisconnectReason | 0x200 | void * | std::string* | 推断 (evidence: pStr* 命名) |
| pStrPopupReason | 0x204 | void * | std::string* | 推断 (evidence: pStr* 命名) |
| pStrPopupDialog | 0x208 | void * | std::string* | 推断 (evidence: pStr* 命名) |
| pSteamRichPresence | 0x1364 | void * | cSteamRichPresence* | 确定 (evidence: types_common.h) |
| pDedicatedServerProcess1 | 0x13B0 | void * | cDedicatedServerProcess* | 确定 (evidence: types_common.h + remaining-f4) |
| pDedicatedServerProcess2 | 0x13B4 | void * | cDedicatedServerProcess* | 确定 (evidence: types_common.h 双进程槽) |

## cNetworkRPCManager
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pRPC4 | 0x0 | void * | RPC4* | 推断 (evidence: remaining-f1 §3 / raknet-r3; 未建 RPC4) |
| pSlotNames | 0x8 | void * | char** | 确定 (evidence: remaining-f1 §3 char*[29]) |

## cNetworkClientObject2
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pPlayerEntity | 0x178 | void * | cEntity* | 确定 (evidence: remaining-f1 §6; cEntity 已定义) |
| pNetStats | 0x208 | void * | uint8_t* | 推断 (evidence: remaining-f1 §6 new[](0x1E0)) |

## cNetworkTileRegion
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pNetworkManager | 0x164 | void * | cNetworkManager* | 确定 (evidence: remaining-f1 §4) |
| pTileGrid | 0x16C | void * | TileGrid* | 推断 (evidence: remaining-f1 §4; 未建) |
| pMapComponent | 0x170 | void * | MapComponent* | 确定 (evidence: remaining-f1 §4) |
| pTileData | 0x174 | void * | uint16_t* | 推断 (evidence: remaining-f1 §4 new[](0x200)) |
| pTileDataPtr | 0x178 | void * | uint16_t* | 推断 (evidence: remaining-f1 §4 切片指针) |

## cPendingConnection
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pServerListing | 0x60 | void * | tServerListing* | 确定 (evidence: remaining-f1 §8) |

## cSteamAccountCommunication
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pAuthTicketBuffer | 0x10C | void * | uint8_t* | 推断 (evidence: remaining-f1 §11 new[](0x800)) |

## cSteamPunchthrough
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pRakPeer | 0x8 | void * | RakPeerInterface* | 推断 (evidence: remaining-f1 §12; 未建) |
| pPlugin | 0x38 | void * | cSteamPunchthroughPlugin* | 确定 (evidence: remaining-f1 §12) |

## cShardManager
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pCheshireCat | 0x9C | void * | cShardManager::tCheshireCat* | 推断 (evidence: tier3-d §1; 未建) |
| pShardBroadcast | 0xA4 | void * | cShardBroadcast* | 确定 (evidence: tier3-d §1) |

## cAccountManager
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pCommunication | 0x38 | void * | cAccountCommunication* | 确定 (evidence: tier3-d §16) |

## cTwitchManager
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pCheshireCat | 0x4 | void * | cTwitchManager::tCheshireCat* | 推断 (evidence: remaining-f1 tCheshireCat 0x588; 未建) |

## cMasterServer
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pRequest | 0x40 | void * | cMasterServerRequest* | 确定 (evidence: types_common.h) |
| pBroadcast | 0x44 | void * | cMasterServerBroadcast* | 确定 (evidence: types_common.h) |

## cMasterServerBroadcast
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pMasterServer | 0x10 | void * | cMasterServer* | 确定 (evidence: types_common.h) |
| pListing | 0x54 | void * | tServerListing* | 确定 (evidence: remaining-f1 + types_common.h) |

## cMasterServerRequest
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pMasterServer | 0xC | void * | cMasterServer* | 确定 (evidence: types_common.h) |

## cLuaNetworkVariable
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pEntity | 0xC | void * | cEntity* | 确定 (evidence: types_common.h) |

## cNetworkLuaProxy
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pNetworkContext | 0x1C | void * | cSimulation* | 推断 (evidence: tier3-d §20 pSimulation 链) |

## CurlRequest
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pCurlMulti | 0x1C | void * | CURLM* | 推断 (evidence: tier3-d §8; 未建) |
| pCurlEasy | 0x20 | void * | CURL* | 推断 (evidence: tier3-d §8; 未建) |
| pCurlSlist | 0x24 | void * | curl_slist* | 推断 (evidence: tier3-d §8; 未建) |

## CurlRequestManager
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pClientThread | 0x4 | void * | ClientThread* | 推断 (evidence: tier3-d §9; 未建) |

## GetURL
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pHttpClient2 | 0x4 | void * | HttpClient2* | 确定 (evidence: tier3-d §10) |

## Replica3
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pReplicaManager | 0x30 | void * | ReplicaManager3* | 确定 (evidence: raknet-review-r1) |

## ReplicaManager3
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pCurrentlyDeallocatingReplica | 0x4C | void * | Replica3* | 确定 (evidence: raknet-review-r1) |

## PluginInterface2
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pRakPeerInterface | 0x4 | void * | RakPeerInterface* | 推断 (evidence: raknet-review-r5; 未建) |
| pTcpInterface | 0x8 | void * | TCPInterface* | 推断 (evidence: raknet-review-r5; 未建) |

## NetworkIDObject
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pNetworkIDManager | 0xC | void * | NetworkIDManager* | 推断 (evidence: raknet-review-r1; 未建) |
| pParent | 0x10 | void * | NetworkIDObject* | 确定 (evidence: raknet-review-r1) |
| pNextInstanceForNetworkIDManager | 0x14 | void * | NetworkIDObject* | 确定 (evidence: raknet-review-r1) |

## RakNetList
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pListArray | 0x0 | void * | void * | 待定 (模板元素类型随实例变化) |

## LastSerializationResult
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pReplica | 0x0 | void * | Replica3* | 确定 (evidence: raknet-review-r1) |
| pLastSerializationResultBS | 0xC | void * | LastSerializationResultBS* | 确定 (evidence: raknet-review-r1) |

## SerializeParameters
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pDestinationConnection | 0x130 | void * | Connection_RM3* | 确定 (evidence: raknet-review-r1) |

## DeserializeParameters
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pSourceConnection | 0x120 | void * | Connection_RM3* | 确定 (evidence: raknet-review-r1) |

## RM3World
| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pNetworkIDManager | 0x1C | void * | NetworkIDManager* | 推断 (evidence: raknet-review-r1; 未建) |

## 无 void* 字段的 exists:true 结构 (无需纠正)
cNetworkComponent, cNetworkConnection, cNetworkReplica, cNatTraversal, cShardBroadcast, cNetID2, tServerListing, MigrationInfo, BitStream, RakNetGUID, SystemAddress, PRO, LastSerializationResultBS

## 汇总
| 判定 | 数量 |
|------|------|
| 确定 | 36 |
| 推断 | 39 |
| 待定 | 1 |
| 跳过(容器/vtable/pad) | 50 |
| **void* 字段合计** | **126** |

### 需新建/补全类型 (推断项目标)
ClientThread*, CURL*, CURLM*, curl_slist*, cNetworkManager::ServerListingData*, cNetworkManager::tCheshireCat*, cShardManager::tCheshireCat*, cTwitchManager::tCheshireCat*, DirectoryDeltaTransfer*, FileListTransfer*, IncrementalReadInterface*, NetworkIDManager*, PluginInterface2*(AdditionalPlugin), RakPeerInterface*, ReadyEvent*, RPC4*, SnapshotManager*, std::string*, TCPInterface*, TileGrid*, uint8_t*/uint16_t*(buffers)
