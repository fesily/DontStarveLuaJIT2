# Phase 0 Sync S1 — Network/RakNet Layout Dump

> program: `dontstarve_steam` (macOS i386)
> tool: ghidra-mcp `get_struct_layout` (read-only)
> shard: S1 (network/RakNet)
> note: list includes `cNetworkReplicaManager` twice; both occurrences recorded.

### cNetworkComponent
size: 684 (hex 0x2ac)
exists: true
layout:
       0 | cEntityComponent             | base_cEntityComponent
      16 | Replica3                     | replica3
     360 | int                          | nField_0x168
     364 | int                          | nField_0x16C
     368 | byte                         | bField_0x170
     369 | byte                         | bField_0x171
     370 | byte[2]                      | pPad_0x172
     372 | uint                         | dwSleepingFlagsLower
     376 | uint                         | dwSleepingFlagsUpper
     380 | byte[8]                      | pMOwnerGUID
     388 | ushort                       | wMOwnerSystemIndex
     390 | byte[2]                      | pPad_0x186
     392 | byte[8]                      | pMClassifiedTargetGUID
     400 | ushort                       | wMClassifiedTargetIndex
     402 | byte[2]                      | pPad_0x192
     404 | BitStream                    | bitStream
     680 | int                          | nSerializeState

### cNetworkManager
size: 5048 (hex 0x13b8)
exists: true
layout:
       0 | void *                       | pVtable
       4 | void *                       | pIface1_vtable
       8 | int                          | nIface1_field1
      12 | int                          | nIface1_field2
      16 | byte                         | bIface1_flag
      17 | byte                         | bPad_11
      18 | byte                         | bPad_12
      19 | byte                         | bPad_13
      20 | void *                       | pIface2_vtable
      24 | int                          | nIface2_field1
      28 | int                          | nIface2_field2
      32 | byte                         | bIface2_flag
      33 | byte                         | bPad_21
      34 | byte                         | bPad_22
      35 | byte                         | bPad_23
      36 | void *                       | pIface3_vtable
      40 | int                          | nIface3_field1
      44 | int                          | nIface3_field2
      48 | byte                         | bIface3_flag
      49 | byte                         | bPad_31
      50 | byte                         | bPad_32
      51 | byte                         | bPad_33
      52 | void *                       | pStrServerName
      56 | int                          | nNetworkState
      60 | byte                         | bField_0x3C
      61 | byte                         | bPad_3D
      62 | byte                         | bPad_3E
      63 | byte                         | bPad_3F
      64 | byte[40]                     | pDequeRakNetGUID
     104 | int                          | nTickRate
     108 | int                          | nMaxPlayers
     112 | int                          | nField_0x70
     116 | int                          | nField_0x74
     120 | void *                       | pStrServerDescription
     124 | void *                       | pStrClanInfo
     128 | void *                       | pStrServerIntention
     132 | void *                       | pStrServerPassword
     136 | ushort                       | wServerPort
     138 | ushort                       | wAuthPort
     140 | ushort                       | wMasterPort
     142 | ushort                       | wField_0x8E
     144 | void *                       | pStrGameMode
     148 | void *                       | pStrServerTags
     152 | int                          | nField_0x98
     156 | byte[36]                     | pNetID
     192 | int                          | nField_0xC0
     196 | int                          | nField_0xC4
     200 | byte                         | bField_0xC8
     201 | byte                         | bIsLANOnly
     202 | byte                         | bPad_CA
     203 | byte                         | bPad_CB
     204 | void *                       | pNetworkRPCManager
     208 | void *                       | pNetworkVoiceManager
     212 | void *                       | pNetworkReplicaManager
     216 | void *                       | pSteamFriendsManager
     220 | void *                       | pNetworkIDManager
     224 | void *                       | pRakPeer
     228 | void *                       | pDirectoryDeltaTransfer
     232 | void *                       | pFileListTransfer
     236 | void *                       | pIncrementalReadInterface
     240 | void *                       | pAdditionalPlugin
     244 | int                          | nField_0xF4
     248 | void *                       | pMasterServer
     252 | void *                       | pNatTraversal
     256 | int                          | nRakString
     260 | void *                       | pClientColourPicker
     264 | byte                         | bField_0x108
     265 | byte                         | bIsServer
     266 | byte                         | bServerStarted
     267 | byte                         | bIsOnline
     268 | byte                         | bPeerCreated
     269 | byte                         | bPad_10D
     270 | byte                         | bPad_10E
     271 | byte                         | bPad_10F
     272 | void *                       | pSimulation
     276 | void *                       | pReadyEvent
     280 | ushort                       | wField_0x118
     282 | byte                         | bPad_11A
     283 | byte                         | bPad_11B
     284 | void *                       | pCheshireCat
     288 | byte[116]                    | pPendingConnection
     404 | byte[8]                      | pTimer1
     412 | byte                         | bField_0x19C
     413 | byte                         | bField_0x19D
     414 | byte                         | bPad_19E
     415 | byte                         | bPad_19F
     416 | void *                       | pStrField_0x1A0
     420 | byte[8]                      | pTimer2
     428 | void *                       | pSnapshotManager
     432 | void *                       | pStrField_0x1B0
     436 | void *                       | pStrField_0x1B4
     440 | void *                       | pSteamPunchthrough
     444 | void *                       | pVecPermissions1_begin
     448 | void *                       | pVecPermissions1_end
     452 | void *                       | pVecPermissions1_cap
     456 | void *                       | pVecPermissions2_begin
     460 | void *                       | pVecPermissions2_end
     464 | void *                       | pVecPermissions2_cap
     468 | void *                       | pVecStrings_begin
     472 | void *                       | pVecStrings_end
     476 | void *                       | pVecStrings_cap
     480 | void *                       | pListTimedBan_next
     484 | void *                       | pListTimedBan_prev
     488 | int                          | nListTimedBan_count
     492 | byte                         | bField_0x1EC
     493 | byte                         | bPad_1ED
     494 | byte                         | bPad_1EE
     495 | byte                         | bPad_1EF
     496 | void *                       | pListServerModInfo_next
     500 | void *                       | pListServerModInfo_prev
     504 | void *                       | pStrField_0x1F8
     508 | void *                       | pServerListingData
     512 | void *                       | pStrDisconnectReason
     516 | void *                       | pStrPopupReason
     520 | void *                       | pStrPopupDialog
     524 | byte[8]                      | pTimer3
     532 | byte[220]                    | pConsoleInput
     752 | byte[8]                      | pTimer4
     760 | int                          | nField_0x2F8
     764 | void *                       | pUnknown2FC
     768 | byte[4180]                   | pLoggerImpl
    4948 | void *                       | pListStrings_next
    4952 | void *                       | pListStrings_prev
    4956 | byte                         | bField_0x135C
    4957 | byte                         | bField_0x135D
    4958 | byte                         | bPad_135E
    4959 | byte                         | bPad_135F
    4960 | int                          | nField_0x1360
    4964 | void *                       | pSteamRichPresence
    4968 | byte[72]                     | pMigrationInfo
    5040 | void *                       | pDedicatedServerProcess1
    5044 | void *                       | pDedicatedServerProcess2

### cNetworkConnection
size: 676 (hex 0x2a4)
exists: true
layout:
       0 | Connection_RM3               | base
     672 | int                          | nField_0x2A0

### cNetworkReplica
size: 354 (hex 0x162)
exists: true
layout:
       0 | Replica3                     | base
     344 | int                          | nField_0x158
     348 | int                          | nField_0x15C
     352 | byte                         | bField_0x160
     353 | byte                         | bRegistered

### cNetworkReplicaManager
size: 5752 (hex 0x1678)
exists: true
layout:
       0 | ReplicaManager3              | base
    1116 | int                          | nField_0x45C
    1120 | int                          | nField_0x460
    1124 | ushort                       | wAutoSerializePerTicksState
    1126 | byte[2]                      | p_pad
    1128 | int                          | nFrameCounter
    1132 | byte[1536]                   | pAwakeState
    2668 | byte[1536]                   | pAsleepState
    4204 | byte[1536]                   | pConstructedState
    5740 | void *                       | pVecReplicas_begin
    5744 | void *                       | pVecReplicas_end
    5748 | void *                       | pVecReplicas_cap

### cNetworkRPCManager
size: 17 (hex 0x11)
exists: true
layout:
       0 | void *                       | pRPC4
       4 | BitStream *                  | (unnamed)
       8 | void *                       | pSlotNames
      12 | int                          | nField_0x0C
      16 | byte                         | bField_0x10

### cNetworkVoiceManager
size: 20 (hex 0x14)
exists: true
layout:
       0 | void *                       | pVtable
       4 | BitStream *                  | pBitStream
       8 | byte                         | bEnabled
      12 | byte[8]                      | pM_mutedPlayers

### cNetworkClientObject2
size: 544 (hex 0x220)
exists: true
layout:
       0 | cNetworkReplica              | base
     356 | byte[12]                     | pM_rakNetGUID
     368 | uint[2]                      | pConnectionMask
     376 | void *                       | pPlayerEntity
     440 | byte[4]                      | pColour
     444 | byte[60]                     | pUNKNOWN_0x1BC
     508 | Timer                        | Timer
     516 | byte                         | bField_0x204
     520 | void *                       | pNetStats
     524 | void *                       | pField_0x20C
     528 | byte                         | bField_0x210
     529 | byte                         | bField_0x211
     530 | byte                         | bFlags_0x212
     531 | int                          | nField_0x213
     535 | ushort                       | wField_0x217
     540 | int                          | nField_0x21C

### cNetworkTileRegion
size: 388 (hex 0x184)
exists: true
layout:
       0 | cNetworkReplica              | base
     356 | void *                       | pNetworkManager
     360 | int                          | nRegionIndex
     364 | void *                       | pTileGrid
     368 | void *                       | pMapComponent
     372 | void *                       | pTileData
     376 | void *                       | pTileDataPtr
     384 | int                          | nField_0x180

### cNetworkFileTransferCB
size: 4 (hex 0x4)
exists: true
layout:
       0 | void *                       | pVtable

### cPendingConnection
size: 106 (hex 0x6a)
exists: true
layout:
       0 | int                          | nEState
       4 | byte                         | bIsDedicated
       8 | byte[4]                      | pM_ip
      12 | ushort                       | wPort
      16 | byte[12]                     | pRakNetGUID
      28 | byte[4]                      | pM_token
      32 | cNetID2                      | m_netId
      76 | byte                         | bHasToken
      84 | Timer                        | Timer
      96 | void *                       | pServerListing
     100 | byte[4]                      | pM_pingIP
     104 | ushort                       | wPingPort

### cNatTraversal
size: 408 (hex 0x198)
exists: true
layout:
       0 | byte[400]                    | pNatPunchthroughClient
     400 | byte[4]                      | pDebugInterface
     404 | int                          | nField_0x194

### cNatPunchthroughDebugInterfaceImpl
size: 4 (hex 0x4)
exists: true
layout:
       0 | void *                       | pVtable

### cSteamAccountCommunication
size: 284 (hex 0x11c)
exists: true
layout:
       0 | cAccountCommunication        | base
     196 | byte[24]                     | pCcallback1
     220 | byte[24]                     | pCcallback2
     244 | byte[24]                     | pCcallback3
     268 | void *                       | pAuthTicketBuffer
     272 | uint                         | dwAuthTicket
     276 | int                          | nTicketBufferSize
     280 | int                          | nField_0x118

### cSteamPunchthrough
size: 70 (hex 0x46)
exists: true
layout:
       0 | void *                       | pVtable
       4 | int                          | nCallbackId
       8 | void *                       | pRakPeer
      12 | byte[32]                     | pCcallResult
      44 | void *                       | pField_0x2C
      48 | int                          | nField_0x30
      52 | int                          | nField_0x34
      56 | void *                       | pPlugin
      61 | byte                         | bIsSteamGameServer
      62 | byte                         | bField_0x3E
      64 | int                          | nField_0x40
      68 | ushort                       | wField_0x44

### cSteamPunchthroughPlugin
size: 196 (hex 0xc4)
exists: true
layout:
       0 | void *                       | pVtable
       4 | byte[12]                     | pPluginInterface2
      16 | byte[24]                     | pCcallback1
      40 | byte[24]                     | pCcallback2
      64 | byte[24]                     | pM_addressToSteamID
      88 | byte[24]                     | pM_steamIDToAddress
     112 | byte[24]                     | pM_idleTimers
     136 | int                          | nField_0x88
     140 | int                          | nField_0x8C
     144 | int                          | nField_0x90
     148 | byte[24]                     | pM_timers2
     172 | byte[24]                     | pM_timers3

### cSteamFriendsManager
size: 29 (hex 0x1d)
exists: true
layout:
       0 | void *                       | pVtable
       4 | byte[8]                      | pM_friends
      12 | byte[8]                      | pM_clans
      20 | byte[8]                      | pM_clanMembers
      28 | byte                         | bField_0x1C

### cSteamRichPresence
size: 83 (hex 0x53)
exists: true
layout:
       0 | void *                       | pVtable
       4 | byte[24]                     | pM_presence
      28 | byte                         | bField_0x1C
      32 | cNetID2                      | m_serverNetId
      76 | byte[4]                      | pM_connectString
      82 | byte                         | bField_0x52

### tCheshireCat
exists: false

### cShardManager
size: 168 (hex 0xa8)
exists: true
layout:
       0 | byte[40]                     | pField_0x00
      40 | byte[24]                     | pM_shardPlayers
      64 | int                          | nField_0x40
      68 | byte[24]                     | pM_incomingMigrations
      92 | byte                         | bField_0x5C
      96 | byte[24]                     | pM_restartMigrations
     120 | float                        | flReconnectInterval
     124 | Timer                        | Timer_1
     132 | int                          | nField_0x84
     136 | Timer                        | Timer_2
     144 | void *                       | pM_strList_next
     148 | void *                       | pM_strList_prev
     152 | byte                         | bField_0x98
     153 | byte                         | bField_0x99
     156 | void *                       | pCheshireCat
     160 | void *                       | pField_0xA0
     164 | void *                       | pShardBroadcast

### cShardBroadcast
size: 4 (hex 0x4)
exists: true
layout:
       0 | byte[4]                      | pStr_0x00

### cAccountManager
size: 80 (hex 0x50)
exists: true
layout:
       0 | void *                       | pVtable
       4 | byte                         | bField_0x04
       8 | byte[4]                      | pStr_0x08
      12 | byte[16]                     | pTAuthenticated
      28 | byte[4]                      | pM_authToken
      32 | byte[4]                      | pM_username
      36 | byte[4]                      | pStr_0x24
      40 | byte[4]                      | pStr_0x28
      44 | byte[4]                      | pStr_0x2C
      48 | int                          | nField_0x30
      52 | byte[4]                      | pStr_0x34
      56 | void *                       | pCommunication
      60 | int                          | nField_0x3C
      64 | byte                         | bField_0x40
      65 | byte[3]                      | pPad_0x41
      68 | byte[4]                      | pStr_0x44
      72 | byte[4]                      | pStr_0x48
      76 | byte[4]                      | pM_offlineUserId

### cTwitchManager
size: 40 (hex 0x28)
exists: true
layout:
       0 | void *                       | pVtable
       4 | void *                       | pCheshireCat
       8 | int                          | nTVInitialized
      12 | Timer                        | Timer
      20 | byte                         | bDeferredInit
      24 | byte[4]                      | pM_username
      28 | byte                         | bField_0x1C
      32 | int                          | nField_0x20
      36 | byte[4]                      | pM_channelName

### cMasterServer
size: 145 (hex 0x91)
exists: true
layout:
       0 | void *                       | pList_next
       4 | void *                       | pList_prev
       8 | Timer                        | timer_0x08
      16 | byte[40]                     | pDeque_0x10
      56 | Timer                        | timer_0x38
      64 | void *                       | pRequest
      68 | void *                       | pBroadcast
      72 | Mutex                        | Mutex_0x48
     128 | int                          | nField_0x80
     132 | int                          | nField_0x84
     136 | int                          | nField_0x88
     140 | int                          | nField_0x8C
     144 | byte                         | bField_0x90

### cMasterServerBroadcast
size: 88 (hex 0x58)
exists: true
layout:
       0 | byte                         | bField_0x00
       4 | byte[4]                      | pM_strServerName
       8 | int                          | nField_0x08
      12 | byte[4]                      | pM_strPassword
      16 | void *                       | pMasterServer
      20 | Timer                        | m_timer
      28 | Mutex                        | m_mutex
      84 | void *                       | pListing

### cMasterServerRequest
size: 16 (hex 0x10)
exists: true
layout:
       0 | void *                       | pVtable
       4 | byte                         | bField_0x04
       8 | byte[4]                      | pM_strURL
      12 | void *                       | pMasterServer

### cNetID2
size: 44 (hex 0x2c)
exists: true
layout:
       0 | int                          | nField_0x00
       4 | int                          | nField_0x04
       8 | int                          | nField_0x08
      12 | int                          | nField_0x0C
      16 | int                          | nField_0x10
      20 | int                          | nField_0x14
      24 | int                          | nField_0x18
      28 | int                          | nField_0x1C
      32 | int                          | nField_0x20
      36 | int                          | nField_0x24
      40 | int                          | nField_0x28

### cPendingContact
exists: false

### cPendingState
exists: false

### SnapshotManager
exists: false

### tServerListing
size: 266 (hex 0x10a)
exists: true
layout:
       0 | byte[52]                     | pStrs
      52 | byte[8]                      | pM_mods
      60 | ushort                       | wField_0x3C
      62 | ushort                       | wField_0x3E
      64 | ushort                       | wField_0x40
      68 | int                          | nField_0x44
      72 | int                          | nField_0x48
      76 | int                          | nField_0x4C
      80 | int                          | nField_0x50
      84 | cNetID2                      | netId
     128 | cNetID2                      | netId2
     172 | int                          | nField_0xAC
     176 | byte                         | bField_0xB0
     177 | byte                         | bField_0xB1
     178 | int                          | nField_0xB2
     184 | cNetID2                      | netId3
     228 | byte[8]                      | pGuid
     236 | int                          | nField_0xEC
     240 | int                          | nField_0xF0
     244 | int                          | nField_0xF4
     248 | byte[4]                      | pStr_0xF8
     252 | int                          | nField_0xFC
     256 | byte                         | bField_0x100
     260 | byte[4]                      | pStr_0x104
     264 | ushort                       | wField_0x108

### tServerModInfo
exists: false

### cPlayerListingData
exists: false

### cLuaNetworkVariable
size: 16 (hex 0x10)
exists: true
layout:
       0 | void *                       | pVtable
       4 | byte                         | bField_0x04
       8 | byte[4]                      | pM_strName
      12 | void *                       | pEntity

### cLuaNetworkVariableType
exists: false

### cNetworkLuaProxy
size: 32 (hex 0x20)
exists: true
layout:
       0 | void *                       | pVtable
       4 | int                          | nField_0x04
       8 | byte[20]                     | pMap_like_0x08
      28 | void *                       | pNetworkContext

### LuaHttpQuery
size: 32 (hex 0x20)
exists: true
layout:
       0 | void *                       | pVtable
       4 | byte[20]                     | pM_requests
      24 | uint                         | dwM_pendingCount
      28 | ulong                        | dwM_requestCounter

### CurlRequest
size: 54 (hex 0x36)
exists: true
layout:
       0 | uint                         | dwM_id
       4 | byte[4]                      | pM_url
       8 | byte[4]                      | pM_postData
      12 | uint[2]                      | pM_authToken
      20 | uint                         | dwField_0x14
      24 | ushort                       | wField_0x18
      28 | void *                       | pCurlMulti
      32 | void *                       | pCurlEasy
      36 | void *                       | pCurlSlist
      40 | ushort                       | wField_0x28
      42 | byte                         | bField_0x2A
      44 | byte[4]                      | pM_response
      48 | uint                         | dwField_0x30
      52 | ushort                       | wField_0x34

### CurlRequestManager
size: 8 (hex 0x8)
exists: true
layout:
       0 | void *                       | pVtable
       4 | void *                       | pClientThread

### GetURL
size: 8 (hex 0x8)
exists: true
layout:
       0 | void *                       | pVtable
       4 | void *                       | pHttpClient2

### MigrationInfo
size: 72 (hex 0x48)
exists: true
layout:
       0 | int                          | nField_0x00
       4 | byte[4]                      | pM_strTarget
       8 | ushort                       | wField_0x08
      12 | byte[4]                      | pM_strSteamId
      16 | byte[8]                      | pM_netId
      24 | int                          | nField_0x18
      28 | cNetID2                      | m_targetNetId

### BitStream
size: 276 (hex 0x114)
exists: true
layout:
       0 | uint                         | dwNumberOfBitsUsed
       4 | uint                         | dwNumberOfBitsAllocated
       8 | uint                         | dwReadOffset
      12 | byte *                       | pData
      16 | bool                         | fCopyData
      17 | byte[256]                    | pStackData
     273 | byte[3]                      | p_pad

### Replica3
size: 344 (hex 0x158)
exists: true
layout:
       0 | NetworkIDObject              | base
      24 | RakNetGUID                   | creatingSystemGUID
      36 | RakNetGUID                   | deletingSystemGUID
      48 | void *                       | pReplicaManager
      52 | LastSerializationResultBS    | lastSentSerialization
     332 | bool                         | fForceSendUntilNextUpdate
     333 | byte[3]                      | p_pad
     336 | LastSerializationResult *    | pLsr
     340 | uint                         | dwReferenceIndex

### Connection_RM3
size: 672 (hex 0x2a0)
exists: true
layout:
       0 | void *                       | pVtable
       4 | bool                         | fIsValidated
       5 | bool                         | fIsFirstConstruction
       6 | byte[2]                      | p_pad0
       8 | SystemAddress                | systemAddress
      28 | RakNetGUID                   | guid
      40 | RakNetList                   | constructedReplicaList
      52 | RakNetList                   | queryToConstructReplicaList
      64 | RakNetList                   | queryToSerializeReplicaList
      76 | RakNetList                   | queryToDestructReplicaList
      88 | RakNetList                   | constructedReplicasCulled
     100 | RakNetList                   | destroyedReplicasCulled
     112 | bool                         | fGotDownloadComplete
     113 | byte[3]                      | p_pad1
     116 | BitStream                    | bitStream1
     392 | BitStream                    | bitStream2
     668 | int                          | nUNKNOWN_0x29C

### ReplicaManager3
size: 1116 (hex 0x45c)
exists: true
layout:
       0 | PluginInterface2             | base
      12 | PRO                          | defaultSendParameters
      28 | ulonglong                    | qwUNKNOWN_0x1C
      36 | ulonglong                    | qwUNKNOWN_0x24
      44 | ulonglong                    | qwUNKNOWN_0x2C
      52 | uint                         | dwUNKNOWN_0x34
      56 | ulonglong                    | qwAutoSerializeInterval
      64 | ulonglong                    | qwLastAutoSerializeOccurance
      72 | bool                         | fAutoCreateConnections
      73 | bool                         | fAutoDestroyConnections
      74 | byte[2]                      | p_pad
      76 | void *                       | pCurrentlyDeallocatingReplica
      80 | uint                         | dwNextReferenceIndex
      84 | void *[255]                  | pWorldsArray
    1104 | RakNetList                   | worldsList

### cNetworkReplicaManager
size: 5752 (hex 0x1678)
exists: true
layout: (duplicate list entry — same fields as earlier section)

### RakNetGUID
size: 12 (hex 0xc)
exists: true
layout:
       0 | ulonglong                    | qwG
       8 | ushort                       | wSystemIndex
      10 | byte[2]                      | p_pad

### SystemAddress
size: 20 (hex 0x14)
exists: true
layout:
       0 | byte[16]                     | pAddr4
      16 | ushort                       | wDebugPort
      18 | ushort                       | wSystemIndex

### PRO
size: 16 (hex 0x10)
exists: true
layout:
       0 | int                          | nPriority
       4 | int                          | nReliability
       8 | char                         | cOrderingChannel
       9 | byte[3]                      | p_pad
      12 | uint                         | dwSendReceipt

### PluginInterface2
size: 12 (hex 0xc)
exists: true
layout:
       0 | void *                       | pVtable
       4 | void *                       | pRakPeerInterface
       8 | void *                       | pTcpInterface

### NetworkIDObject
size: 24 (hex 0x18)
exists: true
layout:
       0 | void *                       | pVtable
       4 | ulonglong                    | qwNetworkID
      12 | void *                       | pNetworkIDManager
      16 | void *                       | pParent
      20 | void *                       | pNextInstanceForNetworkIDManager

### RakNetList
size: 12 (hex 0xc)
exists: true
layout:
       0 | void *                       | pListArray
       4 | uint                         | dwList_size
       8 | uint                         | dwAllocation_size

### LastSerializationResult
size: 16 (hex 0x10)
exists: true
layout:
       0 | void *                       | pReplica
       4 | ulonglong                    | qwWhenLastSerialized
      12 | void *                       | pLastSerializationResultBS

### LastSerializationResultBS
size: 280 (hex 0x118)
exists: true
layout:
       0 | BitStream                    | bitStream
     276 | bool                         | fIndicesToSend
     277 | byte[3]                      | p_pad

### SerializeParameters
size: 328 (hex 0x148)
exists: true
layout:
       0 | BitStream                    | outputBitstream
     276 | BitStream *                  | pLastSentBitstream
     280 | ulonglong                    | qwMessageTimestamp
     288 | PRO                          | pro
     304 | void *                       | pDestinationConnection
     308 | uint                         | dwBitsWrittenSoFar
     312 | ulonglong                    | qwWhenLastSerialized
     320 | ulonglong                    | qwCurTime

### DeserializeParameters
size: 292 (hex 0x124)
exists: true
layout:
       0 | BitStream                    | serializationBitstream
     276 | bool                         | fBitstreamWrittenTo
     277 | byte[3]                      | p_pad
     280 | ulonglong                    | qwTimeStamp
     288 | void *                       | pSourceConnection

### RM3World
size: 32 (hex 0x20)
exists: true
layout:
       0 | RakNetList                   | connectionList
      12 | RakNetList                   | userReplicaList
      24 | byte                         | bWorldId
      25 | byte[3]                      | p_pad
      28 | void *                       | pNetworkIDManager

---

## Summary

- processed (list items): 57
- unique names: 49
- exists: 50
- missing/placeholder (size=1 or not found): 7
- missing names: tCheshireCat, cPendingContact, cPendingState, SnapshotManager, tServerModInfo, cPlayerListingData, cLuaNetworkVariableType
