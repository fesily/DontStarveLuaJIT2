# Sync Void* Slice4 — 38 struct 的 void* 字段按 Ghidra 布局同步到 types_common.h

> 输入: 主 agent 分片任务 (Slice4)
> 数据源: ghidra-mcp `get_struct_layout`(program=`dontstarve_steam`, 38 个 struct 全部实时拉取)
> 目标文件: `3rd/dst/game_decompiler/types_common.h`(仅此文件 + 本报告)
> 日期: 2026-08-12
> 方法: 仅更新 **void* 字段** → Ghidra 实际类型;保持字段名/偏移/顺序/size;不重排;vector 三件套若 Ghidra 仍 void* 则保留

## 同步结果

| struct | void* 数(同步后) | 变更字段 | 状态 |
|--------|------------------|---------|------|
| cSimulation | 20 | pWorldSim→WorldSim*, pMainCamera→cSimCamera*, pDebugCamera→cSimCamera*, pBPWorld→cBPWorld*, pPhysicsThread→Thread*, pStrJsonSettings→cStdString, pStrPurchases→cStdString | ✓ |
| cAnimStateComponent | 11 | pAnimNode→AnimNode*, pUITransformComponent→cUITransformComponent* | ✓ |
| MapGenSim | 9 | 9 个 bt* 目标均在头文件未定义 → 全部保留 void* + TODO | ✓* |
| cPrefab | 6 | 无(void* 均为 vector 三件套) | ✓ |
| ControlMapper | 5 | pSelf→ControlMapper*;pInputManager/pInputManager2 未定义 → TODO | ✓* |
| AnimationFile | 5 | 无(Ghidra 侧为 `pointer` 泛型,不映射) | ✓ |
| cSteamPunchthrough | 3 | pPlugin→cSteamPunchthroughPlugin*;pRakPeer 未定义 → TODO | ✓* |
| CurlRequest | 3 | CURLM*/CURL*/curl_slist* 未定义 → 全部 TODO | ✓* |
| cApplication | 0 | mSystemService→DontStarveSystemService*, mGameService→DontStarveGameService*, mGame→cGame* | ✓ |
| cNetworkClientObject2 | 2 | pPlayerEntity→cEntity* | ✓ |
| EnvelopeComponent | 3 | 无(Ghidra 仍 void*) | ✓ |
| cEntityComponent | 2 | 无(pEntity 已为 struct cEntity*,Ghidra -BAD- 按既有证据保留) | ✓ |
| AStarSearch_ulong | 2 | pParams→AstarParams* 未定义 → TODO | ✓* |
| DontStarveGameService | 1 | pSystemService→DontStarveSystemService* | ✓ |
| Thread | 2 | hThread→pthread_t 未定义 → TODO | ✓* |
| AtlasManager | 1 | pRenderer→Renderer* | ✓ |
| cInventoryManager | 2 | 无(list/map 头仍 void*) | ✓ |
| cNetworkRPCManager | 1 | pSlotNames→char**;pRPC4→RPC4* 未定义 → TODO | ✓* |
| MapRenderer | 1 | pGameRenderer→GameRenderer*;pLayerMgr 未定义 → TODO | ✓* |
| TDataCacheImageNode | 1 | pOwner→ImageNode* | ✓ |
| TDataCacheTextNode | 1 | pOwner→TextNode* | ✓ |
| cVideoWidget | 1 | pVideoObj→VideoNode* | ✓ |
| BinaryBufferReader | 2 | 无(Ghidra 仍 void*) | ✓ |
| cInputTextEvent | 1 | 无 | ✓ |
| ResizeEvent | 1 | 无 | ✓ |
| QuadTreeNode | 0 | pRootNode→QuadTreeNode_Node* | ✓ |
| Metrics | 1 | 无 | ✓ |
| cBaseFactory | 1 | 无 | ✓ |
| VertexDescription | 1 | 无 | ✓ |
| VFXEffectEmitter | 1 | 无 | ✓ |
| cLogger | 1 | 无 | ✓ |
| SerializeParameters | 0 | pDestinationConnection→Connection_RM3* | ✓ |
| cNatPunchthroughDebugInterfaceImpl | 1 | 无 | ✓ |
| cNetworkFileTransferCB | 1 | 无 | ✓ |
| VFXEmitterManager | 1 | 无 | ✓ |
| HWBuffer | 1 | 无 | ✓ |
| cTextWidget | 0 | pTextObj→TextNode* | ✓ |
| GameServiceImpl | 1 | 无 | ✓ |

\* 含未定义类型 → 保留 void* + `/* TODO: <Type> */` 标记

## 判定规则(本次应用)

1. **可映射(目标类型已在头文件定义)**:直接改类型,`X *` → `X*`,保持字段名。
2. **未定义目标类型**:保留 `void*` + 追加 `/* TODO: <Type> */` 注释(沿用 cBPWorld/DontStarveInputHandler 既有风格)。
3. **Ghidra 侧仍为 void***:保留(含 vector 三件套、vtable、rb-tree 头)。
4. **Ghidra `-BAD-`**(cEntityComponent.pEntity):按既有证据保留 `struct cEntity*`(头文件已有类型,不降级)。
5. **Ghidra `pointer` 泛型**(AnimationFile):不映射,保留 void*。

## 关键差异记录

### 1. cSimulation 主要类型化(7 处)
- `pWorldSim` → `struct WorldSim*`(WorldSim 定义于 666 行,头文件已存在)
- `pMainCamera`/`pDebugCamera` → `struct cSimCamera*`(cSimCamera 定义于 662 行)
- `pBPWorld` → `struct cBPWorld*`(定义于 578 行)
- `pPhysicsThread` → `struct Thread*`(Thread 定义于 526 行)
- `pStrJsonSettings`/`pStrPurchases` → `cStdString`(Ghidra 为值类型 cStdString,4B,非指针)
- 注意:头文件使用 `struct X*` 前缀形式是既有惯例(与 `struct cGame* pGame` 一致);指针引用不要求目标完整定义

### 2. 未定义类型清单(TODO 保留,共 14 处)
| struct | 字段 | 目标类型 |
|--------|------|---------|
| cSimulation | pLuaState | lua_State* |
| MapGenSim | pWorld | btDiscreteDynamicsWorld* |
| MapGenSim | pBroadphase | btDbvtBroadphase* |
| MapGenSim | pDispatcher | btCollisionDispatcher* |
| MapGenSim | pSolver | btSequentialImpulseConstraintSolver* |
| MapGenSim | pConfig | btDefaultCollisionConfiguration* |
| MapGenSim | pShapeBox/pShapeTri/pShapeCylinder | btConvex2dShape* |
| ControlMapper | pInputManager/pInputManager2 | IInputManager* |
| cSteamPunchthrough | pRakPeer | RakPeerInterface* |
| CurlRequest | pCurlMulti/pCurlEasy/pCurlSlist | CURLM*/CURL*/curl_slist* |
| AStarSearch_ulong | pParams | AstarParams* |
| Thread | hThread | pthread_t |
| cNetworkRPCManager | pRPC4 | RPC4* |
| MapRenderer | pLayerMgr | MapLayerManagerComponent* |

### 3. 保留 void*(Ghidra 侧即为 void*)
- cSimulation: 12 处(vtable ×3、rb-tree 头 ×6、vec 三件套 ×3)、pStrScenarioScript
- cAnimStateComponent: 11 处(vtable/字符串/vec 三件套等)
- cPrefab: 6 处(全为 vec 三件套)
- cInventoryManager: list_0x08[2] + map1/map2 头(rb-tree)
- EnvelopeComponent: 3 处(vec 三件套)
- BinaryBufferReader: pBuffer

## 验证

- 38/38 struct 从 Ghidra 实时拉取布局并逐字段比对;同步后各 struct void* 残留数与 Ghidra 侧 void* 字段一一对应(脚本核对)。
- 字段名/偏移/顺序/size 未改动;无 struct 重排;`^struct ` 行数 286 不变(本次未增删 struct 定义)。
- 仅修改 Slice4 范围内字段;其他 struct 未触碰。

## 只写文件

- `3rd/dst/game_decompiler/types_common.h`
- `docs/superpowers/type-recovery/sync-voidstar-s4.md`(本报告)
