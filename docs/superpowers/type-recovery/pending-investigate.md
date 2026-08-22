# Pending void* 字段调查报告

> 日期: 2026-08-10
> 程序: `dontstarve_steam` (macOS i386)
> 范围: 5 份 audit 表中 43 个「待定」void* 字段
> 方法: get_struct_layout + 反编译 ctor/dtor + 既有 tier/remaining 证据交叉
> 约束: Ghidra 只读,未改类型; scout 沙箱 EPERM 写盘,由 Main 物化

## 汇总

| 判定 | 数量 |
|------|------|
| 可确定 | **8** |
| 保持 void* | **35** |
| 需更多调查 | **0** |
| **合计** | **43** |

## 可确定字段清单 (8)

| Struct.field | off | 目标类型 |
|---|---|---|
| cSimulation.pStrJsonSettings | 0x168 | std::string (4B COW 内联) |
| cSimulation.pStrPurchases | 0x16c | std::string (4B COW 内联) |
| cGame.pStrInstanceSettings | 0x94 | std::string (4B COW 内联) |
| cGame.pStrPurchases | 0xc4 | std::string (4B COW 内联) |
| MapGenSim.pCollObjs | 0x20 | void** / btCollisionObject** |
| cPhysicsComponent.pPhysicsWorldSim | 0x24 | cBPWorld* |
| ControlMapper.pInputManager | 0x0 | IInputManager* |
| DontStarveSystemService.pCacheMap | 0xc | std::map<cHashedString, MemoryCache::CacheItem>* |

## 关键证据

- **cSimulation.pStrJsonSettings@0x168 / pStrPurchases@0x16c**: ctor@0xf71d2 `this->pStrJsonSettings = PTR__S_empty_rep_storage_00450020 + 0xc` — libstdc++ COW 空串 rep 数据指针。4B 内联 string,非 string*。
- **cGame.pStrInstanceSettings@0x94 / pStrPurchases@0xc4**: ctor@0xf3d2 同 COW 空串模式。
- **cPhysicsComponent.pPhysicsWorldSim@0x24**: dtor@0x67936 `*(pPhysicsWorldSim+0x14)` 取世界指针再 removeRigidBody;cBPWorld.pWorld@0x14 = btDiscreteDynamicsWorld* 完全吻合 → **cBPWorld***。
- **ControlMapper.pInputManager@0x0**: ctor@0x208c4 签名 `ControlMapper(Input::IInputManager*)`,`*(int*)this = param_2`,Assert "NULL != input" → **IInputManager***。
- **DontStarveSystemService.pCacheMap@0xc**: ctor@0x24116 `operator_new(0x18)` 初始化 map 头(left/right 自指) → std::map<cHashedString, MemoryCache::CacheItem>*。
- **MapGenSim.pCollObjs@0x20**: InitPhysics `btAlignedAlloc(n*4)`,ExitPhysics 逐元素 vtable+4 delete → void** 或 btCollisionObject**。

## 保持 void* 分类 (35)

| 类别 | 字段数 | 代表 |
|---|---|---|
| 模板/多形态 | 1 | RakNetList.pListArray |
| FastDelegate/回调槽 | 5 | WorldSim.pCallback*, FileOp*.pContext, pLuaCallTarget, pGlobal2 |
| 不透明库句柄 | 3 | pZipArchive, pZipFile, pSoundFEV |
| 原始缓冲/堆基址 | 7 | ParticleBuffer×5, BinaryBufferReader.pBuffer, Heap.pBase |
| list/树/容器节点 | 4 | ShardClient list×3, pSymbolExchangeTree |
| 缺类型名/无赋值 | 10 | pServerGuidCounter, pLunarBase, pPredictionHistory, pAnimBankResource, FileHandle.pM_pData, FileOpRequest.pData, pStateObj, pMappingStorage2, pGlobal(int 值槽) |
| TDataCache 布局冲突 | 5 | 五个 pOwner |

## 关键反编译锚点

| 地址 | 符号 | 用途 |
|---|---|---|
| 0xf71d2 | cSimulation::ctor | string empty_rep |
| 0xf3d2 | cGame::ctor | string empty_rep |
| 0x67936 | cPhysicsComponent::dtor | +0x14 → cBPWorld 证据 |
| 0x208c4 | ControlMapper::ctor | IInputManager* @0 |
| 0x24116 | DontStarveSystemService::ctor | map new(0x18) |
| 0x4ac0c | MapGenSim::ctor | pCollObjs |
| 0x26aad4 | ZipFileSystem::Mount | zip_open(不透明) |
| 0x27508c | ZipSaver::ctor | minizip zipOpen(不透明) |
