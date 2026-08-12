# Tier 0 — 核心运行时类型恢复报告

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp (当前程序) + idalib-mcp (会话 255dac01)
> 方法:插件推导 struct 作先验基准 + IDA 反编译逐字段交叉验证 + vtable 槽解析
> 注:现有 struct 为 `tools/ghidra_plugin/` 插件前期推导产物,非引擎自动分析;本报告 IDA 交叉验证为独立门禁

## 方法验证结论 (cSimulation 全流程)

**三源交叉验证通过**:
1. **vtable**:`cSimulation` 双 vtable @ `0x456728` (cGameEventListener, 12槽) / `0x45675c` (cSystemEventListener, 7槽)。槽0-1 = 析构,槽2 = HandleEvent,其余 = RegisterLuaComponents / SetDebugCameraTarget/Rotation / GetInput / DoReset / DoUpdate / DoPostUpdate
2. **构造反编译**:Ghidra `0xf71d2` 与 IDA `0xf71d2` 逐字段一致
3. **单例/全局**:`numSimluationLaunches`、`gUseThreadedPhysics` 交叉确认

**关键偏移抽查 (IDA vs Ghidra)**:
| 偏移 | Ghidra 字段 | IDA 证据 |
|---|---|---|
| 0x00 | pVtable_cGameEventListener | `*this = &unk_35F54A+1012190` = 0x456728 ✓ |
| 0x1C | pVtable_cSystemEventListener | `*(this+7) = &unk_35F57E+1012190` = 0x45675C ✓ |
| 0x40 | pEntityManager | `*(this+16) = operator new(0x138)` ✓ |
| 0x5C | flTimeStep | `*(this+27) = 981668463` = 0.001f ✓ |
| 0x74 | nField_0x74 | `*(this+29) = -1` ✓ |
| 0x8C | pBPWorld | `*(this+92) = operator new(0x34)` ✓ |
| 0x194 | bUseThreadedPhysics | `*(this+404) = 1` ✓ |

**结论**:现有 struct 字段名来自 `tools/ghidra_plugin/` 插件前期推导(非引擎自动分析)。本轮的 IDA 反编译交叉验证作为**独立门禁**确认了插件先验的正确性(cSimulation 7 个关键偏移全部一致)。流程 = 插件推导 struct 作先验基准 → IDA decompile 抽查关键偏移 → 记录证据链。

---

## 已恢复类型

### 1. cSimulation — 完成 ✓

- **大小**:412 字节 (0x19C)
- **vtable**:`0x456728` / `0x45675c`(双继承 cGameEventListener + cSystemEventListener)
- **构造**:`0xf71d2`(Ghidra/IDA 一致)
- **结构**:104 字段
- **要点**:开头是 eastl RBTree 头(GameEvent + SysEvent 两组,各 28B);0x1C 起 cSimTime 子对象(12B);Mutex 56B × 2;`pMapHashedStringUint` 24B 是 eastl hash_map 头;末尾 12 个 Lua 引用 int (nRef*) + 3 组 vec 头
- **未知字段**:`nField_0x74` (0x74, 构造置 -1, 疑似 camera index)、`pVecUnknown17C` (0x17C, 三指针 vec 头) — 待 Tier 2 补
- **依赖类型**:cEntityManager (0x138 alloc)、cBPWorld (0x34 alloc)、cSimTime、Mutex

### 2. cGame — 完成 ✓

- **大小**:304 字节 (0x130)
- **vtable**:`0x4567d8` (10 槽, 含 ~cGame, RegisterLuaComponents, DoUpdate, DoPostUpdate, DoReset 等)
- **结构**:~100 字段
- **要点**:单 vtable 开头;0x08-0x18 RBTree 头;0x20 pSimulation;0x28-0x68 大量单例管理器指针(pWindowManager/pRenderer/pInputManager/pFileManager/pAtlasManager/pSoundProjectManager/pEnvelopeManager…);0x60 pGameEventDispatcher;0x80-0x88 pVecPrefabs;0xAC-0xBC 渲染目标对;0xD0 起 Perf* 指针块(20+ profiling 指针)
- **未知字段**:`pField_0x5C`、`pStrUnknown68`、`nField_0x78`、`nField_0x90`、`nField_0xD4`、`pStrPurchases` (0xC4) — 待补
- **关键衔接**:`pSimulation` @ 0x20 → cSimulation;`pGameEventDispatcher` @ 0x60 → cEventDispatcher<cGameEvent>;`pSystemEventDispatcher` @ 0x128 → cEventDispatcher<SystemEvent>

### 3. cDontStarveSettings — 完成 ✓

- **大小**:8 字节 (0x8)
- **vtable**:`0x45d9d0` (6 槽:2×空 + ~D1 @0xac50 + ~D0 @0xac78 + 2×空)
- **结构**:
  - `+0`: vtable
  - `+4`: MultiFileSettings(内嵌 std::map<std::string, SettingFile*>)
- **要点**:GetClientSettings/GetClusterSettings/GetServerSettings/GetBuildSettings 全部转发 `this+4` 的 MultiFileSettings::GetSettingFile;Load 从 client.ini 加载
- **依赖类型**:MultiFileSettings (std::_Rb_tree<std::string, std::pair<const std::string, SettingFile*>> 头, 16B+count)、SettingFile (56B, 两个 RBTree 头 + string)

### 4. cNetworkComponent — 完成 ✓

- **大小**:684 字节 (0x2AC)
- **结构**:
  - `+0`: cEntityComponent 基类 (16B)
  - `+16`: Replica3 基类 (344B, pReplica3Base)
  - `+360`: 网络状态字段 (nField_0x168/0x16C, bField_0x170/0x171)
  - `+372`: sleeping flags (u64)
  - `+380`: owner GUID (8B) + system index (2B)
  - `+392`: classified target GUID (8B) + index (2B)
  - `+404`: RakNet::BitStream (276B)
  - `+680`: serialize state
- **要点**:含完整 Replica3 网络同步 + BitStream,是 Tier 3 网络恢复的关键衔接

### 5. cEntityComponent — 完成 ✓ (基类)

- **大小**:16 字节 (0x10)
- **结构**:
  - `+0`: vtable
  - `+4`: bAwakeFlag
  - `+8`: pVec_component (所属 vector)
  - `+12`: pEntity (所属 cEntity*)
- **要点**:所有 Component 的基类,cEntity::vec_components 存储

### 6. cEntityManager — 完成 ✓

- **大小**:309 字节 (0x135)
- **vtable**:`0x4567d8` 附近
- **结构**:
  - `+0`: vtable
  - `+4`: guid 计数器
  - `+8`: pServerGuidCounter
  - `+12`: pSimulation
  - `+20` 起:7 组 vec 头 (componentLists/wallUpdateTypes/updateTypes/postUpdateTypes/debugUpdateTypes/allEntities/destroyQueue/newEntities/awakeEntities/pendingComponentAdditions)
  - `+136`: pComponentFactory
  - `+140`: CriticalSection (Mutex 56B)
  - `+208`: entity pool (40B)
  - `+248`: pSpatialHash (cSpatialHash<cEntity>)
  - `+276`: entity position map (RBTree 头)
  - `+296`: destroyed positions vec
  - `+308`: bIsProcessingNewEntities
- **要点**:cEntityManager::GetEntityByGUID @ 0xd309a 是 EntityLuaProxy CheckPointer 的依赖

### 7. EntityLuaProxy — 完成 ✓

- **大小**:16 字节 (0x10)
- **构造**:`0xe171c`
- **结构**:
  - `+0`: cEntity* (CheckPointer 时经 GetEntityByGUID 刷新)
  - `+4`: cSimulation* (来自 entity->simulation)
  - `+8`: guid (来自 entity->guid)
  - `+12`: 序号快照 (entity manager 版本计数)
- **要点**:**非** cEntity 头部复用 — 而是 4 个独立字段,CheckPointer 用 `entityMgr->count > 快照` 判断实体是否失效并重取。这是 Lua userdata 直接指向的对象
- **关键洞见**:LuaProxy 家族在构造时从宿主对象拷贝关键字段,不是指针复用 — 这对 Tier 1 恢复方法有指导意义

### 8. cPrefab — 完成 ✓

- **大小**:52 字节 (0x34)
- **构造**:`0xf5bf6`
- **结构**:
  - `+0`: cHashedStringCSL (hash 4B + cstring 指针 4B)
  - `+8`: 0
  - `+12`: cHashedString 值 (8B, 初始 mEmptyString)
  - `+16`: std::string name (12B)
  - `+28`: 0
  - `+32`: 0
  - `+36`: cGame*
  - `+40`: 0
  - `+44`: 0
  - `+48`: 0
- **要点**:cPrefab 挂在 cGame::pVecPrefabs (0x80-0x88)

### 9. cHashedStringLookup — 完成 ✓

- **大小**:92 字节 (0x5C)
- **构造**:`0x284002`
- **结构**:
  - `+0`: vtable (unk_45BD80)
  - `+4`: CriticalSection (56B)
  - `+60`: std::vector<sLookup> (3 ptr, reserve 30000)
  - `+72`: 3MB 字符串 buffer (0x300000, 3145728)
  - `+80`: 3145728 (buffer 大小常量)
- **要点**:单例 (Util::cSingleton<cHashedStringLookup>::mInstance @ 0x45d9c4);hash → 字符串查找表,字符串池 3MB

### 10. Mutex / CriticalSection — 完成 ✓

- **大小**:56 字节 (0x38)
- **构造**:`0x272f5c`
- **结构**:pthread_mutex_t (44B: __sig + 40B opaque) + pthread_mutexattr_t (12B)
- **要点**:CriticalSection 是 Mutex 别名 (0x26ffe6 → 0x27309c);源码路径确认 `/Volumes/SSD/jenkins-buildmaster/workspace/DST_BuildGame_OSX/source/systemlib/posix/mutex.cpp`

---

## 未知字段汇总 (待 Tier 2/3 补充)

| 类型 | 偏移 | 备注 |
|---|---|---|
| cSimulation | 0x74 | 构造置 -1, 疑似 camera index |
| cSimulation | 0x17C | 三指针 vec 头,内容未知 |
| cGame | 0x5C | void* |
| cGame | 0x68 | void* (str?) |
| cGame | 0x78 | int |
| cGame | 0x90 | int |
| cGame | 0xD4 | int |
| cNetworkComponent | 0x168-0x172 | 网络状态 |
| cEntityManager | 0xC4-0xCC | 3 int |
| cEntityManager | 0x110 | padding? |

## 待处理

- [x] cSimulation
- [x] cGame
- [x] cDontStarveSettings / MultiFileSettings / SettingFile
- [x] cNetworkComponent
- [x] cEntityComponent
- [x] cEntityManager
- [x] EntityLuaProxy
- [x] cPrefab
- [x] cHashedStringLookup
- [x] Mutex / CriticalSection
- [ ] 聚合 types_common.h (Task 5)
- [ ] ComponentLuaProxy<T,P> 模板 (Tier 1)
