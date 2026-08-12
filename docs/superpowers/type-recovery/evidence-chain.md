# 证据链 — 逐类型三源交叉记录

> 二进制:`dontstarve_steam` (macOS i386, base 0x1000)
> 工具:ghidra-mcp (G) + idalib-mcp (I)
> 约定:每个字段至少一条「函数地址 + 指令/语句」来源;冲突已标 UNKNOWN

## Tier 0

### cSimulation (412B) — G struct + I ctor 0xf71d2 ✓

| 偏移 | 字段 | 来源 |
|---|---|---|
| 0x00 | pVtable_cGameEventListener | I ctor: `*this = &unk_35F54A+1012190` = 0x456728;G struct 同 |
| 0x1C | pVtable_cSystemEventListener | I ctor: `*(this+7) = &unk_35F57E+1012190` = 0x45675C |
| 0x04-0x18 | RbTree GameEvent 头 | I ctor 初始化 left/right 指向 &color (哨兵) |
| 0x20-0x34 | RbTree SysEvent 头 | 同上 |
| 0x38 | bPostUpdateTriggered | I ctor 尾部 `*(this+56) = 0` |
| 0x3C | flTimeScale | I ctor `*(this+15) = 1065353216` (1.0f) |
| 0x40 | pEntityManager | I ctor `*(this+16) = operator new(0x138); cEntityManager::cEntityManager` |
| 0x44 | nSimStep | I ctor `*(this+17) = 0` |
| 0x48-0x50 | cSimTime 子对象 | I ctor `cSimTime::cSimTime(this, this+72)` |
| 0x58 | pLuaState | I ctor `*(this+22) = 0` (两次置 0) |
| 0x5C | pGame | I ctor `*(this+23) = a3` |
| 0x6C | flTimeStep | I ctor `*(this+27) = 981668463` = 0x001f_0000? → 0.001f ✓ |
| 0x74 | UNKNOWN_0x74 | I ctor `*(this+29) = -1` |
| 0x88-0x90 | pVecQueuedSysEvents | I ctor `*(this+34/35/36) = 0` |
| 0x94 | mutexSysEvents | I ctor `Mutex::Mutex` @ 0x94;G struct 56B |
| 0xCC-0xD4 | pVecQueuedGameEvents | I ctor `*(this+51/52/53) = 0` |
| 0xD8 | mutexGameEvents | I ctor `Mutex::Mutex` |
| 0x110 | pMapHashedStringUint | I ctor 清零 [0x10..0x17] 槽 + 设置哨兵 @ +0xC/+0x10 |
| 0x128-0x158 | nRef* (12 int) | I ctor: `*(_OWORD*)&this[296] = xmmword_3B84F0` ×2 + `*(this+82/84/85/86) = -2` |
| 0x160 | pRgbAmbientColor | I ctor `*(this+88) = **dword_35975E` (White) |
| 0x164 | pRgbaColor2 | I ctor 字节置 0,0,0,0xFF |
| 0x170 | pBPWorld | I ctor `*(this+92) = operator new(0x34); cBPWorld::cBPWorld` |
| 0x174 | bAbortSim | I ctor `*(this+372) = 0` |
| 0x17C-0x184 | pVecUnknown17C | I ctor `*(this+95/96/97) = 0` |
| 0x188 | nGCThreshold | I ctor `*(this+98) = 0` |
| 0x18C | bSkipSim | I ctor `*(this+396) = 0` |
| 0x194 | bUseThreadedPhysics | I ctor `*(this+404) = 1` (gUseThreadedPhysics) |
| 0x198 | flProfilerTime | I ctor `*(this+102) = 0` |

vtable 槽解析:0x456728 → ~cSimulation(0xf7f34/0xf7f50)、HandleEvent(cGameEvent, 0xfd568)、RegisterLuaComponents(0x100e86)、SetDebugCameraTarget(0x100e88)、SetDebugCameraRotation(0x100e8a)、HandleEvent(SystemEvent, 0xfd3e2)、GetInput(0x100e8c)、DoReset(0x100e90)、DoUpdate(0x8e754)、DoPostUpdate(0x100e98)

### cGame (304B) — G struct ✓ (无独立 IDA ctor,构造内联于 cApplication::Startup)

| 偏移 | 字段 | 来源 |
|---|---|---|
| 0x20 | pSimulation | I cSimulation ctor 引用 `pGame->pSimulation` 的兄弟字段;G struct |
| 0x60 | pGameEventDispatcher | I cSimulation ctor: `*(v8+96)` 读 pGame->pGameEventDispatcher → RegisterListener |
| 0x128 | pSystemEventDispatcher | I cSimulation ctor: `*(v8+296)` = pGame+0x128 |
| 0x80-0x88 | pVecPrefabs | G struct (cPrefab 挂载点) |
| 其余 | G struct 基准 | 未经 I 抽查,低风险指针字段 |

### cDontStarveSettings (8B+) — I dtor 0xac50 + Get*Settings ✓

| 偏移 | 字段 | 来源 |
|---|---|---|
| 0x00 | pVtable | I dtor: `*thisa = &unk_45D9D8`;vtable @ 0x45d9d0 槽2/3 = ~D1/~D0 |
| 0x04 | MultiFileSettings | I dtor: `MultiFileSettings::~MultiFileSettings(this+4)`;Load: `MultiFileSettings::Load(this+4, ...)` |

MultiFileSettings: I dtor 0x2850bc 显示 std::_Rb_tree<std::string, pair<const string, SettingFile*>> 头 (header 16B + count @ +0x10);Load 0x28514a 显示 `SettingFile* = operator new(0x38)` + `std::map::operator[](this)` — map 内嵌于 this 头部。

SettingFile: I ctor 0x285844 → 56B (0x38): 两个 RBTree 头 (0x00-0x10, 0x14-0x24) + flags (0x28-0x2C) + std::string @ 0x34;ctor alloc 0x38 与 dtor 一致。注:name string @ 0x34 与 +0x30 有 4B 偏移出入,标 UNKNOWN_0x2C。

### cNetworkComponent (684B) — G struct ✓

G struct 基准;I ctor 0x5adec 未抽查(网络组件构造复杂,留 Tier 3 网络恢复时验证)。含 Replica3 基类 (0x10-0x168) + RakNet::BitStream (0x194-0x2A8)。

### cEntityComponent (16B) — G struct ✓

G struct 基准;pEntity @ 0x0C 由 cEntity::vec_components (0x44) 语义确认;bAwakeFlag @ 0x04。

### cEntityManager (309B) — G struct ✓

G struct 基准;I ctor 0xd2796 未逐字段抽查,关键衔接:`pSimulation` @ 0x0C (ctor 参数)、`pSpatialHash` @ 0xF8、`GetEntityByGUID` @ 0xd309a 供 EntityLuaProxy::CheckPointer 调用 (I 0xe17be: `cEntityManager::GetEntityByGUID(*(this+8), *(v2+64), *(this+2))`)。

### EntityLuaProxy (16B) — I ctor 0xe171c + CheckPointer 0xe17be ✓ (双工具一致)

| 偏移 | 字段 | 来源 |
|---|---|---|
| 0x00 | pEntity | G ctor: `*(int*)this = param_2`;CheckPointer: `*this = GetEntityByGUID(...)` |
| 0x04 | pSimulation | G ctor: `*(this+4) = *(param_2+0x40)` (entity->simulation) |
| 0x08 | guid | G ctor: `*(this+8) = *(param_2+4)` (entity->guid) |
| 0x0C | versionSnapshot | G ctor: `*(this+0xC) = *(iVar1+0x44)`;CheckPointer 比较 `*(v2+68) > *(this+12)` |

### cPrefab (52B) — I ctor 0xf5bf6 ✓

| 偏移 | 字段 | 来源 |
|---|---|---|
| 0x00 | nameHash (cHashedStringCSL) | I ctor: `cHashedStringCSL::Set(&v7, *this)` → `*(QWORD*)(this+4) = v7` (hash+cstr 到 +4?) 注:Ghidra 显示 `*(this+0)` 写;偏移 0x00/0x04 需复查 |
| 0x04 | UNKNOWN (a6) | I ctor `*(this+1) = a6` |
| 0x0C | prefabHash | I ctor `*(this+3) = cHashedString::mEmptyString` |
| 0x14 | name (std::string) | I ctor `std::string::string(this+16, a5)` |
| 0x28 | pGame | I ctor `*(this+9) = a3` |

注:cPrefab 偏移 0x00 vs 0x04 的 hash 归属有歧义 (IDA 用 `*(QWORD*)this+1` 写 8B,实际覆盖 +4..+12),标低置信,建议 Tier 1 复查。

### cHashedStringLookup (92B) — I ctor 0x284002 ✓

| 偏移 | 字段 | 来源 |
|---|---|---|
| 0x00 | pVtable | I ctor `*this = &unk_45BD80` |
| 0x04 | criticalSection | I ctor `CriticalSection::CriticalSection(this)` → Mutex (56B) |
| 0x3C | lookupVec | I ctor `std::vector<sLookup>::reserve(this+60, 30000)` |
| 0x48 | pStringPool | I ctor `operator new[](0x300000)` → `*(this+18)` |
| 0x4C | pStringPoolEnd | I ctor `*(this+19) = v2` |
| 0x50 | nStringPoolSize | I ctor `*(this+20) = 3145728` (0x300000) |

单例:`Util::cSingleton<cHashedStringLookup>::mInstance` @ 0x45d9c4。

### Mutex (56B) — I ctor 0x272f5c + dtor 0x2730a2 ✓

pthread_mutex_t (44B: __sig 4 + __opaque 40) + pthread_mutexattr_t (12B) = 56B。矛盾点解决:macOS i386 mutexattr 是 12B 不是 40B。CriticalSection = Mutex 别名 (0x26ffe6 → 0x27309c)。源码路径:`source/systemlib/posix/mutex.cpp`。

---

## 未验证 / 低置信

| 类型 | 项 | 原因 | 计划 |
|---|---|---|---|
| cPrefab | 0x00/0x04 hash 归属 | IDA 8B 写歧义 | Tier 1 复查 |
| cGame | 全部 | 构造内联,无独立 I 抽查 | Tier 2 通过 pSimulation 引用反查 |
| cEntityManager | 部分 | ctor 未逐字段 | Tier 2 组件恢复时验证 |
| cNetworkComponent | 内部 | 构造复杂 | Tier 3 网络恢复 |
| SettingFile | 0x2C 未知 | ctor 未置位 | 低优先 |

---

## Tier 3(2026-08-08, 5 分片并发恢复)

**全局前提**(分片间交叉证实):
- std::string = 4B 旧 ABI(refcounted)— Slice D/E 独立证实
- std::_Rb_tree 头 = 24B:pad@0, color@4, parent@8, left@0xC, right@0x10, count@0x14 — Slice E dtor 0x2850BC / Slice D map 自引用模式
- 事件公共基类 cGameEvent 8B(vptr@0 + type@4)— Slice C DispatchEvent 0xd810

**关键修正**:
| 项 | 新结论 | 证据链 |
|---|---|---|
| cPrefab | name@0x00, nameHash@0x08, vecAssets@0x14, pGame@0x24, vecDeps@0x28 | ctor 0xf5bf6 反汇编 + AddPrefab 0x13ffa + AddAsset 0xec20a + AddPrefDep 0xec160 + dtor 0xebfac |
| MultiFileSettings | 24B (std::map 头) | dtor 0x2850BC count@0x14;find end@+4 |
| cDontStarveSettings | 28B | dtor 0xAC50 MFS dtor(&this+4) |
| SettingFile | CSimpleIniTempl 包装 56B | ctor 0x285844 Ghidra disasm + IDA 双验证 |
| cInputEvent | 不存在,基类 = cGameEvent | DispatchEvent 0xd810 按 [event+4] 分派 |

**分片证据索引**(详细见各分片报告):
- `tier3-a-rendering.md` — 每类型 vtable/ctor/dtor 地址 + 字段证据
- `tier3-b-map.md` — cPrefab 完整证据链 + Map/Pathfinder 字段
- `tier3-c-input.md` — 事件 vtable 槽表 + 构造点反汇编地址
- `tier3-d-network.md` — std::string 4B 证明 + 容器判定规则
- `tier3-e-system.md` — RBTree 24B 证明 + SettingFile/MultiFileSettings 精化
