# Ghidra 回写记录 (Tier 0)

> 日期:2026-08-08
> 目标程序:`dontstarve_steam` (i386, base 0x1000)
> 方法:`create_struct`/`add_struct_field`/`modify_struct_field`/`delete_data_type` + `get_struct_layout` 验证

## 回写汇总

| 类型 | 状态 | 大小 | 说明 |
|---|---|---|---|
| cSimulation | 已有 ✓ | 412B | 插件先验,已核验无需改 |
| cGame | 已有 ✓ | 304B | 插件先验,已核验无需改 |
| cNetworkComponent | 已有 ✓ | 684B | 插件先验,已核验无需改 |
| cEntityComponent | 已有 ✓ | 16B | 插件先验,已核验无需改 |
| cEntityManager | 已有 ✓ | 309B | 插件先验,已核验无需改 |
| cDontStarveSettings | **重建** | 24B | 原 1B 占位 → vtable + MultiFileSettings |
| MultiFileSettings | **新建** | 20B | map 头 (std::_Rb_tree 20B) |
| SettingFile | **新建** | 56B | 两 RBTree 头 + flags + CoW string |
| EntityLuaProxy | **新建** | 16B | 4 字段 (pEntity/pSimulation/guid/versionSnapshot) |
| cPrefab | **重建** | 52B | 9 字段,引用新 cHashedStringCSL/cHashedString |
| cHashedString | **重建** | 8B | 原 1B 占位 → hash + buf |
| cHashedStringCSL | **重建** | 8B | 原 1B 占位 → hash + cstr |
| cHashedStringLookup | **新建** | 84B | 8 字段 |
| Mutex | **新建** | 56B | pthread_mutex_t 44B + attr 12B |

## 过程中发现并修正的文档错误

1. **cDontStarveSettings 大小**:文档写 8B(vtable + MultiFileSettings)但 MultiFileSettings 实际 20B(map 头),总 24B。文档已修正。
2. **cHashedStringLookup 大小**:文档写 92B,ctor 证据实际 84B(vec @ 60 + pool @ 72/76 + size @ 80)。文档已修正。
3. **SettingFile 大小**:ctor alloc 0x38 = 56B;string @ 0x34 是 CoW 单指针(4B),非 12B。Ghidra struct 有 8B 尾部 padding(显示 64B),字段偏移正确。
4. **cPrefab 字段**:Ghidra 反编译确认 `pName` @ 0x14 是 std::string(12B,非 CoW!)— cPrefab 用 libstdc++ std::string,SettingFile 用 CoW string?需 Tier 1 复查。注:cPrefab `name` 字段 12B 是 IDA ctor 证据 (`std::string::string(this+16, a5)`),与 SettingFile 的 CoW 4B 不同源 — 两处 string 实现可能不同。

## 回写流程验证(供 Tier 1+ 使用)

1. `get_struct_layout` 检查现有 struct(插件先验)
2. 已有且一致 → 跳过
3. 占位(1B)/缺失 → `delete_data_type` 删旧(如需)→ `create_struct` 建新
4. 依赖类型必须先建(如 Mutex → cHashedStringLookup)
5. `get_struct_layout` 验证偏移/大小/类型引用

## ⚠️ 工具陷阱(modify_struct_field 破坏 struct)

**现象**:对 cSimulation 的 `pMutexSysEvents`/`pMutexGameEvents` 调 `modify_struct_field` 改类型为 Mutex 时,**首字段 `pVtable_cGameEventListener` 被误删,所有后续字段偏移 -1**(412B→411B,104字段→90字段),struct 被破坏。

**对比**:cEntityManager 的 `pCriticalSection` 同样操作**成功且无损**。差异原因待查(可能是 cSimulation 字段数多/首字段无 undefined byte 导致)。

**规避**:`modify_struct_field` 对复杂 struct(多字段/首字段紧贴 0x0)有风险 → **用 delete + create_struct 全量重建**,不要 modify 单个字段。cEntityManager 已成功案例可继续用 modify(它首字段 @0 是 void* 且 struct 较简单),但保守起见复杂 struct 一律重建。

**已修复**:cSimulation 删除重建,412B / 90 字段验证通过(与插件先验布局一致,Mutex 字段正确引用)。

## 待办

- [x] cEntityManager/cSimulation 的 Mutex 字段改为 Mutex 类型引用(cSimulation 经重建,含 2×Mutex + cEntityManager 1×Mutex)
- [ ] cPrefab string 类型歧义复查(Tier 1)
- [ ] SettingFile 内部 map 布局精化(非核心)

## Tier 1 回写 (2026-08-08)

| 类型 | 状态 | 大小 | 说明 |
|---|---|---|---|
| ComponentLuaProxy | **新建** | 20B | 模板基类(vtable/component/simulation/guid/version);Add @ 0x30fde 定型 |
| SimLuaProxy | **新建** | 20B | ctor @ 0xed356 定型 |
| EntityLuaProxy | 已有 ✓ | 16B | Tier 0 回写 |

**Lunar 机制关键发现**:userdata 是 4B 指针包装(`Lunar::push` @ 0x312fa),proxy 对象堆上分配。ComponentLuaProxy 20B 覆盖约 28 个 Component 代理,子类无额外字段(仅虚函数)。
