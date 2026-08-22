# Tier 1 — Lua 绑定层类型恢复报告

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp + idalib-mcp (会话 f9cdc808)
> 方法:插件先验 + IDA 反编译门禁 + Lunar 模板机制分析

## 核心发现:Lunar 绑定机制

所有 LuaProxy 通过 **Lunar<T> 模板**(Lua bind 库)注册:

- `Lunar<T>::push` @ 0x312fa:创建 **4B userdata**,仅存 proxy 指针 `*(v4) = a3` — userdata 是**指针包装**,不是内联结构
- `Lunar<T>::check` @ 0x31596:`luaL_checkudata` + 返回 `*(DWORD*)v3` = proxy 指针
- `Lunar<T>::Register` @ 0x30d5c:注册 metatable(className + luaL_Reg 表)

**关键洞见**:Lua 侧拿到的 userdata 是 4B 指针 → 指向真实 proxy 对象(堆上分配)。所以 proxy 对象布局从 `operator new` 大小 + 字段初始化反推,与 EntityLuaProxy(16B,独立)不同。

## 1. ComponentLuaProxy<T,P> 模板基类 — 完成 ✓

**大小**:20 字节 (0x14)
**分配**:`ComponentLuaProxy<T,P>::Add` @ 0x30fde:`v9 = operator new(0x14)`
**字段**(Add 初始化 + CheckPointer 确认):

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | void* | Add: `*v9 = vtable+8` |
| 0x04 | pComponent | T* | Add: `v9[1] = AddComponentToEntity<T>(...)`;PlayAnimation: `*(a2+4)` |
| 0x08 | pSimulation | cSimulation* | Add: `v9[2] = *(v10+64)` (v10 = component->entity) |
| 0x0C | guid | uint | Add: `v9[3] = *(v10+4)` (entity->guid) |
| 0x10 | versionSnapshot | int | Add: `v9[4] = *(v11+68)` (simulation 版本) |

**CheckPointer** @ 0x315e2 (模板实例):`a2+8` = simulation → `a2+4` 失效时经 `GetEntityByGUID(*(a2+12), *(v2+64), *(a2+12))` 刷新为 `EntityByGUID+220`(entity 的 component 槽);`a2+16` 更新快照。

**失效路径**:`EntityByGUID+220` (0xDC) 是 cEntity 中组件索引槽 → 恢复 cEntity 时需确认。

**适用**:约 28 个 `*LuaProxy` 继承此类(cAnimStateComponent 家族、MapGenSim、Physics、Pathfinder 等全部 Component 代理)。

## 2. EntityLuaProxy — 完成 ✓ (Tier 0 已恢复,16B)

见 `tier0-core.md`。独立 4 字段:pEntity/pSimulation/guid/versionSnapshot,**无 vtable**。

## 3. SimLuaProxy — 完成 ✓

**大小**:20 字节 (0x14)
**构造** @ 0xed356:

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pSimulation | cSimulation* | GetNumberOfEntities: `*(*(a1+0)+64)+76/+80` = entityMgr->allEntities vec |
| 0x04 | (未初始化) | — | 构造未写 |
| 0x08 | nField_0x08 | int | 构造置 -1 |
| 0x0C | bField_0x0C | byte | 构造置 0 |
| 0x10 | nField_0x10 | int | 构造置 -2 |

**方法**:GetNumberOfEntities @ 0xed43c、ProfilerPush/Pop、Hook、Get/SetDebugRender* 等 — 全是 simulation 访问。

## 4. 独立 LuaProxy(单例/服务代理)— 部分完成

| 类型 | 布局 | 证据 |
|---|---|---|
| DontStarveGameService::LuaProxy | 4B (仅 +0 服务指针) | ctor @ 0x1aaa6 |
| cInventoryLuaProxy | 无字段(单例) | ctor @ 0x14f136:仅 assert cInventoryManager::mInstance |
| cNetworkLuaProxy | 待恢复 | ctor @ 0x18e4f6 |
| cShardLuaProxy | 待恢复 | ctor @ 0x1a220a |
| SystemServiceLuaProxy | 4B? | ctor @ 0x239aa |
| DontStarveInputHandler::LuaProxy | 待恢复 | — |

## 5. 待恢复/确认

- [ ] cNetworkLuaProxy (含 tClientProxy 子类)布局 — 网络代理,Tier 3 网络恢复前需定
- [ ] cShardLuaProxy — shard 网络代理
- [ ] cEntity +220 (0xDC) component 槽确认(Tier 2)
- [ ] 42 个 LuaProxy 逐个 vtable 槽计数(确认虚函数完整性,可选)

## 方法总结(供后续)

1. `Lunar<T>::push` 反编译 → userdata 大小 + 存储方式(指针 vs 内联)
2. `ComponentLuaProxy<T,P>::Add`/`operator new` 大小 → proxy 对象大小
3. Add 字段初始化顺序 → 字段名/类型/偏移
4. `CheckPointer` 反编译 → 失效刷新逻辑 + 依赖字段(entity 槽位)
5. `Lunar<T>::Register` → className + luaL_Reg 方法表(方法签名)
