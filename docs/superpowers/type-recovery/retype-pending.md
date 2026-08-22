# Pending Retype — 待定字段回写报告

> 输入: task-pending-retype-brief.md(8 项)+ pending-investigate.md「可确定字段清单」
> 操作: ghidra-mcp create_struct / modify_struct_field 写回 dontstarve_steam(macOS i386)
> 验证: 全部 5 个涉及 struct 的 get_struct_layout 复核 — 类型已变、字段名保留、size 未变
> 注: 两段式同 S1-S5 — 先按字段名改类型(会清空字段名),再以 `field_name:"offset:0xN"` + new_name 重新落名。

## 类型预检(search_data_types)

| 需求类型 | 实际类型 | size | 路径 |
|------|------|------|------|
| std::string(4B COW) | `cStdString`(新建) | 4 | /cStdString |
| IInputManager(4B 接口) | `IInputManager`(已存在,复用) | 4 | /IInputManager |
| btCollisionObject | 仅 Demangler 占位(1B) | 1 | /Demangler/btCollisionObject |
| cBPWorld | `cBPWorld`(已存在) | 52 | /cBPWorld |
| Input_SDLInputManager | `Input_SDLInputManager`(已存在) | 2916 | /Input_SDLInputManager |

- `cStdString` 新建:1 字段 `0x00 void* pRepData`(libstdc++ COW 旧 ABI 数据指针),4B。
- `IInputManager` 已存在且布局与规格完全一致(`0x00 void* pVtable`,4B),直接复用,未重复建。
- `btCollisionObject` 仅有 1B Demangler 占位(非真实 struct)→ MapGenSim.pCollObjs 按 brief 回写 `void **`。

## 成功 (7/8)

| struct.field | 新类型 | 偏移 | 说明 |
|------|------|------|------|
| cSimulation.pStrJsonSettings | cStdString | 0x168 | 内联 4B string(值类型,非指针) |
| cSimulation.pStrPurchases | cStdString | 0x16c | 内联 4B string(值类型,非指针) |
| cGame.pStrInstanceSettings | cStdString | 0x94 | 内联 4B string(值类型,非指针) |
| cGame.pStrPurchases | cStdString | 0xc4 | 内联 4B string(值类型,非指针) |
| MapGenSim.pCollObjs | void ** | 0x20 | btCollisionObject 未建 → void** |
| cPhysicsComponent.pPhysicsWorldSim | cBPWorld * | 0x24 | dtor@0x67936 +0x14 证据吻合 |
| ControlMapper.pInputManager | IInputManager * | 0x0 | ctor@0x208c4 签名 Input::IInputManager* |

## 保持 void* (1)

| struct.field | 偏移 | 原因 |
|------|------|------|
| DontStarveSystemService.pCacheMap | 0xc | 未建 MemoryCache::CacheItem / map 头,无法具体化;按 brief 保持 void* |

## 失败清单

无(FAIL_TYPE: 0 / FAIL_FIELD: 0)

## 抽查结果(5 struct + 1 新类型,全部 get_struct_layout 复核)

| struct | size(改前/改后) | 关键字段确认 |
|------|------|------|
| cStdString(新建) | - / 4 | pRepData = void * @0 |
| cSimulation | 412 / 412 | pStrJsonSettings = cStdString @0x168;pStrPurchases = cStdString @0x16c |
| cGame | 304 / 304 | pStrInstanceSettings = cStdString @0x94;pStrPurchases = cStdString @0xc4 |
| MapGenSim | 92 / 92 | pCollObjs = void ** @0x20 |
| cPhysicsComponent | 108 / 108 | pPhysicsWorldSim = cBPWorld * @0x24 |
| ControlMapper | 520 / 520 | pInputManager = IInputManager * @0x0 |

结论:建 1 类型(cStdString)+ 复用 IInputManager;7 字段成功回写、1 字段(pCacheMap)按 brief 保持 void*。字段名保留、size 未变。已 save_program。
