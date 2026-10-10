# DST 服务器延迟补偿 (Lag Compensation)

## 问题背景

在 Don't Starve Together 中，当怪物（服务端权威）攻击玩家时，服务器使用玩家的**最后确认位置**进行命中判定。由于网络延迟，客户端显示玩家已经跑出攻击范围，但服务器仍判定命中，造成明显的视觉不一致。

这是典型的"服务器用过去的位置做判定"问题，与延迟补偿（帮助攻击方命中）方向相反——需要的是**位置外推（Position Extrapolation）**：让服务器看到玩家的**预估当前位置**，而不是延迟后的确认位置。

---

## 技术分析

### 命中判定核心链路

```
Lua: TheSim:FindEntities(x, y, z, radius, mustTags, cantTags, onlyTags)
  → SimLuaProxy::FindEntities     [macOS 32-bit: 0xee500 | Win x64: 0x140130ae0]
  → cEntityManager::Query         [macOS 32-bit: 0xd5052 | Win x64: 0x14011ce20]
  → cSpatialHash::ApplyPred<QueryPred>
  → QueryPred::operator()(entity*)
      直接读取 entity+0x1f0/0x1f4/0x1f8 (worldPosX/Y/Z 缓存)
```

`TheSim:FindEntities` 是唯一的空间查询入口——所有攻击判定、仇恨判定、技能范围判定，以及所有 Mod 的自定义逻辑都通过此接口。

### entity 世界坐标缓存

| 字段 | macOS 32-bit | Windows x64 |
|------|------------|-------------|
| `worldPosX` | `entity+0xe8` | `entity+0x1f0` |
| `worldPosY` | `entity+0xec` | `entity+0x1f4` |
| `worldPosZ` | `entity+0xf0` | `entity+0x1f8` |
| `active flag` | `entity+0xf4` | `entity+0x1fc` |

这个缓存由 `cEntity::UpdateWorldPosition` 在每次 `SetPosition` 后立刻刷新（setter-driven，非帧循环批量），读自 `cTransformComponent+0x34/0x38/0x3c`（权威坐标）。该缓存是**单向只读**的——修改它不影响物理、碰撞、运动解算。

### 移动包结构分析

`RPC.PredictWalking` 包含：预测目标位置、移动方向、是否奔跑、`overridemovetime`（客户端本地移动时长）。**不含速度、不含显式 tick 编号**。速度通过 `player_classified` 网络变量单独同步。

### RTT 接口

`FUN_14022c430`（内部 `GetNetworkPing`）：
- 读取 `cNetworkManager` 全局单例（`DAT_140669d70`）
- `+0x2b0` = `RakPeer*`，`+0x30a` = `bServerStarted`
- 调用 `RakPeer vtable+0x158` = `GetAveragePing(GUID)`
- 返回到对端的平均 RTT（毫秒），无 args（自动选 GUID）

---

## 方案设计

### 选择的方案：Lua monkey-patch + 原生辅助函数

**核心思路**：在 `lag_compensation.lua` 中替换 `TheSim:FindEntities` 方法；在每次调用原始接口前，通过原生函数将所有已追踪玩家实体的世界坐标缓存临时替换为外推位置，调用结束后立即还原。原生层（`GameSimHook.cpp`）仅负责快照/外推/覆写/还原，不 hook 任何 C++ 函数。

**优势**：
- 不动空间哈希桶分配（避免漏检）
- DST 服务器单线程 tick，无并发风险
- 无需查找 `SimLuaProxy::FindEntities` 地址，维护成本低
- entity 世界坐标缓存单向只读，修改不影响物理

**外推公式**：

```
predicted_pos = last_confirmed_pos + velocity × (½ RTT)
```

其中 velocity 由相邻 FindEntities 调用间的位置差分计算，½ RTT 来自 `GetNetworkPing()` 实测值（fallback 50ms）。Y 轴不外推（规避角色上下抖动噪声）。外推量限幅 1.5 游戏单位（约 0.25 秒×6 u/s 跑速），防止玩家静止后突然移动时过度外推。

### 为何不 Hook UpdateWorldPosition

在 Windows x64 中，`cEntity::UpdateWorldPosition` 已被编译器 **inline** 进 `cTransformComponent::UpdateTransform`，不存在独立函数入口地址，无法 hook。

### inst.entity 解包装

`AllPlayers[i].entity` 是 `Lunar<EntityLuaProxy>` 创建的 Lua full userdata：

```c
void* ud    = lua_touserdata(L, -1);  // EntityLuaProxy**（full userdata 内容）
char* proxy = *(char**)ud;            // EntityLuaProxy*
char* ent   = *(char**)proxy;         // proxy+0x00 = cEntity*
```

`EntityLuaProxy` 布局（size=0x10，从 macOS 32-bit ctor 0xe173a 确认）：

| 偏移 | 类型 | 内容 |
|------|------|------|
| +0x00 | `cEntity*` | raw entity 指针 |
| +0x04 | `void*` | pEntityManager |
| +0x08 | `uint32_t` | entity GUID |
| +0x0c | `void*` | entityMgr+0x44 |

---

## 实现

### 关键地址

| 用途 | macOS 32-bit（参考，有符号） | Windows x64（目标） |
|------|------|------|
| `SimLuaProxy::FindEntities` | `0xee500` | `0x140130ae0` |
| `cEntityManager::Query` | `0xd5052` | `0x14011ce20` |
| `QueryPred::operator()` | `0xd6ba0` | `0x14011a0d0` |
| `GetNetworkPing` 内部 | — | `0x14022c430` |
| `cNetworkManager` 单例指针 | — | `DAT_140669d70` |
| `entity::worldPosX` | `+0xe8` | `+0x1f0` |
| `entity::worldPosY` | `+0xec` | `+0x1f4` |
| `entity::worldPosZ` | `+0xf0` | `+0x1f8` |
| `entity::active flag` | `+0xf4` | `+0x1fc` |
| `entity::pTransformComponent` | `+0xe0` | `+0xf0` |
| `entity::GUID` | `+0x04` | `+0x04` |
| `cEntity::UpdateWorldPosition` | `0xcf826` | Inline，无独立地址 |

### 字节特征码

```
# SimLuaProxy::FindEntities (Windows x64)
# MOV RAX,RSP; MOV [RAX+8],RBX; MOV [RAX+10h],RBP; MOV [RAX+18h],RSI; MOV [RAX+20h],RDI
48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 54 48 81 EC A0 01 00 00 48 8B ED

# GetNetworkPing / FUN_14022c430 (Windows x64)
# PUSH RBX; SUB RSP,50h; MOV RAX,[cNetworkManager]; CMP byte [RAX+30Ah],0
53 48 83 EC 50 48 8B 05 ?? ?? ?? ?? 80 B8 0A 03 00 00 00
```

### 文件结构

```
src/DontStarveInjector/
├── GameSimHook.hpp      # 空（仅 #pragma once，无导出声明）
├── GameSimHook.cpp      # 原生辅助函数实现（~147行）
│                        #   DS_LUAJIT_entity_get_raw_ptr
│                        #   DS_LUAJIT_lag_comp_init / clear_slot
│                        #   DS_LUAJIT_lag_comp_update_snapshot
│                        #   DS_LUAJIT_lag_comp_apply_all / restore_all
└── CMakeLists.txt       # MSVC else() 块添加 GameSimHook.cpp

Mod/scripts/
└── lag_compensation.lua # Lua 层：monkey-patch TheSim:FindEntities，
                         # 通过 FFI 调用上述原生函数
```

### 核心逻辑伪代码

```lua
-- lag_compensation.lua（Lua 层）
local original_FindEntities = sim_mt.FindEntities
sim_mt.FindEntities = function(...)
    lib.DS_LUAJIT_lag_comp_apply_all()          -- 临时写入外推位置
    local results = { original_FindEntities(...) }
    lib.DS_LUAJIT_lag_comp_restore_all()        -- 立即还原
    return unpack(results)
end
```

```cpp
// GameSimHook.cpp（原生层）
void DS_LUAJIT_lag_comp_update_snapshot(void* entity_ptr, int slot, float half_rtt_s) {
    // 读取当前位置，更新速度快照，计算外推位置（限幅 MAX_EXTRAP_DIST=1.5f），存入 g_snapshots[slot]
}

void DS_LUAJIT_lag_comp_apply_all() {
    // 将 g_snapshots 中所有 valid 条目的 entity+0x1f0/0x1f8 替换为外推值
}

void DS_LUAJIT_lag_comp_restore_all() {
    // 还原 entity+0x1f0/0x1f4/0x1f8 为快照中记录的原始值
}
```

---

## 已知限制与待改进项

### RTT 精度

~~当前 `GetNetworkPing()` 返回服务器到**所有已连接 peer** 的 Average Ping，而非 per-client RTT。~~

**已解决（network.stats）**：`plugin_network_stats` 按特征码锚定 `cNetworkClientObject2::UpdateNetStats`，
从代码窗口派生 5 个必需偏移（**不硬编码**）：`listing`（userid，作键）+ `ring` 指针/索引/槽位数/槽步长。
该函数每客户端每秒把引擎解出的 RTT（clamp 到 99999）写进 `ring[idx]`，插件只读该槽 —— 不替换、不调用
任何引擎函数（无 interceptor），也**不依赖 core.vm**。唯一导出 `DS_LUAJIT_net_client_ping(userid)`
（Lua: `TheNet:GetClientPing(userid)`）；userid/名字/netscore 等其它字段由 Lua 侧自取。
`lag_compensation.lua` 的 `refresh_rtt_map()` 优先使用它，取不到时回退 `GetClientTable()[i].ping`
（一次性输出 `[sim.lagcomp] native client ping unavailable, …`）。

平台实测参考（Windows x64 由运行时 probe 取得；Android arm64 为反编译参考，非 x86-64 平台不跑解码）：

| 项 | Windows x64（实测） | Android arm64（参考） |
|---|---|---|
| 锚点（签名命中唯一） | client `0x140296b80` / server `0x14025d2f0` | `UpdateNetStats @0x93b540` |
| listing（userid std::string 起点） | `+0x1C0` | `+0x1C0` |
| ring 指针 / 槽位数 / 槽步长 | `+0x330` / 60 / 8 | `+0x2C0`（`new(0x1E0)` = 60×8） |
| ring 最新槽索引 | `+0x340`（int8） | `+0x2D0`（int16，初值 0xFFFF） |
| 累加器（插件不读，解码内部用于推 N） | `+0x338` | `+0x2C8` |
| 引擎取 RTT 的方式 | `rakPeer->vtable[+0x158](rakPeer, &aog)` → clamp → 写入 `ring[idx]` | 同形（槽 `+0x1C0`） |
| 备注 | `client+0x320 = cNetworkManager*`，`manager+0x240 = RakPeerInterface*`（见 `types_android.hpp` 同构记录） | 同左（arm64 偏移见该文件） |

### 速度平滑

当前速度由相邻两帧的位置差计算，可能受到网络抖动影响。改进方向：添加简单的低通滤波（EMA），或使用多帧滑动窗口平均。

### 垂直方向

Y 轴外推被有意跳过（避免跳跃/落地时的位置噪声）。若有需求，可根据垂直速度阈值判断是否外推。

---

## 相关文件

- `src/DontStarveInjector/GameSimHook.cpp` — 原生辅助函数实现（entity 解包、快照/外推/覆写/还原）
- `src/DontStarveInjector/GameSimHook.hpp` — 空文件（仅 `#pragma once`）
- `Mod/scripts/lag_compensation.lua` — Lua 层实现（monkey-patch TheSim:FindEntities，FFI 调用原生函数）
- `docs/movement-prediction.md` — cTransformComponent 移动预测（nPredictionEnabled 四态状态机）分析
- `docs/ghidra-struct-analysis.md` — cPhysicsComponent、cTransformComponent、GroundCreep 等 struct 逆向分析
