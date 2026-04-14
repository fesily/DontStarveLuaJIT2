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

### 选择的方案：SimLuaProxy::FindEntities Hook

**核心思路**：在 `SimLuaProxy::FindEntities` 调用前，临时将所有玩家实体的世界坐标缓存替换为外推位置；调用结束后立即还原。所有通过 `TheSim:FindEntities` 的查询（包括 Mod）自动受益，无需修改任何 Lua 代码。

**优势**：
- 不动空间哈希桶分配（避免漏检）
- DST 服务器单线程 tick，无并发风险
- 对 Lua 层完全透明，Mod 无法绕过
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
├── GameSimHook.hpp      # 导出 void InstallSimHooks();
├── GameSimHook.cpp      # 完整实现（278行）
├── DontStarveInjector.cpp  # Inject() 末尾调用 InstallSimHooks()
└── CMakeLists.txt       # MSVC else() 块添加 GameSimHook.cpp
```

### Hook 框架

项目使用 **Frida-GUM** (`gum_interceptor_replace`)，与 `GameRenderHook.cpp` 相同模式。Lua API 通过 `GetGameLuaContext().api._xxx()` 调用（不能直接调用标准 C Lua API）。

### 核心逻辑伪代码

```cpp
void hooked_FindEntities(void* self, void* L_) {
    // 1. 遍历 AllPlayers，计算并临时写入外推位置
    for (player in AllPlayers) {
        cEntity* ent = unwrap(player.entity);
        float cx = ent[+0x1f0], cy = ent[+0x1f4], cz = ent[+0x1f8];

        // 更新速度快照
        snap.vel.xz = (current_pos - snap.pos.xz) / dt;
        snap.pos = current_pos;

        // 外推
        float half_rtt = GetNetworkPing() / 2000.0f;  // 秒
        float ex = cx + snap.vel.x * half_rtt;
        float ez = cz + snap.vel.z * half_rtt;
        clamp(ex, ez, MAX_EXTRAP_DIST=1.5f);           // 限幅

        // 临时替换
        ent[+0x1f0] = ex; ent[+0x1f8] = ez;
        patches.push({ent, cx, cy, cz});
    }

    // 2. 调用原始 FindEntities（所有查询看到外推位置）
    original_FindEntities(self, L_);

    // 3. 立即还原
    for (p in patches) { ent[+0x1f0/4/8] = p.saved; }
}
```

---

## 已知限制与待改进项

### RTT 精度

当前 `GetNetworkPing()` 返回服务器到**所有已连接 peer** 的 Average Ping，而非 per-client RTT。当服务器上同时存在多个延迟差异较大的玩家时，精度下降。

**改进方向**：通过 `entity → cNetworkComponent::GetOwningNetworkClientObject() → cNetworkClientObject2+0x164(GUID) → RakPeer::GetLastPing(GUID)` 获取 per-client RTT。

| 函数 | macOS 32-bit | Windows x64 |
|------|------|------|
| `GetOwningNetworkClientObject` | `0x5c2e6` | 无符号，待定位 |
| `RakPeer::GetLastPing` | `0x0022b468` | 无符号，待定位 |
| `cNetworkClientObject2::GUID offset` | `+0x164` | 待确认 |

### 速度平滑

当前速度由相邻两帧的位置差计算，可能受到网络抖动影响。改进方向：添加简单的低通滤波（EMA），或使用多帧滑动窗口平均。

### 垂直方向

Y 轴外推被有意跳过（避免跳跃/落地时的位置噪声）。若有需求，可根据垂直速度阈值判断是否外推。

---

## 相关文件

- `src/DontStarveInjector/GameSimHook.cpp` — 完整 C++ 实现
- `src/DontStarveInjector/GameSimHook.hpp` — 接口声明
- `docs/movement-prediction.md` — cTransformComponent 移动预测（nPredictionEnabled 四态状态机）分析
- `docs/ghidra-struct-analysis.md` — cPhysicsComponent、cTransformComponent、GroundCreep 等 struct 逆向分析
