# DST 移动预测系统分析

> 逆向来源: `dontstarve_steam` macOS 32-bit（完整符号版）
> 源文件: `source/simlib/TransformComponent.cpp`

---

## 概述

DST 客户端在本地执行玩家移动输入并预测未来位置，从而掩盖网络延迟带来的卡顿感。服务器定期下发真实坐标，客户端与之对齐（收敛），当收敛失败时进入等待/缓冲状态。

---

## 核心数据结构

### `cTransformComponent` 预测相关字段

| Offset | Type | 名称 | 说明 |
|--------|------|------|------|
| `+0x16c` | `cTransformationHistory*` | `pPredictionHistory` | 预测历史缓冲区；为 `null` 时预测完全禁用 |
| `+0x170` | `int` | `nPredictionStep` | 当前追赶步数；`EnableMovementPrediction` 初始化为 0 |
| `+0x174` | `int` | `nPredictionEnabled` | **核心状态机**（见下节）|
| `+0x178` | `ushort` | `wPristineDirtyFlags` | 全量同步掩码 |
| `+0x17a` | `ushort` | `wCurrentDirtyFlags` | 增量脏标记 |

### `nPredictionEnabled` 四态状态机

| 值 | 枚举名 | 含义 |
|----|--------|------|
| `0` | `DISABLED` | 预测关闭；`EnableMovementPrediction(false)` 设置 |
| `1` | `ACTIVE` | 正常预测运行 |
| `2` | `WAITING` | 缓冲区满 + 收敛失败；等待服务器重同步 |
| `3` | `BUFFERING` | 收到服务器数据但 `Flatten` 失败；正在缓冲追赶 |

---

## 状态转换

```
                  EnableMovementPrediction(true)
                  [客户端模式 && pPredictionHistory==null]
                            │
                            ▼
              ┌─────────────────────────┐
              │      0: DISABLED        │◄──── EnableMovementPrediction(false)
              └─────────────────────────┘
                            │ 创建 cTransformationHistory
                            │ nPredictionStep = 0
                            ▼
              ┌─────────────────────────┐
          ┌──►│      1: ACTIVE          │◄──────────────────────────────┐
          │   └─────────────────────────┘                               │
          │              │                                              │
          │   PostPhysicsWallUpdate:                                    │
          │   缓冲区占用率 >= HIGH_THRESHOLD                              │
          │   && Flatten() 失败                                          │
          │              │ → SendResyncRequestToServer()                │
          │              │ → Lua: "desync_waiting"                     │
          │              ▼                                              │
          │   ┌─────────────────────────┐                               │
          │   │      2: WAITING         │                               │
          │   └─────────────────────────┘                               │
          │              │                                              │
          │   CheckTransformationPredictionHistory:                     │
          │   Truncate成功 + Flatten失败                                  │
          │   + 占用率 > LOW_THRESHOLD                                   │
          │   + !param_2 + 当前状态==2                                   │
          │              │ → Lua: "desync_buffering"                   │
          │              ▼                                              │
          │   ┌─────────────────────────┐                               │
          │   │      3: BUFFERING       │                               │
          │   └─────────────────────────┘                               │
          │                                                             │
          └─── 回到 ACTIVE 的所有路径 ────────────────────────────────────┘
```

### 回到 ACTIVE(1) 的所有条件

| 触发函数 | 条件 | 日志/事件 |
|---------|------|---------|
| `CancelTransformationPrediction()` | 任意状态，强制 | - |
| `ClearTransformationPrediction()` | 任意状态，清空缓冲 | - |
| `CheckTransformationPredictionHistory` | Truncate 成功 + Flatten **成功** | `"desync_resumed"` |
| `CheckTransformationPredictionHistory` | Flatten 失败 + 占用率 ≤ LOW_THRESHOLD | `"Locomotor: Resumed"` |
| `CheckTransformationPredictionHistory` | param_2 && 尾部距离 < ε | `"Locomotor: Resynced"` |

---

## 关键函数说明

### `EnableMovementPrediction(bool)` — `0x80f32`

启用/禁用预测的入口。

**启用时** (`true`) 前置检查：
1. `pPredictionHistory == null`（未重复初始化）
2. `cNetworkManager->bField_0x108 != 0`（必须是客户端，服务器永远跳过）

满足条件后：
- `new cTransformationHistory(capacity)` → `pPredictionHistory`
- 容量 = `flInputScale * TICK_CONSTANT`，上限 `0x834`
- `nPredictionStep = 0`
- `nPredictionEnabled = 1`

**禁用时** (`false`)：
- 删除 `pPredictionHistory`，置 `null`
- `nPredictionEnabled = 0`

---

### `CanPredict()` — `0x80a30`

```c
bool CanPredict() {
    return pPredictionHistory != null
        && nPredictionEnabled >= 1;
}
```

---

### `HasPrediction()` — `0x80eb6`

```c
bool HasPrediction() {
    return pPredictionHistory != null
        && nPredictionEnabled >= 1
        && history.size() > 0;
}
```

---

### `PostPhysicsWallUpdate(float dt)` — `0x811f2`

每物理帧调用，负责检测 ACTIVE → WAITING 转换：

```
if 缓冲区占用率 >= HIGH_THRESHOLD:
    if Flatten() 失败:
        nPredictionEnabled = 2  // WAITING
        SendResyncRequestToServer()
        Log "Locomotor: Waiting for server..."
        PushLuaEvent("desync_waiting")
```

---

### `WallUpdateCheckTransformationPrediction(float dt)` — `0x80c28`

每逻辑帧调用，从服务器接收到位置数据后执行同步判断：

```
if !IsServerReadyForMovementPrediction():
    CancelTransformationPrediction()   // 服务器未就绪则取消（不禁用）
    return

调用 CheckTransformationPredictionHistory(serverPos, isAuthoritative)
```

---

### `CheckTransformationPredictionHistory(Vector3& serverPos, bool authoritative)` — `0x8072e`

核心状态收敛函数，决定是否能回到 ACTIVE：

```
Truncate(serverPos)  // 裁剪历史到服务器时间戳

if Truncate 成功:
    if Flatten() 成功:
        → ACTIVE(1), Log "desync_resumed"
    else if 占用率 > LOW_THRESHOLD && !authoritative && state == 2:
        → BUFFERING(3), Log "desync_buffering"
    else if 占用率 <= LOW_THRESHOLD:
        → ACTIVE(1), Log "Locomotor: Resumed"
    
if authoritative && tail_distance < ε:
    → ACTIVE(1), Log "Locomotor: Resynced"
```

---

### `FlattenPrediction()` — `0x80efe`

将预测历史"压平"到当前服务器位置，即平滑插值纠偏。

- 成功 = 误差在可接受范围内
- 失败 = 客户端与服务器位置偏差过大，需要继续等待

---

### `CancelTransformationPrediction()` — `0x81096`

强制回到 ACTIVE，但**不销毁** `pPredictionHistory`（保留缓冲容量）：

```c
history.clear();
nPredictionStep = 0;
nPredictionEnabled = 1;
```

---

### `ClearTransformationPrediction()` — `0x8067e`

与 Cancel 类似，额外清零服务器坐标缓存：

```c
history.clear();
nPredictionStep = 0;
nPredictionEnabled = 1;
// 同时清零 flServerPos/Rotation/Scale
```

---

## 预测被禁止的完整情况

| 场景 | 原因 | 结果 |
|------|------|------|
| **服务器进程** | `bNetworkManager_0x108 == 0` | `EnableMovementPrediction` 直接 return，永不启用 |
| **显式关闭** | Lua/C++ 调用 `EnableMovementPrediction(false)` | `nPredictionEnabled = 0` |
| **服务器未就绪** | `IsServerReadyForMovementPrediction() == false` | 每帧 `WallUpdate` → `CancelTransformationPrediction()`（状态维持 1，但历史清空） |
| **严重去同步** | 缓冲区满且 `Flatten()` 失败 | `nPredictionEnabled = 2`，物理速度被强制清零 |

---

## 与物理系统的联动

`cPhysicsComponent::SetLocalMotorVel` 中：

```c
if (*(int*)(pTransformComponent + 0x174) < 2) {
    // nPredictionEnabled == 0 或 1：正常施加速度
    this->fMotorVelX/Y/Z = vel;
} else {
    // nPredictionEnabled == 2 或 3 (WAITING/BUFFERING)：
    // 清零 motor vel，清零 btRigidBody linearVelocity
    // → 实体在去同步期间完全停止移动
}
```

即：**WAITING 和 BUFFERING 期间实体无法移动**，防止客户端在与服务器严重不同步时继续预测位置偏移。

---

## 术语对照

| 代码术语 | 含义 |
|---------|------|
| `cTransformationHistory` | 环形缓冲区，存储历史输入帧的位置/速度快照 |
| `Truncate` | 根据服务器时间戳裁剪历史（删除已确认的旧帧） |
| `Flatten` | 将预测历史压平到服务器位置（平滑纠偏） |
| `nPredictionStep` | 追赶步数，控制 Flatten 的插值速度 |
| `HIGH_THRESHOLD` | 缓冲区占用率上限（`DAT_003b77b0`），超过则触发 WAITING |
| `LOW_THRESHOLD` | 缓冲区占用率下限，低于则可恢复 ACTIVE |
| `SendResyncRequestToServer` | 向服务器请求完整状态重同步 |
