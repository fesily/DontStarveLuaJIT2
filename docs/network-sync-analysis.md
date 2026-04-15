# Don't Starve Together — 网络同步分析

> 平台：macOS 32-bit `dontstarve_steam`（完整符号）  
> 分析方法：Ghidra 反编译 + 符号二进制逆向工程  
> 最后更新：2026-04-14

---

## 目录

1. [网络同步架构概述](#1-网络同步架构概述)
2. [通用序列化机制](#2-通用序列化机制)
3. [cAnimStateComponent — 动画状态同步](#3-canimstatecomponent--动画状态同步)
4. [cPhysicsComponent — 物理状态同步](#4-cphysicscomponent--物理状态同步)
5. [GroundCreepEntity — 爬行地面实体同步](#5-groundcreepentity--爬行地面实体同步)

---

## 1. 网络同步架构概述

DST 使用基于"脏标记 (DirtyFlags)"的增量组件同步。每个可同步组件维护两个 flag 字段：

| 字段 | 语义 |
|------|------|
| `dwCurrentDirtyFlags` | 本帧发生变化的属性掩码 |
| `dwPristineDirtyFlags` | 历史上曾改变过的属性掩码（Full-sync 时 OR 进去） |

**Serialize 调用约定**：

```c
void Serialize(BitStream* bs, bool bFullSync);
void Deserialize(BitStream* bs, bool bFullSync, bool bIgnoreApply);
```

- `bFullSync = true`：全量同步（Late-join 或状态重置），`dirtyMask = dwCurrentDirtyFlags | dwPristineDirtyFlags`
- `bFullSync = false`：增量同步，`dirtyMask = dwCurrentDirtyFlags`
- `bIgnoreApply`：反序列化时不写入某些"客户端自主推进"的字段（如 AnimTime、PlayMode）

---

## 2. 通用序列化机制

### 2.1 DirtyFlags 模式

```
Serialize() 流程：
  uMask = dwCurrentDirtyFlags | (bFullSync ? dwPristineDirtyFlags : 0)
  for each属性 P:
    if (uMask & BIT_P):
      bs.WriteBit(1)
      bs.Write(value_of_P)
    else:
      bs.WriteBit(0)

Deserialize() 流程：
  for each属性 P:
    if bs.ReadBit():
      read value_of_P
      apply to component
```

### 2.2 OnPostSerialize / SetPristine_Server

- `OnPostSerialize`：合并 dirty bits 到 pristine（bits 2+ 用 OR，bits 0-1 用 XOR 追踪 toggle 类型）；清零 dwCurrentDirtyFlags
- `SetPristine_Server`：清零全部 pristine + dirty，用于服务端认为状态已稳定时

---

## 3. cAnimStateComponent — 动画状态同步

**组件大小**：`sizeof(cAnimStateComponent) = 0xD0 = 208 bytes`  
**源文件**：`AnimStateComponent.cpp`  
**Serialize**：`0x2c39e`（578 行）  
**Deserialize**：`0x2d470`（680 行）

### 3.1 Struct 布局（精确偏移）

```c
struct cAnimStateComponent {
    /* +0x00 */ cEntityComponent  base;                  // 16 bytes
    /* +0x10 */ void*             pBBoxProviderVtable;
    /* +0x14 */ float             flAnimTime;            // 当前动画帧时间
    /* +0x18 */ float             flDeltaTimeMultiplier; // 播放速率倍数
    /* +0x1c */ uint32_t          dwAnimHash;            // 当前动画名 hash
    /* +0x20 */ void*             pAnimStr;
    /* +0x24 */ uint32_t          dwBankHash;
    /* +0x28 */ void*             pBankStr;
    /* +0x2c */ uint32_t          dwBuildHash;
    /* +0x30 */ void*             pBuildStr;
    /* +0x34 */ uint32_t          dwSkinHash;
    /* +0x38 */ void*             pSkinStr;
    /* +0x3c */ uint32_t          dwOverrideBuildHash;
    /* +0x40 */ void*             pOverrideBuildStr;
    /* +0x44 */ int32_t           nEPlayMode;            // 播放模式（0=normal,1=loop,2=once）
    /* +0x48 */ int32_t           nEQueuedPlayMode;
    /* +0x4c */ uint8_t           bRayTestOnBB;
    /* +0x4d */ uint8_t           bHidden;
    /* +0x4e */ uint8_t           _pad[2];
    /* +0x50 */ uint32_t          dwPristineDirtyFlags;
    /* +0x54 */ uint32_t          dwCurrentDirtyFlags;
    /* +0x58 */ uint32_t          dwDeserializedAnimHash; // 服务端下发的 animhash（与本地区分）
    /* +0x5c */ uint32_t          dwQueuedAnimHash;
    /* +0x60 */ uint32_t          dwRgbaAddColour;        // 加法混色 RGBA
    /* +0x64 */ uint32_t          dwRgbaMultColour;       // 乘法混色 RGBA
    /* +0x68 */ uint32_t          dwRgbaOverrideAddColour;
    /* +0x6c */ uint32_t          dwRgbaOverrideMultColour;
    /* +0x70 */ float             flOverrideShade;
    /* +0x74 */ float             flScaleX;
    /* +0x78 */ float             flScaleY;
    /* +0x7c */ float             flFinalOffsetX;
    /* +0x80 */ float             flFinalOffsetY;
    /* +0x84 */ float             flFinalOffsetZ;
    /* +0x88 */ uint8_t           bHasOverrideAddColour;
    /* +0x89 */ uint8_t           bHasOverrideMultColour;
    /* +0x8a */ uint8_t           _pad2[2];
    /* +0x8c */ int32_t           nField_0x8C;
    /* +0x90 */ float             flHauntStrength;
    /* +0x94 */ void*             pAnimNode;              // AnimNode* (渲染层状态)
    /* +0x98 */ void*             pVecAnimQueue_begin;
    /* +0x9c */ void*             pVecAnimQueue_end;
    /* +0xa0 */ void*             pVecAnimQueue_cap;
    /* +0xa4 */ int32_t           nSortOrder;
    /* +0xa8 */ void*             pAnimBankResource;
    /* +0xac */ void*             pUITransformComponent;
    /* +0xb0 */ float             flBBMinX;
    /* +0xb4 */ float             flBBMinY;
    /* +0xb8 */ float             flBBMinZ;
    /* +0xbc */ float             flBBMaxX;
    /* +0xc0 */ float             flBBMaxY;
    /* +0xc4 */ float             flBBMaxZ;
    /* +0xc8 */ uint8_t           bManualHitRegion;
    /* +0xc9 */ uint8_t           _pad3[3];
    /* +0xcc */ void*             pSymbolExchangeTree;    // RbTree<cHashedString, sSymbolOverride>
};
```

### 3.2 AnimNode 内部字段（渲染层对象）

AnimNode 是独立的渲染状态对象，由 cAnimStateComponent 持有，序列化时直接写入其字段：

| AnimNode 偏移 | 类型 | 含义 |
|--------------|------|------|
| `+0x48` | `uint8_t` | layer（层索引，3-bit 序列化） |
| `+0x4c` | `int` | sort_order 中间字段（vtable+0 调用） |
| `+0xC0` | `float[2]` | scale = [flScaleX, flScaleY] |
| `+0xC4` | `float` | depthBias |
| `+0xC8` | `float` | lightOverride |
| `+0xDC` | `void*` | hiddenLayers vector begin |
| `+0xE0` | `void*` | hiddenLayers vector end |
| `+0xE8` | `void*` | hiddenSymbols vector begin |
| `+0xEC` | `void*` | hiddenSymbols vector end |
| `+0xF4` | `bool` | bDepthTestEnabled |
| `+0xF5` | `bool` | bDepthWriteEnabled |
| `+0xF8` | `float` | sortOrder（vtable+8 调用） |
| `+0xFC` | `uint32_t` | dwAddColour（RGBA） |
| `+0x110~0x120` | RbTree | symbolOverrideTree（begin/end/size） |
| `+0x124` | `uint8_t` | orientation（1-bit 序列化） |
| `+0x128` | `float` | rotation |
| `+0x130` | `float` | finalOffsetX |
| `+0x134` | `float` | finalOffsetY |
| `+0x138` | `float` | finalOffsetZ |

### 3.3 DirtyFlags 位定义

| 位掩码 | 属性名 | 序列化内容 | 目标字段 |
|--------|--------|-----------|---------|
| `0x000001` | PlayMode | 2-bit enum | `nEPlayMode` |
| `0x000002` | AnimHash | 32-bit hash | `dwAnimHash` → `OnAnimChanged()` |
| `0x000004` | DeserializedAnimHash | 32-bit hash | `dwDeserializedAnimHash` |
| `0x000008` | BuildHash | 32-bit hash | `dwBuildHash` + `dwSkinHash` + `HandleClientBuildOverrides()` |
| `0x000010` | BankHash | 32-bit hash | `dwBankHash` → `OnAnimChanged()` |
| `0x000020` | *(always)* bHidden | 1-bit bool | `bHidden` |
| `0x000040` | SymbolExchanges | 5-bit count + N×entries | `pSymbolExchangeTree` |
| `0x000080` | HiddenLayers | 5-bit count + N×32-bit hashes | `pAnimNode+0xDC/0xE0` |
| *(next)* | HiddenSymbols | 5-bit count + N×32-bit hashes | `pAnimNode+0xE8/0xEC` |
| `0x000300` | Scale | 32-bit×2 (X,Y) | `flScaleX/Y` → `pAnimNode+0xC0` |
| `0x000400` | Layer | 3-bit | `pAnimNode+0x48` |
| `0x000800` | Orientation | 1-bit | `pAnimNode+0x124` |
| `0x001000` | Rotation | 32-bit float | `pAnimNode+0x128` |
| `0x002000` | SortOrderIntermediate | 8-bit (vtable+0) | `pAnimNode+0x4c` |
| `0x004000` | SortOrder | 32-bit float (vtable+8) | `pAnimNode+0xf8` |
| `0x008000` | DeltaTimeMultiplier | 32-bit float | `flDeltaTimeMultiplier` |
| *(always)* | bRayTestOnBB | 1-bit bool | `bRayTestOnBB` |
| `0x020000` | AddColour | RGBA 32-bit | `dwRgbaAddColour` → `pAnimNode+0xfc` |
| `0x040000` | MultColour | RGBA 32-bit | `dwRgbaMultColour` → `ApplyMultColour()` |
| `0x080000` | BloomEffect / OverrideBuild | 32-bit hash | `dwOverrideBuildHash` + `ApplyBloomEffectHandle()` |
| *(always 1-bit)* | HauntStrength | 1-bit bool | `flHauntStrength`（0 or const） |
| `0x100000` | LightOverride | 32-bit float | `pAnimNode+0xC8` |
| `0x200000` | FinalOffset | Vector3（3×32-bit） | `flFinalOffsetX/Y/Z` → `pAnimNode+0x130/134/138` |
| *(next)* | DepthBias | 32-bit float | `pAnimNode+0xC4` |
| *(always)* | DepthTestEnabled | 1-bit bool | `pAnimNode+0xF4` |
| *(always)* | DepthWriteEnabled | 1-bit bool | `pAnimNode+0xF5` |
| *(next bit)* | ManualHitRegion | 4×32-bit AABB | `flBBMin/MaxX/Y`；sets `bManualHitRegion=1` |
| *(next)* | AnimTime | 32-bit float（仅 `bIgnoreApply==false` 时写入） | `flAnimTime` |

### 3.4 Deserialize 两条代码路径

#### 路径 A：增量同步（普通帧，`bFullSync == false`）

```
dirtyMask = dwCurrentDirtyFlags
for each property bit:
  if (dirtyMask & bit) AND bs.ReadBit():
    read + apply property
  else:
    bs.ReadBit() (skip)
...
AnimTime：只有 bIgnoreApply==false 时才写入 flAnimTime
```

客户端自主推进 flAnimTime，服务端不参与逐帧推进。

#### 路径 B：全量同步（Late-join / 强制重置，`bFullSync == true`）

```
dirtyMask = dwCurrentDirtyFlags | dwPristineDirtyFlags
// 同 A 路径处理所有属性...
// 末尾增量驱动路径：
ReadBit PlayMode (2-bit)
if (bs.remaining > 0 && bs.ReadBit() == 1):
  ReadBit dwQueuedAnimHash (32-bit)
if (bIgnoreApply == false):
  clear animQueue (pVecAnimQueue_end = pVecAnimQueue_begin)
  dwAnimHash = dwQueuedAnimHash
  pAnimStr = null
  OnAnimChanged()
  if PlayMode != 2 且非循环重播同一动画:
    flAnimTime = 0.0
```

### 3.5 AnimTime 同步设计意图

| 场景 | bIgnoreApply | AnimTime 行为 |
|------|-------------|--------------|
| 正常增量帧 | `true` | 不写入；客户端完全自主推进 |
| Late-join 全量同步 | `false` | 写入 flAnimTime，定位到服务端当前帧位置 |
| 切换到新动画 | `false` | 新动画 flAnimTime = 0.0（全量路径重置） |
| 循环动画重播同一个 | `false` | 保留当前 flAnimTime（不重置） |

**设计核心**：AnimTime 只在初始化和动画切换时做对齐用，正常情况由客户端完全自主推进，避免网络抖动导致动画卡顿。

### 3.6 关键副作用函数

| 函数 | 触发条件 | 作用 |
|------|---------|------|
| `OnAnimChanged()` | AnimHash 或 BankHash 变化 | 加载动画资源，触发 Lua 回调 |
| `HandleClientBuildOverrides()` | BuildHash 变化 | 处理皮肤/Build 覆盖逻辑 |
| `ApplyMultColour()` | MultColour 变化 | 将 RGBA 写入 `pAnimNode+0x100` |
| `ApplyBloomEffectHandle()` | BloomEffect/OverrideBuild 变化 | 应用特效 Build 覆盖 |

---

## 4. cPhysicsComponent — 物理状态同步

**组件大小**：`sizeof(cPhysicsComponent) = 0x6C = 108 bytes`  
**源文件**：`PhysicsComponent.cpp`

### 4.1 DirtyFlags 位定义

| 位掩码 | 属性名 | 序列化内容 | 目标字段 |
|--------|--------|-----------|---------|
| `0x001` | Active | 1-bit bool（XOR 追踪） | `bActive` |
| `0x002` | Collides | 1-bit bool（XOR 追踪） | `nCollisionFlags` bit2 |
| `0x004` | CollisionMask | 16-bit short | `nCollisionMask` |
| `0x008` | CollisionGroup | 16-bit short | `nCollisionGroup` |
| `0x010` | Mass | 32-bit float | `fMass` |
| `0x020` | Friction | 32-bit float | `fFriction` → `btRigidBody+0xec` |
| `0x040` | Restitution | 32-bit float | `fRestitution` → `btRigidBody+0xf0` |
| `0x080` | CollisionShape | eCollisionShape（2-bit）| `eCollisionShape`；触发 `SetCollisionObject()` 重建 |
| `0x100` | Radius | 32-bit float | `fRadius` |
| `0x200` | Height | 32-bit float | `fHeight` |

### 4.2 PristineFlags 语义

- **bits 0-1**（Active / Collides）：XOR 追踪，反映与初始值的差异（toggle 布尔量）
- **bits 2-9**：OR 累积，表示"该字段是否曾被设置过"（全量同步时需要发送）
- `SetPristine_Server()`：4 字节原子写零，清空 pristine+dirty（服务端确认稳定后调用）

---

## 5. GroundCreepEntity — 爬行地面实体同步

**组件大小**：`sizeof(GroundCreepEntity) = 0x18 = 24 bytes`

### 5.1 Struct 布局

```c
struct GroundCreepEntity {
    /* +0x00 */ cEntityComponent  base;   // 16 bytes
    /* +0x10 */ uint8_t           nFlags; // bit0=dirty(radius), bit1=pristine, bit2=pristine2
    /* +0x11 */ uint8_t           _pad[3];
    /* +0x14 */ float             fRadius; // 网络同步 radius
};
```

### 5.2 同步属性

| 属性 | 类型 | DirtyBit | 说明 |
|------|------|---------|------|
| fRadius | 32-bit float | `nFlags` bit 0x01 | 爬行效果影响半径 |

**SetRadius**（Lua 接口）：`nFlags = 7`（同时设置 dirty + pristine 两个标志位）

---

## 附录：同步属性分类汇总

### 外观类（客户端感知优先）
- AnimHash、BankHash、BuildHash、SkinHash
- AddColour、MultColour、OverrideShade、BloomEffect
- HiddenLayers、HiddenSymbols、SymbolExchanges

### 动画控制类
- PlayMode、DeltaTimeMultiplier、AnimTime（初始化/切换时对齐）
- Scale、Orientation、Rotation、Layer
- FinalOffset、SortOrder

### 渲染辅助类
- DepthBias、DepthTestEnabled、DepthWriteEnabled
- LightOverride、HauntStrength

### 碰撞类（物理层）
- CollisionShape、Radius、Height、Mass
- Friction、Restitution
- CollisionMask、CollisionGroup、Active、Collides

### 交互类
- RayTestOnBB（射线检测）
- ManualHitRegion（手动 AABB 碰撞盒）
- fRadius（GroundCreepEntity）
