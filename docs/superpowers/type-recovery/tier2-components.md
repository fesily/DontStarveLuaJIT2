# Tier 2 — Entity/Component 体系类型恢复报告

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp + idalib-mcp (会话 f9cdc808)
> 方法:插件先验 + IDA 反编译门禁 + 构造/析构 this+off

## 恢复成果

### 1. cAnimStateComponent — 验证通过 ✓ (插件先验 208B)

IDA `PlayAnimation` @ 0x2a626 交叉验证:
- `this[7]` = +28 `dwAnimHash` ✓
- 8B 写 +28..+35 = `dwAnimHash` + `pAnimStr` ✓
- `this[17]` = +68 `nEPlayMode` ✓
- `this[18]` = +72 `nEQueuedPlayMode` ✓
- `this[21]` = +84 `dwCurrentDirtyFlags` ✓

插件先验 208B/56 字段布局全部确认,无需重建。

### 2. EnvelopeComponent — 恢复完成 ✓ (28B)

- ctor @ 0x348fc:基类 + `*this = &unk_454BE8`(vtable)+ `this+4/5/6` = vec 头
- dtor @ 0x3496c:vec 存 Envelope hash(uint),经 EnvelopeManager::DeleteEnvelope 释放

```
+0x00 cEntityComponent base (16B)
+0x10 pVecEnvelopes_begin  +0x14 end  +0x18 cap
```

### 3. cImageComponent — 恢复完成 ✓ (20B)

- ctor @ 0x3d31c:基类 + vtable
- dtor @ 0x3d370:`this+4` (+16) 对象指针,经 vtable+24 释放(Texture*)

```
+0x00 cEntityComponent base (16B)
+0x10 pTexture (void*)
```

### 4. cSoundEmitterComponent — 恢复完成 ✓ (84B)

- ctor @ 0x7610a:基类 + vtable + 20 字段
- `+52/56` vec 头(哨兵指向 &+44 → 内联缓冲)

### 5. cPhysicsComponent — 恢复完成 ✓ (108B)

- ctor @ 0x6770c:基类 + vtable + 27 字段
- +72/+76/+80/+84:4 个对象指针(btRigidBody 等,dtor @ 0x67936 经 vtable 释放)
- 关键常量:1065353216 = 1.0f、1056964608 = 0.5f、0x10000 = 65536

### 6. TagSet — 拆字段完成 ✓ (72B, 原仅 char[72])

- ctor @ 0x282582 + MoveToHeap @ 0x282c02:
```
+0x00 staticTags: uint[12]   (STATIC_TAGS = 12, 静态标签)
+0x30 pStaticTags (指向自身)
+0x34 pHeapTags   (堆标签,MoveToHeap 时 new[4*size])
+0x38 nStaticCount
+0x3C nHeapCount
+0x40 nHeapCapacity
+0x44 nField_0x44
```
MoveToHeap:size > 0xC 断言,堆分配 4×size 字节,静态 12 tag 拷入。

### 7. cSpatialHash<cEntity> — 恢复完成 ✓ (40B)

- 分配:cEntityManager ctor @ 0xd2796 `operator new(0x28)`
- +36 `flCellSize` = 1098907648 = **0x41800000 = 16.0f**
- +0..+8: sBucketHolder vector 头
- +12..+28: std::map<cEntity*, sHashCoord> RBTree 头

### 8. Pool<T,FakeLock> — 恢复完成 ✓ (36B)

- ctor @ 0xd85cc:`Pool<cEntity,FakeLock>(this+208, 100)`
- +0 vtable、+4 firstChunk、+8 currentChunk、+12 chunkSize、+16-32 计数/状态
- sChunk (8B):`pData` + `pNext`;对象按 252B(cEntity)链式分配

## cEntity 引用闭合

cEntity 252B/39 成员全部指向已恢复类型:
- `+0x00` vtable
- `+0x10` cHashedString (prefabNameHash)
- `+0x18` StdVectorEntityPtr (children)
- `+0x28` RbTreeFollowerComponents
- `+0x40` cSimulation* (simulation)
- `+0x44` StdVectorComponentPtr (vec_components)
- `+0x60` TagSet (tagset)
- `+0xAC` RbTreeLuaNetVarsMap
- `+0xD4` pTransformComponent / `+0xD8` pNetworkComponent / `+0xDC` pAnimStateComponent — **与 Tier 1 CheckPointer `EntityByGUID+220` 吻合**

## 回写状态

| 类型 | Ghidra 状态 |
|---|---|
| cAnimStateComponent | 已有 208B,验证通过 ✓ |
| cTransformComponent | 已有 380B(未逐字段验证)|
| cEntityComponent | 已有 16B ✓ |
| cEntityManager | 已有 309B ✓ |
| EnvelopeComponent | **新建 28B** |
| cImageComponent | **新建 20B** |
| cSoundEmitterComponent | **新建 84B** |
| cPhysicsComponent | 已有 108B(插件先验,IDA ctor/dtor 验证一致 ✓)|
| TagSet | **新建 69B+3pad** |
| cSpatialHash_cEntity | **新建 40B** |
| Pool_Base / Pool_sChunk | **新建 36B / 8B** |

## 遗留

- cTransformComponent 380B 未逐字段验证
- 其余 30+ Component(cLabelComponent、cLightEmitter/Watcher、DebugRender、DynamicShadow、Follower、GraphicsOptions、Map、MiniMap、Pathfinder、PostProcessor、RoadManager、Shadow*、Shard*、StaticShadow、Twitch、Wave、cSerializableEntityComponent、cUITransformComponent、FontComponent、PurchasesManagerComponent、MapComponentBase、MapLayerManagerComponent)
- TagSet +0x44 语义未定
