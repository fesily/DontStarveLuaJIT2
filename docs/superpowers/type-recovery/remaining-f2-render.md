# 剩余渲染/场景类型恢复报告 — remaining-f2-render.md (2026-08-08)

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp(get_struct_layout/read_memory/get_xrefs_to/decompile_function/disassemble_function)+ idalib-mcp(func_query/decompile,会话 c1f3f184 重建)
> 约束:只读,未回写 Ghidra;每类型 decompile ≤2 次(idalib)
> 前置:cEntityComponent = 16B;SceneGraphNode = 148B(0x94);std::string = 4B 旧 ABI;cDontStarveSim = 1148B 已建(含 pFreeCamera)

## 目标清单现状(Ghidra 搜索)

| 类型 | 现状 | 大小(本次确认) |
|---|---|---|
| Buffer | 1B 占位(/Demangler) | **0x0C = 12B** |
| cBBoxProvider | 1B 占位 | **4B(纯虚接口)** |
| cCameraInfo | 1B 占位 | **0xC0 = 192B** |
| cSimCamera | 1B 占位 | **0xC8 = 200B** |
| cFreeCamera | 1B 占位 | **0x150 = 336B** |
| cFreeCamera::sParams | 1B 占位 | **0x18 = 24B** |
| cFrameWalker | 1B 占位 | **0x10 = 16B** |
| RoadBuilder | 1B 占位 | **0x2C = 44B**(与 RoadManagerComponent+0xA4 一致) |
| VFXEmitterManager | 1B 占位 | **0x1004 = 4100B** |
| ShadowEntityComponent | 1B 占位 | **0x1C = 28B** |
| GroundCreep | **已存在 213B** | 核对通过(ctor 逐字段吻合) |
| GroundCreepEntity | **已存在 24B** | 核对通过(Serialize 吻合) |
| SimplexNoise | 1B 占位 | **0x804 = 2052B** |
| WorldSimActual | **已存在 36B** | 核对通过(new(0x24) + ctor 吻合) |

---

### Buffer
- 状态: 待恢复(1B 占位)
- 大小: 0x0C = 12B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x45BD58 | C2 `*(this)=&unk_45BD58` |
| 0x04 | uint | nSize | Size() 0x280980 `return this+4` |
| 0x08 | void* | pData | Data() 0x280988 `return this+8`(vtable slot3) |

- **接口契约(任务重点)**:vtable[+8]=GetSize(0x280980)、vtable[+12]=GetData(0x280988)。
  BinaryBufferReader C2 0x27f006 实证:`this+8 = vtable[+12](buf)`(=GetData→pBuffer)、`this+12 = vtable[+8](buf)`(=GetSize→dwBufferLength),与 Ghidra 已建 BinaryBufferReader(16B:pVtable/nOffset/pBuffer/dwBufferLength)完全吻合;BinaryBufferWriter(12B:vptr/pBuffer/dwOffset)同样吻合。
- 证据: C2 0x2807b0(`new[](a3)` 分配数据);copy C2 0x280880(转移所有权);D1 0x28092c / D0 0x280954;Size 0x280980 / Data 0x280988
- 回写建议: **新建 12B**(vtable 4 槽:D1/D0/Size/Data;BinaryBufferReader/Writer 已存在无需动)

### cBBoxProvider
- 状态: 待恢复(1B 占位)
- 大小: 4B(抽象接口,仅 vtable)
- 字段: 无数据成员;仅 vtable 0x45ee88(D1 0x48a88 / D0 0x48a8a + 纯虚 GetLocalBBox/GetWorldBBox)
- 证据: IDB 仅 D1 0x48a88 / D0 0x48a8a(0x1/0x5);派生类实现:cEntity::GetLocalBBox 0xcf8be / GetWorldBBox 0xcf914、cAnimStateComponent 0x2ad5e、MapComponentBase 0x46588、cImageWidget 0x3efa0、cTextEditWidget 0x7ccc2、cVideoWidget 0x8876c(均带 __ZThn16_ 跳转,说明作次级基类,返回 24B AABB = min/max Vector3,空实现填 ±FLT_MAX 0x7f7fffff/0xff7fffff)
- 回写建议: **新建 4B 抽象接口**(仅 vptr;或跳过——无数据成员,派生类已各自定型)

### cCameraInfo
- 状态: 待恢复(1B 占位)
- 大小: 0xC0 = 192B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | Vector3 | pos | SetCamera 0xe135a `this+0..8 = a2` |
| 0x0C | Vector3 | dir | SetCamera `this+12..20 = a3` |
| 0x18 | Vector3 | up | SetCamera `this+24..32 = a4` |
| 0x24 | Vector2<float> | screenSize | SetScreenSize 0xe12bc 写 +0x24/+0x28 |
| 0x2C | float | fov | SetFOV 0xe12ee 写 +0x2C |
| 0x30 | float | heading(deg) | SetCamera `this+48 = atan2(dir.z,dir.x)/0.017453+180` |
| 0x34 | float | minDist | SetMinDist 0xe1312 写 +0x34 |
| 0x38 | float | maxDist | SetMaxDist 0xe1336 写 +0x38 |
| 0x3C | Matrix4 | viewMatrix(64B) | GetViewMatrix 0xe1076 缓存于 +0x3C(flags&1 时重建) |
| 0x7C | Matrix4 | projMatrix(64B) | GetProjectionMatrix 0xe110c 缓存于 +0x7C(flags&2 时重建) |
| 0xBC | byte | flags(bit0=view dirty, bit1=proj dirty) | SetCamera 写 +188=3;SetScreenSize/SetFOV/SetMinDist/SetMaxDist 置位 2 |

- 证据: SetCamera 0xe135a(0xa5);GetViewMatrix 0xe1076 / GetProjectionMatrix 0xe110c;SetScreenSize 0xe12bc / SetFOV 0xe12ee / SetMinDist 0xe1312 / SetMaxDist 0xe1336;WorldToScreen 0xe1400 / ScreenToWorldRay 0xe15ec / GetFrustum 0xe168a;无 ctor 符号(内联,由 cSimCamera 内嵌构造)
- 回写建议: **新建 192B**(注意:无 vtable,首字段即 pos;视矩阵/投影矩阵为缓存)

### cSimCamera
- 状态: 待恢复(1B 占位)
- 大小: 0xC8 = 200B(cDontStarveSim::DoReset 0x8c09f `new(200)` 创建主相机)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x4566B8 | DoReset `*(pcVar2)=PTR_vtable_00450610+8`(=0x4566B8);GetCameraInfo 0x270ee 返回 this+8 |
| 0x04 | cSimulation* | pSimulation | DoReset `+4 = this`;cFreeCamera ctor `+1 = a3` |
| 0x08 | cCameraInfo(192B) | cameraInfo | GetCameraInfo 0x270ee `return this + 8`;Update 0xed2b6 对 +8 调 SetScreenSize |

- 证据: vtable 0x4566B8 = [D1 0xed2e0, D0 0xed2e2, Update 0xed2b6, GetCameraInfo 0x270ee];ctor 内联(DoReset 逐字段初始化:pos=(0,0,-12)、dir=(0,0,1)、up=(0,1,0)、screenSize=(1280,736)、fov=90、minDist=0、maxDist=200、flags=3)
- 回写建议: **新建 200B**(基类 cCameraInfo 内嵌于 +8;SetMainCamera/SetDebugCamera 0xfd2fe/0xfd322 存 cSimulation+0x10/+0x14 指针——已建 cSimulation 需核对)

### cFreeCamera
- 状态: 待恢复(1B 占位)
- 大小: 0x150 = 336B(cDontStarveSim::DoReset `new(0x150)` → pFreeCamera)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x454A38 | C2 `*(this)=&unk_454A38` |
| 0x04 | cSimulation* | pSimulation | C2 `+1 = a3` |
| 0x08 | cCameraInfo(192B) | cameraInfo | 继承 cSimCamera(GetCameraInfo 返回 this+8) |
| 0xC8 | sParams(24B) | params | C2 写入 sParams 六个初值(+50..+55);UpdateInfo 读 +200/+0xCC 传 SetCamera |
| 0xE0 | Vector3 | position | Update 0x26a24 射线-平面相交后改写 +0xE0/+0xE8 |
| 0xEC | cPController(28B) | zoomController | Update `cPController::Update(this+0xEC)` |
| 0x108 | cPController(28B) | headingController | Update `cPController::Update(this+0x108)`;UpdateInfo 0x2671e 读 +0x108 做 BuildYRotation |
| 0x124 | float | flHeading | SetHeading 0x2704c 写 +0x124/+0x128 |
| 0x128 | float | flHeadingTarget | 同上 |
| 0x12C..0x138 | float×5 + byte | UNKNOWN(1.0/0/1.0/0.01/byte0) | C2 置初值 |
| 0x140 | Vector3 | focusPos | Update 命中时写 +0x140/+0x144/+0x148 |
| 0x14C | byte | bHasFocus | Update 命中置 1 |

- 注: ctor 内两次 `cPController::Update` 目标 +0xEC/+0x108,各 28B(值@0/目标@4/速度@8/min@0xC/max@0x10/阈值@0x14/byte@0x18,据 cPController::Update 0x27076);SetFocusPos 0x26a06 写 focusPos
- 证据: C2 0x26472(0x2ab);D2 0x269d8(仅复位 vtable);Update 0x26a24(0x628);UpdateInfo 0x2671e;SetHeading 0x2704c;SetFocusPos 0x26a06;创建者 cDontStarveSim::DoReset 0x8c09f(`new(0x150)`)
- 回写建议: **新建 336B**(继承 cSimCamera;sParams 用嵌套类型)

### cFreeCamera::sParams
- 状态: 待恢复(1B 占位)
- 大小: 0x18 = 24B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | float | flMinZoom = 2.0 | C2 `+0 = 0x40000000` |
| 0x04 | float | flMaxZoom = 3456.0 | C2 `+1 = 1163575296` |
| 0x08 | float | flField_0x08 = 0 | C2 `+2 = 0` |
| 0x0C | float | flHeadingSpeed = 0.0824 | C2 `+3 = 1035122882` |
| 0x10 | float | flField_0x10 = 1.473 | C2 `+4 = 1069409358` |
| 0x14 | float | flField_0x14 = 0.7875 | C2 `+5 = 1061752795` |

- 证据: C2 0x26416(0x2e);cFreeCamera C2 把同值散布到 zoomController(min=+0xF8=2.0/max=+0xFC=3456.0)与 headingController(+0x114/+0x118)+ flHeading(+0x124/+0x128)
- 回写建议: **新建 24B**(作为 cFreeCamera 嵌套类型;语义命名参考 DST 源码 "cFreeCamera::sParams")

### cFrameWalker
- 状态: 待恢复(1B 占位)
- 大小: 0x10 = 16B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | const sAnim* | pAnim | C2 `*(a2) = a3` |
| 0x04 | int | ePlayMode | C2 `*(a2+4) = a4` |
| 0x08 | int | nFrameIndex | C2 `(Frame - anim+4) / 8`(8B/帧) |
| 0x0C | int | nFramesRemaining | C2 `floor(extra / anim->fps)`;GetNextFrame 递减并回 0 结束 |

- 证据: C2 0x12f89e(0xaa);GetNextFrame 0x12f94e(0x50,读 sAnim+0x14 帧数、+4 帧数据)
- 回写建议: **新建 16B**(sAnim 为已建动画类型,此处仅持指针)

### RoadBuilder
- 状态: 待恢复(1B 占位;RoadManagerComponent+0xA4 已预留 byte[44])
- 大小: 0x2C = 44B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x456118 | C2 `*(this)=off_456118` |
| 0x04 | vector<Vector2<float>>(12B) | vecControlPoints | AddControlPoint 0x99d5a `push_back(this+4)`;D2 delete +4 |
| 0x10 | int | nRoadCount = -1 | C2 `+4 = -1`;BeginRoad 0x99c94 `+0x10 += 1` |
| 0x14 | vector<RoadVisibilityData>(12B) | vecVisibility | BeginRoad `resize(this+0x14, ...)` |
| 0x20 | vector<SplineVB<Vector2,CatmullRomSpline>::GeneratedData>(12B) | vecGenerated | BeginRoad `resize(this+0x20, ...)`;D2 遍历 32B 元素释放 4 指针 |

- 证据: C2 0x99b2c(0x59);D2 0x99be0(0x82);BeginRoad 0x99c94;AddControlPoint 0x99d5a;AddSmoothedControlPoint 0x99e22;GenerateVertices 0x9a0ea;UpdateTileGrid 0x9a428(0x9a2);RoadManagerComponent::RenderRoads 0x6cdde 引用
- 回写建议: **新建 44B**(替换 RoadManagerComponent+0xA4 的 byte[44] 引用;RoadVisibilityData/GeneratedData 保持 1B 占位或按 32B 元素建)

### VFXEmitterManager
- 状态: 待恢复(1B 占位)
- 大小: 0x1004 = 4100B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x45637C | C2 `*(this)=off_45637C` |
| 0x04 | slot[512] × 8B | emitters | C2 `bzero(this+4, 4096)`;StartEmitter 0xbf468 循环 512 槽 |
| 槽+0 | word | wFlags(0x101=使用中) | StartEmitter `MOV word [slot+0],0x101`;KillEmitter 清 0 |
| 槽+2 | byte | bSleeping | SetSleeping 0xbf580 `this[id*8+6] = b` |
| 槽+4 | VFXEffectEmitter* | pEmitter | StartEmitter 存 / GetEmitter 0xbf568 读 `this+id*8+8`;KillEmitter 释放 |

- 证据: C2 0xbf406(0x2c);D0 0xbf462;StartEmitter 0xbf468 / StopEmitter 0xbf4c8 / KillEmitter 0xbf4ec / FlushAll 0xbf524 / GetEmitter 0xbf568 / SetSleeping 0xbf580 / Update 0xbf598 / CollectEmitterNodes 0xbf626
- 回写建议: **新建 4100B**(512 槽数组;VFXEffectEmitter 0x80 已建 28B?——注意 emitter 为 `new(0x80)` 的 VFXEffectEmitter,Slot 结构内嵌)

### ShadowEntityComponent
- 状态: 待恢复(1B 占位)
- 大小: 0x1C = 28B(字段止于 +0x1A)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | cEntityComponent(16B) | base | D0 0x71b40 调基类 dtor |
| 0x10 | float | flSizeX | SetSize 0x71792 写 +0x10;Serialize 0x717ec 经 SerializeScaleVector(this+0x10) |
| 0x14 | float | flSizeY | SetSize 写 +0x14 |
| 0x18 | byte | bEnabled | Enable 0x717ce 写 +0x18;Deserialize 0x71856 读 |
| 0x19 | byte | bPristine | Serialize `SVar1 |= this[0x19]` |
| 0x1A | byte | bFlags(bit0=enable dirty,bit1=sizeX,bit2=sizeY) | SetSize/Enable 置位;Serialize 判 &6 |

- 证据: vtable 0x4559b8(D1 0x71b3a / D0 0x71b40);SetSize 0x71792 / Enable 0x717ce / Serialize 0x717ec / Deserialize 0x71856 / OnPostSerialize 0x718d8;ctor 内联(工厂模板,无独立符号)
- 回写建议: **新建 28B**(基类 cEntityComponent;注意 bFlags 语义:序列化网络位)

### GroundCreep
- 状态: **已存在 213B,核对通过**
- 大小: 0xD5 = 213B(Ghidra 现有)
- 字段(ctor 0x3984c 逐字段核对):

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | cEntityComponent(16B) | base | C2 调 cEntityComponent::C2 |
| 0x10 | SceneGraphNode(148B) | sgn | C2 调 SceneGraphNode::C2;`+22=1`(SGN 内) |
| 0xA4 | float | fAccumTime | C2 `+41 = 0` |
| 0xA8 | float | fUpdateInterval = 1.0 | C2 `+42 = 1.0` |
| 0xAC | float | fField_0xAC = 1.0 | C2 `+43 = 1.0` |
| 0xB0 | TileGrid* | pTileGrid1 | C2 `+44 = 0`;OnInit 0x39b3e `new(0x1C)` 两 TileGrid |
| 0xB4 | TileGrid* | pTileGrid2 | C2 `+45 = 0`;OnInit 新建 |
| 0xB8 | byte* | pByteArray | C2 `+46 = 0`;OnInit `new[](w*h)` memset 1 |
| 0xBC | void* | pListBegin | C2 `+47 = 0` |
| 0xC0 | void* | pListEnd | C2 `+48 = 0` |
| 0xC4 | dword | nField_0xC4 | C2 `+49 = 0` |
| 0xC8 | MapLayerManagerComponent* | pMapLayerManagerCmp | C2 `+50 = 0`;OnInit 取组件并写入 MapRenderer+4 |
| 0xCC | MapRenderer* | pMapRenderer | C2 `+51 = 0`;OnInit `new(0x1C)` 创建 MapRenderer |
| 0xD0 | std::string(4B) | strEncodedData | C2 置空串;OnInit 非空则 DecodeString |
| 0xD4 | byte | bVBsDirty | C2 `+212 = 0` |

- **增量核对(任务指定)**:OnInitializationComplete 0x39b3e 确认 `new(0x1C)` 创建 **MapRenderer**(28B,已建),存入 +0xCC;pMapRenderer+4 = MapLayerManagerComponent;MapRenderer ctor 参数 "shaders/creep.ksh" ×2 → dwEffectHandle_1/_2 句柄。与 remaining-a-render.md 的 MapRenderer 28B 布局完全一致。
- 回写建议: **保留现有 213B struct**(核对通过),仅建议把 `sceneGraphNode`/`field_0xA8` 与 ctor 语义对齐命名

### GroundCreepEntity
- 状态: **已存在 24B,核对通过**
- 大小: 0x18 = 24B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | cEntityComponent(16B) | base | D0 0x3b6ea 调基类 |
| 0x10 | byte | nFlags | Serialize 0x3b2c8 判 `(bFullSync*4 + 2) & nFlags` |
| 0x14 | float | fRadius | Serialize 写 fRadius 至 BitStream;LuaProxy SetRadius 0x3be1a |

- 证据: Serialize 0x3b2c8(0xb6)/ Deserialize 0x3b37e;Pool<GroundCreepEntity,FakeLock> 0x8f4ac;cFactory Register 0x8e19e
- 回写建议: **保留现有 24B struct**(核对通过)

### SimplexNoise
- 状态: 待恢复(1B 占位)
- 大小: 0x804 = 2052B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x46252C | C2 `*(this)=&unk_46252C` |
| 0x04 | byte[1024] | perm[256] | C2 从 0x3C7A10 拷 256 dword → +4 |
| 0x404 | byte[1024] | permMod12[256] | C2 拷 256 dword → +0x404 |

- 证据: C2 0x12a9e0(0x47);sample 0x12aa70(0x648);D0 0x12b0ba;Util::cSingleton<SimplexNoise>::mInstance 0x45db50 + Initialize 0x1521e
- 回写建议: **新建 2052B**(标准 SimplexNoise 排列表;建议 `unsigned char perm[256]; unsigned char permMod12[256]`)

### WorldSimActual
- 状态: **已存在 36B,核对通过**
- 大小: 0x24 = 36B(Lunar<WorldSimActual>::Register 0xda1b5 `new(0x24)` + C1)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | void* | pLunarBase | Lunar 框架写(Lunar::push 0xda84a) |
| 0x04 | BoostMap* | pBoostMap | C2 `+1 = new BoostMap`(8B);ResetAll 0xdad26 重建;所有方法直用 |
| 0x08 | TileGrid* | pTileGrid | C2 `+2 = 0`;ConvertToTileMap 0xdba66 `new(0x1C)` 并存 |
| 0x0C | byte[24] | pLunarMetadata | 现命名(ctor/dtor 均未触碰,语义待定) |

- 证据: C2 0xdfea0(0x3f);D2 0xdfee6(0x4f,释放 pTileGrid+pBoostMap);new_T 0xdaa32(`operator_new(0x24)`);GetEncodedMap 0xdc9c0 / ReserveSpace 0xdeeb8 大量使用 pBoostMap/pTileGrid
- 回写建议: **保留现有 36B struct**(new(0x24) 与 ctor/dtor 吻合),建议 pLunarMetadata 改 byte[24] 或 UNKNOWN_0x0C[24]

---

## 回写建议汇总

| 类型 | 大小 | 建议 | 备注 |
|---|---|---|---|
| Buffer | 12B | **新建** | vtable[+8]=Size/+12=Data;BinaryBufferReader/Writer 已存在 |
| cBBoxProvider | 4B | **新建**(或跳过) | 纯虚接口,派生类已定型 |
| cCameraInfo | 192B | **新建** | 无 vtable;含 2×Matrix4 缓存 + flags@0xBC |
| cSimCamera | 200B | **新建** | vtable 0x4566B8;cCameraInfo 内嵌 +8 |
| cFreeCamera | 336B | **新建** | 继承 cSimCamera;cPController×2 + sParams@0xC8 |
| cFreeCamera::sParams | 24B | **新建** | 6 float;cFreeCamera 嵌套 |
| cFrameWalker | 16B | **新建** | sAnim* + 3 int |
| RoadBuilder | 44B | **新建** | 替换 RoadManagerComponent+0xA4 byte[44] |
| VFXEmitterManager | 4100B | **新建** | vtable + 512×8B 槽(word flags + byte sleeping + ptr) |
| ShadowEntityComponent | 28B | **新建** | cEntityComponent + 2 float + 3 byte |
| GroundCreep | 213B | **已存在,保留** | ctor 逐字段吻合;MapRenderer 28B 创建核对通过 |
| GroundCreepEntity | 24B | **已存在,保留** | Serialize 吻合 |
| SimplexNoise | 2052B | **新建** | 标准 perm 双表 |
| WorldSimActual | 36B | **已存在,保留** | new(0x24)/ctor/dtor 吻合 |

## 交叉验证链

- **Buffer 接口 ↔ BinaryBufferReader/Writer**:reader/writer ctor 经 Buffer vtable[+8]/[+12] 取 Size/Data,三者布局闭合。
- **cSimCamera ↔ cFreeCamera**:cFreeCamera 继承 cSimCamera(GetCameraInfo 均返回 this+8);cDontStarveSim::DoReset 同时 `new(200)`(主相机,vtable 0x4566B8)与 `new(0x150)`(自由相机,vtable 0x454A38),尺寸互证。
- **RoadBuilder ↔ RoadManagerComponent**:RoadBuilder 44B 与 RoadManagerComponent+0xA4 的 byte[44] 完全一致;RenderRoads 0x6cdde 经 component+0xA4 调用。
- **GroundCreep ↔ MapRenderer**:OnInitializationComplete 0x39b3e `new(0x1C)` 创建 MapRenderer(28B,已建),字段写入与 remaining-a-render.md 一致。
- **WorldSimActual ↔ BoostMap/TileGrid**:ctor/dtor/多个 Lua 方法交叉确认 +4/+8;new(0x24) 闭合 36B。
