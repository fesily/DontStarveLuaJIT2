# Tier 3-B — Map/WorldGen 子系统类型恢复报告

> 二进制:`dontstarve_steam`(macOS i386, base 0x1000)
> 工具:ghidra-mcp (G) + idalib-mcp (I, 会话 f9cdc808)
> 方法:ctor/dtor 反编译 + 使用函数语义验证 + 原始反汇编核对
> 只读调查,未回写 Ghidra。

---

## 1. MapComponentBase — 恢复完成 ✓ (304B)

**Ghidra 现状**:`/Demangler/MapComponentBase` 1B 占位。
**ctor**:`MapComponentBase::MapComponentBase()` @ 0x46eb6 (I);**dtor**:D2 @ 0x4707c (G)。
**vtable**:主 @ 0x4550F8;次 (+0x10) @ 0x455158;次 (+0x14) @ 0x455174(D2 重置确认)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | cEntityComponent base | 16B | ctor `cEntityComponent::cEntityComponent(this)` (I 0x46ec6) |
| +0x10 | pVtable2 (render iface) | void* | ctor `*(thisa+4)=&unk_455158`;D2 `*(this+0x10)=&PTR_...455158` |
| +0x14 | SceneGraphNode subobject | SceneGraphNode | ctor `SceneGraphNode::SceneGraphNode(thisa+20)` (0x46edd);D2 `SceneGraphNode::~(this+0x14)`;vtable @ +0x14 = 0x455174 |
| +0x60 | nField_0x60 | int =1 | ctor `*(thisa+23)=1` (0x47055);MapComponent ctor 亦置 1 |
| +0xA8 | pField_0xA8 | void* =0 | ctor 置 0;D2 `if(+0xa8) delete` |
| +0xB4 | pField_0xB4 | void* =0 | ctor 置 0;D2 `if(+0xb4) delete` |
| +0xC8 | bounds (AABB3F min/max) | 6×float | ctor `+50..+55 = 2139095039/-8388609`(+inf/-inf) |
| +0xE0 | pTileGrid | TileGrid* =0 | D2 `TileGrid::~TileGrid(+0xe0)`;Finalize 读 +0xe0 → w/h/tile data |
| +0xE4 | pTileGrid2 | TileGrid* =0 | D2 第二份 TileGrid delete |
| +0xE8 | pLayerManager | MapLayerManagerComponent* | D2 `*(+0xe8)+0x10` 调 cResourceManager::Release;MapComponent::Finalize `+0xe8 = GetComponent<MapLayerManagerComponent>()` |
| +0xEC | vecUndergroundRegions | vector<UndergroundRegion> | ctor 置 0;D2 `~vector(+0xec)`;Finalize `Terrain::GenerateUndergroundRegions(..., +0xf8)` 后 `operator=(+0xec, ...)` |
| +0xF8 | vecRenderLayers | vector<uint> | D2 逐元素 `cResourceManager::Release(+0xe8+0x10)` |
| +0x104 | vecTiles/Handles | vector<uint> | D2 逐元素 Release;Finalize 遍历(+0x104..+0x108)计 tile |
| +0x110 | bUndergroundLayer | byte =0xFF | ctor `*(byte)(+272) = -1`;Finalize `SetMapShore(..., (ushort)this[0x110], ...)` |
| +0x114 | pMapRenderer | MapRenderer* | D2 `MapRenderer::~(+0x114)`;Finalize `*(*(+0x114)+4) = layerManager` |
| +0x11C | map<int,int> (tile→count) | RBTree 20B | ctor 自引用 `left/right=&self+0x11C`;Finalize `_M_erase(+0x118)` + `map::operator[](+0x118)`;GCC4.2 空树:parent=0,left/right=&header |
| +0x130 | —(MapComponent 起点) | | MapComponentBase 结束 = 0x130 (304B) |

**UNKNOWN**:SceneGraphNode 内部字段(含 +0xA5 byte,Finalize 置 1)未展开(Tier 2 域);+0x60 语义(≈1 的整数)。

**回写建议**:新建 `MapComponentBase` 304B。

---

## 2. MapComponent — 恢复完成 ✓ (400B)

**Ghidra 现状**:`/Demangler/MapComponent` 1B 占位。
**ctor**:C2 @ 0x44f2c (I);**dtor**:D2 @ 0x4501e (G)。
**vtable**:主 @ 0x455008;次 (+0x10) @ 0x455074;次 (+0x14) @ 0x455090。
**继承**:MapComponent : MapComponentBase(304B)+ 自有字段 96B。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x130 | nNumWalkableTiles | int | ctor 0;Finalize `+0x130 += (tile>>0xC & 1)` |
| +0x134 | nNumUndergroundTiles | int | ctor 0;Finalize `+0x134 += (tile != 0x110 layer)` |
| +0x138 | mMat4_0 | Mat4 | ctor `*((_OWORD*)+312) = xmmword_3C84C0` (0x44f76) |
| +0x148 | mMat4_1 | Mat4 | ctor `+328 = xmmword_3C84C0` (0x44f7d) |
| +0x158 | flColor/Scale[4] | 4×float =1.0 | ctor `+86..+89 = 1065353216` |
| +0x168 | bInitialized | byte | Finalize `this[0x168] = 1` |
| +0x16C | pNavGrid | TileGrid* | ctor 0;SetNavSize 0x45298 `new TileGrid(0x1c, w, h)` → `+0x16c`;D2 `TileGrid::~(+0x16c)` |
| +0x170 | pMapRenderer | MapRenderer* | ctor 0;D2 delete;Finalize `*(*(+0x170)+4)=layerManager` |
| +0x174 | pWaveComponent | cWaveComponent* | ctor 0;Finalize `+0x174 = GetComponent<WaveComponent>()` |
| +0x178 | pRoadManager | RoadManagerComponent* | Finalize `+0x178 = GetComponent<RoadManagerComponent>()` |
| +0x17C | pGroundCreep | GroundCreep* | Finalize `+0x17C = GetComponent<GroundCreep>()` |
| +0x180 | ppNetworkTileRegions | cNetworkTileRegion** | ctor 0;Finalize `new[w*h*4]` + 每格 `new cNetworkTileRegion(0x188)`;D2 逐元素 vtable+4 delete 后 delete[] |
| +0x184 | nField (含 +0x186 short) | int =0x800040 | ctor `+97 = 8388672`;Finalize `(short)+0x186` → SetMapShore 高度 |
| +0x188 | flField | float =0.25 | ctor `+98 = 1048576000` (0x3E800000) |
| +0x18C | bFinalized | byte | Finalize `this[0x18c] = 1`;D2 尾部 |

**UNKNOWN**:+0x184 高位字节、+0x188 用途(0.25f,疑似 tile 尺寸系数);+0x138/+0x148 两个 Mat4 语义(渲染矩阵,值来自 xmmword_3C84C0)。

**回写建议**:新建 `MapComponent` 400B(基类引用新 MapComponentBase)。

---

## 3. MapGenSim — 恢复完成 ✓ (92B, Pool 分块 0x5C 证实)

**Ghidra 现状**:`/Demangler/MapGenSim` 1B 占位。
**ctor**:C2 @ 0x4ac0c (I);**dtor**:D2 @ 0x4acd8;**大小证据**:`Pool<MapGenSim>::sChunk::sChunk` @ 0x929be `new(chunkSize * 0x5C)`。
**vtable**:0x4551B8(单继承,无 thunk)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | cEntityComponent base | 16B | ctor (I 0x4ac1c) |
| +0x10 | pWorld | btDiscreteDynamicsWorld* | InitPhysics G: `new(0x150) btDiscreteDynamicsWorld` → `+0x10`;ExitPhysics vtable+4 delete |
| +0x14 | UNKNOWN | int | ctor/InitPhysics 均未写 |
| +0x18 | nCollObjCount | int | InitPhysics 增长逻辑 `if (+0x18 == +0x1c) grow` |
| +0x1C | nCollObjCap | int | 同上 |
| +0x20 | pCollObjs | void** | InitPhysics `btAlignedAlloc(n*4)` → `+0x20`;ExitPhysics 逐元素 vtable+4 delete |
| +0x24 | bAlignedAlloc | byte =1 | ctor `*(byte)+36=1`;InitPhysics `this[0x24]` 控制 aligned free |
| +0x28 | pBroadphase | btDbvtBroadphase* | InitPhysics `new(0xc4)` → `+0x28` |
| +0x2C | pDispatcher | btCollisionDispatcher* | InitPhysics `new(0x148c)` → `+0x2C` |
| +0x30 | pSolver | btSequentialImpulseConstraintSolver* | InitPhysics `btAlignedAlloc(0xd0)` → `+0x30` |
| +0x34 | pConfig | btDefaultCollisionConfiguration* | InitPhysics `new(0x5c)` → `+0x34` |
| +0x38 | vecNodes | vector<btRigidBody*> | ctor 置 0;GetNodePosition G `*(+0x38)[i]+0x204` 读节点 |
| +0x44 | pShapeBox (ground) | btConvex2dShape* | InitPhysics `btBoxShape(1,1,0.05)` + convex2d 包装 → `+0x44`,margin 0.03 |
| +0x48 | pShapeTri | btConvex2dShape* | InitPhysics `btConvexHullShape(三角)` + convex2d → `+0x48` |
| +0x4C | pShapeCylinder | btConvex2dShape* | InitPhysics `btCylinderShapeZ(1,1,0.05)` + convex2d → `+0x4C` |
| +0x50 | vecConstraints | vector<btTypedConstraint*> | ctor 置 0 (3 dword) |

**UNKNOWN**:+0x14;+0x50 内 12B 的语义(疑似约束向量,CreateConstraint @ 0x4bc84 未逐行核对)。

**回写建议**:新建 `MapGenSim` 92B。

---

## 4. MapLayerManagerComponent — 恢复完成 ✓ (84B)

**Ghidra 现状**:`/Demangler/MapLayerManagerComponent` 1B 占位。
**ctor**:C2 @ 0x4d896 (I);**dtor**:D2 @ 0x4d9ce (G:`cResourceManager::~(this+0x10)` + `cEntityComponent::~`)。
**vtable**:主 @ 0x455208;次 (+0x10) @ 0x45525C(→ __ZThn16 的 DoUnload/DoLoad,即 cResourceManager 虚接口)。
**继承**:cEntityComponent (16B) + cResourceManager<MapLayerRenderData,uint,FakeLock> @ +0x10 (68B)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | cEntityComponent base | 16B | ctor |
| +0x10 | cResourceManager 基类 | 68B | D2 `cResourceManager::~(this+0x10)` |
| +0x18 | (manager+0x08) vecRecords | vector<sResourceRecord> | ctor 3 dword 0;manager Add G `vector::push_back(this+8)` |
| +0x28 | (manager+0x18) free-list/map 头 | 20B | ctor 自引用 `+0x30/+0x34 = &this+0x28`;manager Add 读 +0x2C/+0x30 |
| +0x3C | (manager+0x2C) nFreeState | int | manager Add `if (+0x2c == +0x30) grow` |
| +0x40 | (manager+0x30) pFreeHead | int | 同上 free-list head |
| +0x48 | (manager+0x38) name | std::string | ctor `+0x48 = empty_rep+0xC`,`+0x4C/+0x50 = 0` |
| +0x54 | — | | 结束 = 84 (0x54) |

**UNKNOWN**:manager +0x04/+0x14 未初始化字段;free-list 结构内部。

**回写建议**:新建 `MapLayerManagerComponent` 84B。

---

## 5. MapLayerRenderData — 恢复完成 ✓ (≥624B, 0x270)

**Ghidra 现状**:`/Demangler/MapLayerRenderData` 1B 占位(含子占位 AtlasElement)。
**ctor**:C2 @ 0x94f86 (I,0x3ac);**dtor**:D2 @ 0x959ae (G:ReleaseVBs + `_M_erase(+0x254)` + 48×12B 循环 delete)。
**无 vtable**。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | nLayerIndex | byte | ctor `*thisa = (byte)a5`(工厂 h 参数) |
| +0x04 | mMaskTexture | uint (resource handle) | ctor FileManager map 查询 `+4 = handle` (0x9514a) |
| +0x08 | mNoiseTexture | uint | ctor 同上 `+8` (0x951e0) |
| +0x0C | pGameRenderer | GameRenderer* | ctor `thisa[3] = a3`;D2 `ReleaseVBs(this, *(this+0xc))` |
| +0x10 | atlasElements | StaticVector<48, vector<AtlasElement>> | ctor 循环零 12B×48 (0x94fb3);D2 `iVar1=0x244; do delete[+i]; i-=0xC` 循环至 +0x10;`StaticVector<...48>::resize/at` 函数证实 |
| +0x250 | nAtlasCount | int =0 | ctor `thisa[148]=0` (0x94fd5) |
| +0x254 | UNKNOWN | int | ctor 未写;D2 `_M_erase(+0x254)` 邻近(±4 歧义) |
| +0x258 | map<uint,RegionInfo> | RBTree 20B | ctor 自引用 `+0x260/+0x264 = &self+0x258` (0x95017/0x9501d);`std::map<uint,RegionInfo>::operator[]` @ 0x976f6 |
| +0x26C | nField | int =0 | ctor `thisa[154]=0` (0x9500d) |

**UNKNOWN**:+0x254 ±4(map 头实际基址,GCC4.2 RBTree header color 字段导致);AtlasElement 内部(1B 占位);RegionInfo 内部。

**回写建议**:新建 `MapLayerRenderData` 624B + 子类型 AtlasElement/RegionInfo 待 Tier 4。

---

## 6. PathfinderComponent — 恢复完成 ✓ (104B)

**Ghidra 现状**:`/Demangler/PathfinderComponent` 1B 占位。
**ctor**:C2 @ 0x61f3c (I);**dtor**:D2 @ 0x620c4;**vtable**:0x63390(`off_455748` 内容,read_memory 验证)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | cEntityComponent base | 16B | ctor |
| +0x10 | nField_0x10..0x14 | 3×int | ctor 置 0 |
| +0x20 | map1 (nav?) | RBTree 20B | ctor 自引用 `+0x28/+0x2C = &self+0x20` |
| +0x38 | map2 | RBTree 20B | ctor 自引用 `+0x40/+0x44 = &self+0x38` |
| +0x4C | map<uint,PathSearchRecord> searches | RBTree 20B | SubmitSearch G `map::operator[](+0x4c)`;GetSearchStatus `find(+0x4c)`,`end=+0x50`;GetSearchResult 同;ctor 初始化观测于 +0x50 区域(±4) |
| +0x64 | nNextSearchId | int | ctor `+100 = 1`;SubmitSearch `id = *(this+100); *(this+100) = id+1` |

**UNKNOWN**:+0x20/+0x38 两个 map 的具体键值语义(疑 wall/nav 数据,HasWall/AddWall 未逐行核对);map 头 ±4。

**回写建议**:新建 `PathfinderComponent` 104B。

### 6a. PathSearchRecord — 恢复完成 ✓ (144B)

**Ghidra 现状**:1B 占位(内嵌于 map 模板)。
**构造**:PathfinderComponent::SubmitSearch @ 0x62736 (G) 内联填充;**更新**:UpdateSearch @ 0x623b2 (G)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | eStatus status | int | SubmitSearch `*rec = 0`;GetSearchStatus `*(node+0x14)` = rec+0 |
| +0x08 | pPathfinderComponent | void* | SubmitSearch `rec[2] = this` |
| +0x0C | caps | PathCaps (2B) | SubmitSearch `*(word)(rec+0xc) = *(word)caps` |
| +0x10 | startPos | Vector3 | SubmitSearch `rec[4..6] = param_1` |
| +0x1C | goalPos | Vector3 | SubmitSearch `rec[7..9] = param_2` |
| +0x28 | startNode | PathNode (12B) | SubmitSearch `rec[10..0xc] = GetPathNodeFromPoint 输出` |
| +0x34 | goalNode | PathNode (12B) | 同上 |
| +0x40 | nMaxIterations | int (默认 1000) | SubmitSearch `rec[0x10] = 1000/param_5` |
| +0x44 | AStarSearch<PathNode,PathfinderParams> | 52B | SubmitSearch `AStarSearch::StartSearch(rec+0x44)`;UpdateSearch `AdvanceSearch(rec+0x44)` |
| +0x78 | resultPath | vector<PathNode> | UpdateSearch `push_back(+0x78)`;GetSearchResult `vector::operator=(+0x8c→rec+0x78)` |
| +0x84 | nIterations | int | UpdateSearch `+0x84 += AdvanceSearch 返回值` |
| +0x88 | flTime | double | UpdateSearch 累加 |

**回写建议**:新建 `PathSearchRecord` 144B。

---

## 7. AStarSearch<PathNode,PathfinderParams> — 恢复完成 ✓ (52B)

**Ghidra 现状**:`/Demangler/AStarSearch<PathNode,PathfinderParams>` 1B 占位(含 sNode)。
**ctor**:内联(PathfinderComponent 系构造);**dtor**:D1 @ 0x64006 / D0 @ 0x65560。
**StartSearch** @ 0x64214 (I);**AdvanceSearch** @ 0x63ba0 (G)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pVtable | void* | D0 存在(值未直接观测;ulong 实例同布局 +0 = 0x464654) |
| +0x04 | nStatus | int | StartSearch `a1[1]=0`;AdvanceSearch `if(+4==0)`;完成置 1/2 |
| +0x08 | openSet | vector<sNode*> | StartSearch `vector::push_back(a1+2)`;AdvanceSearch 排序+pop |
| +0x14 | closedSet | vector<sNode*> | AdvanceSearch `push_back(this+0x14)` |
| +0x20 | pParams | PathfinderParams* | StartSearch `a1[8]=a2`;AdvanceSearch `this_00 = *(this+0x20)` |
| +0x24 | path | vector<PathNode> | AdvanceSearch 完成时 `push_back(this+0x24)` 回溯 |
| +0x30 | flSearchTime | float | StartSearch `a1[12]=0`;AdvanceSearch `+0x30 += Timer` |

**sNode<PathNode>** (24B,`new(0x18)`):+0x00 pParent;+0x04 node(PathNode 8B,起点);+0x0C goal(终点坐标);+0x10 fGScore;+0x14 fHeuristic。证据:StartSearch `v2[3]=params+44; v2+1=params+36; v2[5]=CalcHeuristic; v2[4]=0`;AdvanceSearch 新节点构造 `*new=parent; new[3]=pf[3]; *(new+1)=*(pf+1); new[5]=heuristic; new[4]=gScore`。

**回写建议**:新建 `AStarSearch_PathNode` 52B + `sNode_PathNode` 24B。

---

## 8. AStarSearch<unsigned_long,AstarParams> — 恢复完成 ✓ (52B)

**Ghidra 现状**:`/Demangler/AStarSearch<unsigned_long,AstarParams>` 1B 占位。
**ctor**:C2 @ 0x30497a (I);**dtor**:D2 @ 0x3048fa;**StartSearch** @ 0x304a24 (I);**AdvanceSearch** @ 0x2ebdf0。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pVtable | void* = 0x464654 | ctor `*a1 = &unk_464654` |
| +0x04 | nStatus | int | ctor/StartSearch 置 0 |
| +0x08 | openSet | vector<sNode*> | ctor 置 0;StartSearch `push_back(a1+2)` |
| +0x14 | closedSet | vector<sNode*> | ctor `a1[5]=0` 等 |
| +0x20 | pParams | AstarParams* | StartSearch `a1[8]=a2` |
| +0x24..+0x2C | nField×3 | int | ctor 置 0 |
| +0x30 | flSearchTime | float | StartSearch `a1[12]=0` |

**sNode<unsigned long>** (16B,`new(0x10)`):+0x00 =0;+0x04 nodeId(ulong);+0x08 =0;+0x0C fScore。证据:StartSearch `v2[0]=0; v2[4]=nodeId; v2[8]=0; v2[12]=*(graph...)`。

**AstarParams**(部分):+0x04 startNodeId;+0x08 nField;+0x0C pNodeVec(boost adjacency_list 顶点数组);+0x10 nNodeCount。证据:StartSearch `v3=a2[1]; *(a2[3]+4*v3)`;D2 @ 0x306f7a `~vec(+0xc) 逐元素 delete`。boost 图内部未展开。

**回写建议**:新建 `AStarSearch_ulong` 52B + `sNode_ulong` 16B;AstarParams 部分(建议 20B 骨架,内部 boost 结构标 UNKNOWN)。

---

## 9. Maze — 恢复完成 ✓ (44B)

**Ghidra 现状**:`/Demangler/Maze` 1B 占位。
**ctor**:C2 @ 0x30b6d4 (I);**dtor**:D2 @ 0x30b986;**无 vtable**。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | bounds | AABB2F (4×float) | ctor `+0..+0xC = ±FLT_MAX` 后 ExpandToFit |
| +0x10 | points | vector<Vector2f> | ctor `push_back(a1+16)` 收集网格内点 |
| +0x1C | eMazeType | MazeType | ctor `+28 = a3` |
| +0x20 | nField_0x20 | int | ctor `+32 = a4`(种子/尺寸,UNKNOWN) |
| +0x24 | groundType | MapPainter::GroundType =154 | ctor `+36 = 154`;SetTileTypes G `+0x24 = param_2` |
| +0x28 | floorType | MapPainter::GroundType =18 | ctor `+40 = 18`;SetTileTypes `+0x28 = param_3` |

**UNKNOWN**:+0x20 语义;154/18 对应 GroundType 枚举名。

**回写建议**:新建 `Maze` 44B。

---

## 10. sBuild — 已存在验证通过 ✓ (76B)

**Ghidra 现状**:`/sBuild` 76B(插件先验)。
**dtor**:D2 @ 0x1359de (I) 逐字段核对(dtor 释放顺序即字段表验证):

| 偏移 | 结构字段 | dtor 证据 |
|---|---|---|
| +0x04 | dwName_cow | `v2 = thisa[1]`;`_Rep::_M_destroy(v2-0xC)` = std::string ✓ |
| +0x08 | pTexturesVec_begin | `vector<string>::~vector(this+8)` ✓ |
| +0x14 | pTextureHandles_begin | `if (thisa[5]) operator delete` ✓ (非数组 delete) |
| +0x20 | pSymbols | `if (thisa[8]) operator delete[]` ✓ |
| +0x24 | pSymbolFrames | `if (thisa[9]) operator delete[]` ✓ |
| +0x30 | pVertexData | `if (thisa[12]) operator delete[]` ✓ |
| +0x34 | pVertexData2 | `if (thisa[13]) operator delete[]` ✓ |

全部与现有 76B 结构吻合(+20 用 delete、其余数组 delete[]、vector<string> @ +8、string @ +4)。

**回写建议**:已存在,验证通过,无需改动。

---

## 11. QuadTreeNode — 恢复完成 ✓ (176B)

**Ghidra 现状**:`/Demangler/QuadTreeNode` 1B 占位(含 `/Node` 子占位)。
**ctor**:C2 @ 0xc4a52 (I) / C2(cGame*,cHashedString) @ 0xc4b86 (G);**dtor**:D2 @ 0xc4c8a。
**vtable**:0x456478。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | SceneGraphNode base | 148B | ctor `SceneGraphNode::(this)`;vtable @ +0 |
| +0x94 | pRootNode | QuadTreeNode::Node* | ctor `+0x94 = Node::RecCreate(min(-2048,-2048), max(2048,2048), 8)`;AddChild G `*(+0x94)` 断言非空 |
| +0x9C | set<SceneGraphNode*> | RBTree 20B | ctor 自引用 `+0xA4/+0xA8 = &self+0x9C`;CollectNodes 用 |

**QuadTreeNode::Node** (56B,RecCreate `new(0x38)`):
| 偏移 | 字段 | 证据 |
|---|---|---|
| +0x00 | bounds AABB2F | Node ctor / RecCreate `pf[0..3]` |
| +0x10 | pChild[4] | RecCreate `pf[4..7] = RecCreate(四象限, depth-1)`;Node ctor 置 0 |
| +0x20 | UNKNOWN/pad | 未写 |
| +0x24 | set<SceneGraphNode*> | Node ctor 自引用 `+0x2C/+0x30 = &self+0x24`;AddToQuadTree G `_M_insert_unique(this+0x20)`(±4 歧义) |

**回写建议**:新建 `QuadTreeNode` 176B + `QuadTreeNode_Node` 56B。

---

## 12. MyQuadTree / MyQuadTree::QuadTreeNode<RoadTri> — 恢复完成 ✓ (60B)

**Ghidra 现状**:`/Demangler/MyQuadTree/QuadTreeNode<RoadTri>` 1B 占位。
**MyQuadTree = 命名空间**(非类型):函数均为 `MyQuadTree::QuadTreeNode<RoadTri>::*`;RoadManagerComponent::GenerateQuadTree @ 0x6da20 直接 `QuadTreeNode<RoadTri>::Create(...)`,无容器对象。
**dtor**:D2 @ 0x6f7b4 (I 反汇编核对,循环为 4 个子节点);**Create** @ 0x6e920 (G,`new(0x3C)`)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | bounds | AABB2F | Create `puVar1[0..3] = ±FLT_MAX` |
| +0x10 | children[4] | boost::shared_ptr<QuadTreeNode<RoadTri>> ×4 | Create 零 4 对;dtor 释放 ctrl @ +0x14/+0x1C/+0x24/+0x2C (disasm `[EDI+EBX+0x14]`,EBX=0x18..-8 步进) |
| +0x30 | elements | vector<Element*> | Create `puVar1[0xC..0xE]=0`;dtor `if(+0x30) delete` |

**回写建议**:新建 `MyQuadTree_QuadTreeNode_RoadTri` 60B(或按模板 `QuadTreeNode<T>` 泛型)。

---

## 13. WorldSim — 已存在验证通过 ✓ (16B) + SimThread 140B

**Ghidra 现状**:`/WorldSim` 16B(插件先验)。
**ctor**:C2 @ 0xd92d6 (I);**dtor**:D2 @ 0xd9360 (G)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pCallbackObj | void* | ctor 拷贝 a5 (FastDelegate) 3 dword |
| +0x04 | pCallbackFunc | void* | 同上 |
| +0x08 | nCallbackAdjust | int | 同上 |
| +0x0C | pSimThread | WorldSim::SimThread* | ctor `new(0x8C) SimThread(a2,a3,a4)` → `a1[3]`;D2 `Thread::Stop(+0xc)` + delete ✓ |

**WorldSim::SimThread** (140B,ctor @ 0xd98fa G):+0x00 Thread base (vtable @ +0 = 0x456638);+0x78 pLuaState;+0x7C pSimulation;+0x80 byte;+0x84 char* (empty string 初始化);+0x88 int nLuaRef;+0x8C 结束。lua_alloc = WorldSim::SimThread::lua_alloc(用户数据 = this)。

**回写建议**:WorldSim 已存在验证通过;SimThread 为嵌套类型,建议新建(140B)。

---

## 14. cPrefab — 复查完成,需重建 (52B,字段布局与现有结构不同)

**Ghidra 现状**:`/cPrefab` 52B(插件先验)——**字段归属错误,需重建**。
**ctor**:C2 @ 0xf5bf6 (I + G 反汇编双重核对);**dtor**:D2 @ 0xebfac (G 反汇编)。
**特派任务结论**:0x00/0x04 hash 归属歧义已解决——**nameHash 在 +0x08,不在 +0x00**;+0x00 是 name 字符串数据指针;+0x04 是 int 参数。

**关键证据链**(0xf5bf6 反汇编):
- `0xf5c1a: string::string(EDI, [ESP+0x58])` → 临时 string @ +0 (arg3,即名字)
- `0xf5c27: [EDI+4] = [ESP+0x60]` → +0x04 = arg5 (int)
- `0xf5c3d: [EDI+0xC] = mEmptyString.dwHash`(瞬态,后被覆盖)
- `0xf5c52: string::string(EDI+0x10, [ESP+0x5C])` → string @ +0x10 (arg4)
- `0xf5c5e..0xf5c73: [EDI+0x14..0x20] = 0` → 资产 vec + 1 字段
- `0xf5c7a: [EDI+0x24] = [ESP+0x54]` → +0x24 = arg2 (cGame*)
- `0xf5c80..0xf5c8e: [EDI+0x28..0x30] = 0` → deps vec
- `0xf5cb0: cHashedStringCSL::Set(&local, *(char**)EDI)` → 对 +0 的字符串算 hash
- `0xf5cbb: [EDI+8] = local (8B)` → +0x08..+0x0F = {dwHash, pCstr}
- cGame::AddPrefab @ 0x13ffa:`*(cPrefab+8)` 作排序键 ✓ nameHash @ +8
- AddPrefDep @ 0xec160:`vector<string>::push_back(&this+0x28)` ✓ deps vec @ +0x28
- AddAsset @ 0xec20a:`vector<sPrefabAsset>::push_back(this+0x14)` ✓ 资产 vec @ +0x14
- dtor 反汇编:0xebfcc `~vec(+0x28)`;0xebfd7 `~vec(+0x14)`;0xebfe2 `_Rep::destroy(*(+0x10))`;0xebff0 `_Rep::destroy(*(+0x00))` ✓

| 偏移 | 字段(重建后) | 类型 | 与现有结构差异 |
|---|---|---|---|
| +0x00 | pName (name string _M_p) | char* | 现有误作 nameHash.dwHash |
| +0x04 | nFlags | int (arg5) | 现有误作 CSL 内部 |
| +0x08 | nameHash.dwHash | uint | 现有误作 nUNKNOWN_0x08 |
| +0x0C | nameHash.pCstr | char* | 现有误作 prefabHash.dwHash |
| +0x10 | sName2 (string _M_p) | char* | 现有误作 prefabHash.pBuf |
| +0x14 | vecAssets | vector<sPrefabAsset> | 现有误作 pName[12] |
| +0x20 | nField_0x20 | int =0 | 一致(现有 nUNKNOWN_0x20) |
| +0x24 | pGame | cGame* | 现有误作 nUNKNOWN_0x24 |
| +0x28 | vecDeps | vector<std::string> | 现有误作 pGame |
| +0x34 | — | 52B 结束 | |

**回写建议**:重建 `cPrefab`(52B,按上表);修正 tier0 evidence-chain 遗留歧义。

---

## 15. MapLuaProxy — 核对完成 ✓ (ComponentLuaProxy<MapComponent,MapLuaProxy> 子类,20B)

**Ghidra 现状**:`/Demangler/MapLuaProxy` 1B 占位;且 Demangler 已解析出基类 `ComponentLuaProxy<MapComponent,MapLuaProxy>`(1B 占位)。
**核对证据**:MapLuaProxy::SetSize @ 0x48b00 (G):
```c
cVar1 = ComponentLuaProxy<MapComponent,MapLuaProxy>::CheckPointer();
MapComponentBase::SetSize(*(MapComponentBase**)(this + 4), w, h);
```
- ✓ **确认是 ComponentLuaProxy<MapComponent,MapLuaProxy> 子类**,组件指针 @ +4
- 注册/Add:ComponentLuaProxy<MapComponent,MapLuaProxy>::Register @ 0x49ee4 / Add @ 0x4a240(与 tier1 模板机制一致)
- MapLuaProxy 自身无额外字段(D1 @ 0x4a61e 为空)
- 布局沿用 tier1 `ComponentLuaProxy<T,P>` 模板:+0x00 pVtable、+0x04 pComponent、+0x08 pSimulation、+0x0C guid、+0x10 versionSnapshot = **20B**

**回写建议**:新建 `MapLuaProxy` 20B(或复用 tier1 ComponentLuaProxy 模板注释)。

---

## 16. sRayCastPred — 恢复完成 ✓ (144B)

**Ghidra 现状**:`/Demangler/sRayCastPred` 1B 占位。
**ctor**:C2 @ 0xd90fa (I);**operator()**:@ 0xd6fc0 (G);SortResults @ 0xd5bde。**无 vtable**(仿函数)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vRayOrigin/pos | Vector3 (12B) | ctor 从 GetCurrentCameraInfo 拷 12B;operator() 距离计算读 `+0/+4/+8` |
| +0x0C | frustum | Frustum (96B) | ctor `Frustum(Proj*View)` + `qmemcpy(+0xc, 0x60)`;operator() `Frustum::Intersects(+0xc, ...)` |
| +0x6C | fClosestDist | float | ctor 0;operator() `if (fVar7 < +0x6c) +0x6c = fVar7` |
| +0x70 | pClosestEntity | cEntity* | ctor 0;operator() 同步更新 |
| +0x74 | bSortByDist | byte | ctor `+116 = a4`;operator() `(bool)this[0x74]` → RayTest |
| +0x78 | vPoint | Vector2f | ctor `+120 = *a5`;operator() `RayTest(entity, bSort, +0x78, ...)` |
| +0x80 | pSimulation | cSimulation* | ctor `+128 = a3` |
| +0x84 | results | vector<cEntity*> | ctor 零 3 dword;operator() `vector::push_back(+0x84, &entity)` |
| +0x90 | — | 144B 结束 | |

**回写建议**:新建 `sRayCastPred` 144B。

---

## 17. sPerPlayerSleepCheckPred — 恢复完成 ✓ (24B)

**Ghidra 现状**:`/Demangler/sPerPlayerSleepCheckPred` 1B 占位。
**ctor**:C2 @ 0x18b84c (I);**SetClient**:@ 0x18b8a8;**operator()**:@ 0x18b8b4 (G);Commit @ 0x18ba36。**无 vtable、无 dtor**(平凡类型)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pSimulation | cSimulation* | ctor `*thisa = a3` |
| +0x04 | pEntityManager | cEntityManager* | ctor `+1 = a3[16]`(=sim+0x40,与 SimLuaProxy 证据一致);operator() `ShouldEntitySleep(*(this+4), ...)` |
| +0x08 | pClient/Net | void* | ctor 0;SetClient 写入;operator() `*(*(this+8)+0x170/0x178)` 网络标志 |
| +0x0C | slept | vector<cEntity*> | ctor 零 3 dword;operator() `vector::push_back(+0xc, &entity)` |

**回写建议**:新建 `sPerPlayerSleepCheckPred` 24B。

---

## 回写建议汇总表

| 类型名 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| MapComponentBase | 新建 | 304B | ctor 0x46eb6 + D2 0x4707c 指针释放 + Finalize 语义 |
| MapComponent | 新建 | 400B | ctor 0x44f2c + D2 0x4501e + Finalize 0x4531a(字段语义) |
| MapGenSim | 新建 | 92B | ctor 0x4ac0c + InitPhysics 0x4ad6c + Pool chunk 0x5C @ 0x929be |
| MapLayerManagerComponent | 新建 | 84B | ctor 0x4d896 + D2 0x4d9ce(manager @ +0x10) |
| MapLayerRenderData | 新建 | 624B | ctor 0x94f86(StaticVector 48×12B + map) + D2 0x959ae |
| PathfinderComponent | 新建 | 104B | ctor 0x61f3c + SubmitSearch/GetSearchStatus(map @ +0x4C) |
| PathSearchRecord | 新建 | 144B | SubmitSearch 0x62736 全字段填充 + UpdateSearch/GetSearchResult |
| AStarSearch\<PathNode,PathfinderParams\> | 新建 | 52B | StartSearch 0x64214 + AdvanceSearch 0x63ba0 |
| sNode\<PathNode\> | 新建 | 24B | StartSearch new(0x18) 字段布局 |
| AStarSearch\<unsigned_long,AstarParams\> | 新建 | 52B | C2 0x30497a + StartSearch 0x304a24 |
| sNode\<unsigned_long\> | 新建 | 16B | StartSearch new(0x10) |
| AstarParams | 新建(骨架) | ~20B+ | D2 0x306f7a(+0xC vec);boost 图内部 UNKNOWN |
| Maze | 新建 | 44B | ctor 0x30b6d4 + SetTileTypes 0x30b9ba |
| sBuild | 已存在验证通过 | 76B | D2 0x1359de 与现有结构逐字段吻合 |
| QuadTreeNode | 新建 | 176B | ctor 0xc4a52/0xc4b86 + AddChild |
| QuadTreeNode::Node | 新建 | 56B | RecCreate 0xc4430 new(0x38) + Node ctor 0xc42c6 |
| MyQuadTree::QuadTreeNode\<RoadTri\> | 新建 | 60B | Create 0x6e920 new(0x3C) + D2 0x6f7b4(反汇编 4 子节点) |
| WorldSim | 已存在验证通过 | 16B | ctor 0xd92d6 + D2 0xd9360 |
| WorldSim::SimThread | 新建 | 140B | SimThread C2 0xd98fa(new(0x8C)) |
| cPrefab | **重建** | 52B | ctor 0xf5bf6 反汇编:nameHash @ +8(非 +0)、vecAssets @ +0x14、pGame @ +0x24、vecDeps @ +0x28 |
| MapLuaProxy | 新建 | 20B | SetSize 0x48b00 → ComponentLuaProxy<MapComponent,MapLuaProxy>::CheckPointer |
| sRayCastPred | 新建 | 144B | ctor 0xd90fa + operator() 0xd6fc0(Frustum/vec @ +0x84) |
| sPerPlayerSleepCheckPred | 新建 | 24B | ctor 0x18b84c + operator() 0x18b8b4 |

## 遗留 / 低置信

- GCC4.2 RBTree/map 头基址普遍存在 ±4 歧义(`_M_color` 枚举宽度);各 map 以「find/operator[] 使用的 this 基址」为准,ctor 自引用偏移见各节。
- PathfinderComponent +0x20/+0x38 两个 map 的键值语义未定。
- MapComponent +0x138/+0x148 Mat4、+0x188 float(0.25)语义未定。
- cPrefab +0x10 sName2(arg4)的语义(疑 prefabHash 名称/路径,ctor 参数映射见 0xf5bf6 反汇编)。
- AstarParams 内部 boost::adjacency_list 布局未展开(Tier 4)。
- sBuildSymbolFrame(52B,已存在)未在本片验证。
