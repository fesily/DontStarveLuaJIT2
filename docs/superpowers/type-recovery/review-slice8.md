# Type Recovery Review — Slice 8 (Map)

- 日期: 2026-08-08
- 分片: Maze, QuadTreeNode_Node, QuadTreeNode, AStarSearch_PathNode
- 对照: `docs/superpowers/../../3rd/dst/game_decompiler/types_common.h` + `docs/superpowers/type-recovery/tier3-b-map.md`
- 环境: Ghidra `/dontstarve_steam`(macOS i386, base 0x1000); idalib-mcp session `f9cdc808`
- 性质: 只读审查,未做任何写入

## 审查方法
1. `get_struct_layout` 读取 Ghidra 当前 struct 布局。
2. 与 `types_common.h` / `tier3-b-map.md` 字段表比对(名称、偏移、类型、总大小)。
3. idalib-mcp decompile 抽查 ctor / 使用字段的函数,交叉验证关键偏移。
4. 检查 padding/UNKNOWN 合理性、字段错位。

---

### Maze
- 状态: **PASS**
- Ghidra 大小: 44B | 文档大小: 44B (0x2C) | 匹配: yes
- 字段比对: 全部一致(仅命名风格不同,偏移/类型/顺序完全相同):

| 偏移 | Ghidra | types_common.h / tier3-b-map.md |
|---|---|---|
| +0x00 | flBounds_minx/miny/maxx/maxy (float×4) | bounds AABB2F (float[4]) |
| +0x10 | pPoints_begin/end/cap (void*×3) | points vector\<Vector2f\> |
| +0x1C | nEMazeType (int) | eMazeType (MazeType) |
| +0x20 | nField_0x20 (int) | nField_0x20 (int) |
| +0x24 | nGroundType (int) | groundType (GroundType=154) |
| +0x28 | nFloorType (int) | floorType (GroundType=18) |

- 证据:
  - ctor `0x30b6d4`: `+0..+0xC = ±FLT_MAX`(bounds 初始化);`+0x10/+0x14/+0x18 = 0`(vector);`+0x1C = a3`(eMazeType);`+0x20 = a4`(nField_0x20);`+0x24 = 154`(groundType);`+0x28 = 18`(floorType);`std::vector::push_back(a1+16, ...)`(points @ +0x10)✓
  - SetTileTypes `0x30b9ba`: `*(a1+36)=a2`(+0x24 groundType)、`*(a1+40)=a3`(+0x28 floorType)✓ 与报告证据逐字吻合。
- 问题清单: 无。命名差异(nEMazeType/nGroundType vs eMazeType/groundType)为纯命名惯例,偏移与类型一致,不影响布局正确性。

---

### QuadTreeNode_Node
- 状态: **PASS**
- Ghidra 大小: 56B | 文档大小: 56B (0x38) | 匹配: yes
- 字段比对: 全部一致:

| 偏移 | Ghidra | types_common.h / tier3-b-map.md |
|---|---|---|
| +0x00 | flBounds_minx/miny/maxx/maxy (float×4) | bounds AABB2F |
| +0x10 | pChild0..3 (void*×4) | pChild[4] |
| +0x20 | nField_0x20 (int) | UNKNOWN/pad(未写) |
| +0x24 | nSet_pad/color + pSet_parent/left/right (RBTree 20B) | set\<SceneGraphNode*\> RBTree 20B |

- 证据:
  - RecCreate `0xc4430`: `new(0x38)` = 56B;`+0..+0xC` 拷贝 bounds;`+0x10/+0x14/+0x18/+0x1C` = 递归 RecCreate(四象限);set header `+0x24..+0x34` 清零,自引用 `+0x2C/+0x30 = &self+0x24` ✓
  - Node ctor `0xc42c6`: 相同模式(bounds 拷贝、children 清零、`+0x2C/+0x30 = a1+9` = &self+0x24);`+0x20`(a1[8]) 在 ctor 与 RecCreate 中均未写入 → UNKNOWN 字段命名合理 ✓
- 问题清单: 无。RBTree header 的 Ghidra 拆分(nSet_pad@+0x24 处 4B = key_compare+pad)与 std::_Rb_tree 布局(key_compare 1B+pad、color、parent、left、right = 20B)一致。

---

### QuadTreeNode
- 状态: **PASS**(附带 types_common.h 文档不一致提示)
- Ghidra 大小: 176B | 文档大小: 176B (0xB0) | 匹配: yes
- 字段比对: 与 tier3-b-map.md 完全一致;与 types_common.h 字段表存在 4B 偏移差异(见问题清单):

| 偏移 | Ghidra | tier3-b-map.md | types_common.h |
|---|---|---|---|
| +0x00 | pBase byte[148] | SceneGraphNode base 148B | base[148] |
| +0x94 | pRootNode (void*) | pRootNode | pRootNode |
| +0x9C | nSet_pad/color + pSet_parent/left/right (20B) | set\<SceneGraphNode*\> RBTree 20B @ +0x9C | `set[5]`(字段表隐含 @ +0x98) |
| 总大小 | 176B | 176B | 注释 0xB0 ✓ |

- 证据:
  - ctor `0xc4a52`: `SceneGraphNode::SceneGraphNode(this)`(base @ +0);`*thisa = off_456478`(vtable @ +0,与报告 0x456478 一致);set header `+0x9C..+0xAC` 清零,自引用 `+0xA4/+0xA8 = &self+0x9C`(即 RBTree parent@+8、left@+0xC);`+0x94 = Node::RecCreate(min(-2048,-2048), max(2048,2048), 8)`(pRootNode)✓ 与报告逐字段吻合。
- 问题清单:
  - **Ghidra 布局本身正确**(176B、pRootNode@+0x94、set@+0x9C 与 ctor 证据完全一致,且比 types_common.h 更精确)。
  - **types_common.h 第 455 行字段表有内部不一致**: `{ uint8_t base[148]; void* pRootNode; int32_t set[5]; }` 按字段求和 = 0xAC(172B),隐含 set @ +0x98,与注释 `// 0xB0`(176B)矛盾;实际证据 set @ +0x9C(中间 4B 为 RBTree key_compare+pad,Ghidra 已以 `nSet_pad` 正确表达)。建议修正文档为 `base[148]; pRootNode; nSet_pad[4](或 UNKNOWN_0x98); set[5]`。
  - 此为文档问题,非 Ghidra 回写问题。

---

### AStarSearch_PathNode
- 状态: **PASS**
- Ghidra 大小: 52B | 文档大小: 52B (0x34) | 匹配: yes
- 字段比对: 全部一致:

| 偏移 | Ghidra | types_common.h / tier3-b-map.md |
|---|---|---|
| +0x00 | pVtable (void*) | pVtable |
| +0x04 | nStatus (int) | nStatus |
| +0x08 | pOpenSet byte[12] | openSet vector\<sNode*\> |
| +0x14 | pClosedSet byte[12] | closedSet vector\<sNode*\> |
| +0x20 | pParams (void*) | pParams (PathfinderParams*) |
| +0x24 | pPath byte[12] | path vector\<PathNode\> |
| +0x30 | flSearchTime (float) | flSearchTime |

- 证据:
  - StartSearch `0x64214`: `a1[1] = 0`(+0x04 nStatus);`a1[8] = a2`(+0x20 pParams);`a1[12] = 0`(+0x30 flSearchTime);`std::vector<...sNode*>::push_back(a1+2, &v4)`(openSet @ +0x08);sNode `new(0x18)` = 24B ✓ 与报告一致。
  - pVtable @ +0 未被 StartSearch 直接写,但 D0/D1 存在且 ulong 实例同布局 +0 = 0x464654(报告证据),无冲突。
- 问题清单: 无。byte[12] 与 vector(3×void*)表示等价。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| Maze | PASS | 无(命名差异 nEMazeType/nGroundType vs eMazeType/groundType,偏移一致) |
| QuadTreeNode_Node | PASS | 无 |
| QuadTreeNode | PASS | types_common.h 字段表缺 4B pad(set 实际 @ +0x9C,文档字段表隐含 +0x98);Ghidra 布局本身与 ctor 证据完全一致 |
| AStarSearch_PathNode | PASS | 无 |

## 结论
四个类型全部通过,大小与 tier3-b-map.md 基准(44B / 56B / 176B / 52B)逐一匹配,关键偏移均经 IDA decompile(ctor/使用函数)交叉验证,无字段错位、无类型/偏移错误。唯一发现是 `types_common.h` 中 QuadTreeNode 字段表与自身大小注释的内部不一致(非 Ghidra 回写问题),建议后续修正文档。
