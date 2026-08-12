# Review 分片 7 — DontStarveInputHandler / MapComponentBase / MapComponent / MapGenSim

> 对照文档:`docs/superpowers/../../3rd/dst/game_decompiler/types_common.h`(§447/§450-452)、`tier3-c-input.md` §2/§2.1(DontStarveInputHandler/ControlMapper)、`tier3-b-map.md` §1-§3。
> 交叉验证:idalib-mcp(decompile 0x44f2c / 0x4ac0c / 0x1d4a4 / 0x208d8,会话 f9cdc808)+ ghidra-mcp(disassemble 0x1b208、get_struct_layout)。
> 只读审查,未做任何写入。Ghidra 回写目标为根分类同名 struct(`/DontStarveInputHandler` 等),`/Demangler/` 下占位符均未动。

---

### DontStarveInputHandler
- 状态: **FAIL**
- Ghidra 大小: 708B (0x2C4) | 文档大小: 720B (0x2D0,tier3-c-input.md;types_common.h 注 `~0x2C4`) | 匹配: no
- 字段比对(不一致项):
  - **三个 Lua ref 偏移整体 -4 错位**:struct 中 `nRefOnInputKey@0x24 / nRefOnMouseButton@0x28 / nRefOnMouseMove@0x2C / nField_0x30@0x30`,而 C2 反汇编 0x1b25c/0x1b263/0x1b26a 写 `-2 (0xFFFFFFFE)` 于 **0x28 / 0x2C / 0x30**(紧随 mInitVec[16]@0x18 之后);types_common.h 亦为 0x28/0x2C/0x30。struct 沿用了 tier3-c-input.md 的 -4 偏移行(tier3-c-input.md 自身与二进制冲突:mInitVec 16B@0x18 与 nRefOnInputKey@0x24 重叠,引用证据 0x1b25c 的操作数实为 0x28)。
  - **mInitVec[16] @ +0x18 缺失**:C2 0x1b258 `MOVUPS xmmword ptr [ESI+0x18]`(xmmword_3B84F0);struct 0x18..0x24 无定义。
  - **oControlMapper 子对象(516B,+0x44..0x247)未写入**:C2 0x1b366 `ControlMapper(ECX=ESI+0x44, arg1=ESI+0x248, arg2=inputMgr)`;struct 中 0x44..0xA0(0x5C)与 0x132..0x248 完全未定义;嵌套类型 `/Demangler/DontStarveInputHandler/ControlMapper` 仍为 1B 占位(§2.1 建议新建嵌套 516B,未执行)。
  - **bWheelState[6] @ +0x1E1、bState[3] @ +0x242 缺失**(tier3-c-input.md 表末两行,DEV_GetKeyState 0x1d59e/0x1d5a9/0x1d5cd 证据)。
  - **尾部 3×int @ +0x2C4 / +0x2C8 / +0x2CC 缺失**:C2 0x1b381/0x1b38b/0x1b395 均写 0;struct 以 0x2C4 结束 → 大小 708 vs 720(嵌入证据:cDontStarveSim @+0x1A4 后接字段 @0x474,0x1A4+0x2D0=0x474 ✓)。
- 证据(已定义字段逐项核对正确):
  - C2 0x1b208:0x22c `vptr=0x4549F8` ✓(EBP 基址 0x1b217+0x4397e1);+4/+8/+0xC = cGame 派生指针 ✓;+0x10/+0x14 = 0 ✓;0x1b45e `reserve(ESI+0x34, 0x49=73)` → vecControls@0x34 ✓(struct 正确);0x1b2c4 `LEA EDI,[ESI+0x248]` → oMappingStorage@0x248 ✓(124B:0x248..0x2C4)。
  - idalib decompile 0x1d4a4 `GetPosition`:`*(a2+160)=flMouseX@0xA0`、`*(a2+164)=flMouseY@0xA4` ✓(struct 偏移正确;注意 0xA0 位于 ControlMapper 子对象 +0x5C 处,即鼠标/按键数组实为 ControlMapper 内部字段,struct 按直接字段定义仅偏移碰巧一致)。
  - idalib decompile 0x208d8 `ControlMapper::ControlMapper`:thisa+0x00=pMappingStorage(arg1=0x248)、+0x0C=73、+0x10=5、+0x08=MaxDeviceId、+0x14/+0x1C=qword、+0x24=-1、+0x28 byte=0、+0x2C=this、+0x30=OnControlMapped(文档 §2.1 表一致;仅 +0x30 文档标注 "pGlobal2" 实为回调指针,标签级差异)。
- 问题清单:
  1. [严重] ref 三字段 + nField_0x30 偏移整体 -4(0x24/0x28/0x2C/0x30 vs 二进制 0x28/0x2C/0x30/—,0x34 实为 vecControls.begin);nField_0x30 在二进制中不存在。
  2. [严重] mInitVec[16]@0x18 缺失(0x18..0x24 悬空)。
  3. [严重] oControlMapper 516B 子对象未定义(0x44..0xA0、0x132..0x248 两段空白;嵌套类型未建)。
  4. [中等] bWheelState[6]@0x1E1、bState[3]@0x242 缺失。
  5. [严重] 尾部 3×int @0x2C4/0x2C8/0x2CC 缺失 → 大小 708 vs 720(与 cDontStarveSim 嵌入 0x474 不符)。
  - 已定义字段(vptr..pLuaState、vecControls@0x34、flMouseX/Y、bMouseDown/Pressed、bKeys[128]@0xB2、oMappingStorage@0x248)偏移均正确。

---

### MapComponentBase
- 状态: **PASS**
- Ghidra 大小: 304B | 文档大小: 304B | 匹配: yes
- 字段比对: `base cEntityComponent[16]@0x00`、`UNKNOWN_0x10[232]@0x10..0xF8`、`vecRenderLayers[12]@0xF8`、`vecTiles[12]@0x104`、`bUndergroundLayer@0x110`、`pMapRenderer@0x114`、`mapTileCount[5]@0x11C`(20B)→ 与 types_common.h 逐字段一致;切片文档细字段(+0x60 nField、+0xA8/+0xB4 指针、+0xC8 AABB、+0xE0/+0xE4 TileGrid、+0xE8 LayerManager、+0xEC vec、+0x11C RBTree)全部落在 UNKNOWN blob 范围内,无冲突。
- 证据: MapComponent ctor 0x44f2c 首指令 `MapComponentBase::MapComponentBase(this)` 后即写 0x130 起自有字段 → 基类嵌入 304B(0x130)正确;bUndergroundLayer@0x110 = 272、pMapRenderer@0x114 = 276、map@0x11C..0x130 与切片文档 `+0x130 = MapComponent 起点` 吻合。
- 问题清单: 无 struct 级问题。文档级备注:tier3-b-map.md 将 `nField_0x60` 标为 +0x60,但其引用的证据 `ctor *(thisa+23)=1`(0x47055)实为字节偏移 92=0x5C(4B 偏差),位于 UNKNOWN blob 内,不影响回写结果。

---

### MapComponent
- 状态: **WARN**
- Ghidra 大小: 397B | 文档大小: 400B | 匹配: no(差 3B 尾部对齐 padding)
- 字段比对: 16 个自有字段偏移与切片文档逐项一致:0x130 nNumWalkableTiles、0x134 nNumUndergroundTiles、0x138 mMat4_0[16]、0x148 mMat4_1[16]、0x158 flColorScale[4]、0x168 bInitialized、0x16C pNavGrid、0x170 pMapRenderer、0x174 pWaveComponent、0x178 pRoadManager、0x17C pGroundCreep、0x180 ppNetworkTileRegions、0x184 nField、0x188 flField、0x18C bFinalized;基类嵌入 MapComponentBase 304B@0x00 ✓。
- 证据: idalib decompile 0x44f2c `MapComponent::MapComponent`:`+76/+77=0`(0x130/0x134)、`OWORD@312/@328 = xmmword_3C84C0`(0x138/0x148)、`+86..+89=1065353216`(0x158..0x164,1.0f)、`byte@360=0`(0x168)、`+91..+96=0`(0x16C..0x180)、`+98=1048576000`(0x188,0.25f)、`byte@396=0`(0x18C)、`+97=8388672=0x800040`(0x184)、vptrs 0x455008/0x455074/0x455090;全部与 struct 偏移吻合。
- 问题清单:
  1. [中等] 大小 397 vs 400:Ghidra struct Alignment=1,`bFinalized`@0x18C(1B)后无 3B 尾部 padding → 0x190 对齐缺失。文档按 304B 基类 + 96B 自有 = 0x190;若代码以 sizeof/Pool 分块 0x190 分配,当前 397B 会差 3B。
  2. 无字段错位;+0x138/+0x148 Mat4、+0x188 0.25f 语义未定(文档已知 UNKNOWN,非本次问题)。

---

### MapGenSim
- 状态: **PASS**
- Ghidra 大小: 92B | 文档大小: 92B | 匹配: yes
- 字段比对: `base cEntityComponent[16]@0x00`、`pWorld@0x10`、`nField_0x14@0x14`、`nCollObjCount@0x18`、`nCollObjCap@0x1C`、`pCollObjs@0x20`、`bAlignedAlloc@0x24`、`pBroadphase@0x28`、`pDispatcher@0x2C`、`pSolver@0x30`、`pConfig@0x34`、`vecNodes 12B@0x38`、`pShapeBox@0x44`、`pShapeTri@0x48`、`pShapeCylinder@0x4C`、`vecConstraints 12B@0x50` → 与 types_common.h/切片文档逐项一致;大小 0x5C 与 `Pool<MapGenSim>::sChunk` new(chunkSize*0x5C)@0x929be 证据吻合。
- 证据: idalib decompile 0x4ac0c `MapGenSim::MapGenSim`:`vptr=0x4551B8` ✓、`byte@36=1`(0x24 bAlignedAlloc)✓、`+8/+6/+7=0`(0x20/0x18/0x1C)✓、`+14/+15/+16=0`(0x38/0x3C/0x40 vecNodes)✓、`+20/+21/+22=0`(0x50/0x54/0x58 vecConstraints)✓、+0x14 未写(与文档 "ctor/InitPhysics 均未写" 一致)✓。
- 问题清单: 无。

---

## 汇总表

| 类型 | 状态 | 主要问题 |
|---|---|---|
| DontStarveInputHandler | FAIL | ref 三字段偏移 -4(0x24/28/2C/30 vs 0x28/2C/30);mInitVec[16]@0x18、oControlMapper 516B 子对象(+0x44)、bWheelState[6]@0x1E1、bState[3]@0x242、尾部 3×int@0x2C4-0x2CC 均缺失;大小 708 vs 720 |
| MapComponentBase | PASS | 无(struct 与 types_common.h 完全一致) |
| MapComponent | WARN | 字段偏移全部正确;大小 397 vs 400(缺 3B 尾部对齐 padding,Alignment=1) |
| MapGenSim | PASS | 无(92B,ctor 0x4ac0c 逐项验证) |
