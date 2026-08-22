# Review Slice 1 — cEntityManager / cEntity / cSimulation / cGame

> 二进制:`dontstarve_steam`(macOS i386 32位)
> 工具:ghidra-mcp(get_struct_layout)+ idalib-mcp 会话 f9cdc808(decompile / type_inspect)
> 参照:docs/superpowers/../../3rd/dst/game_decompiler/types_common.h + tier0-core.md(+ tier1-luaproxy.md 的 CheckPointer 互证)
> 方式:只读。Ghidra 布局 vs 文档 vs IDB 基准(cEntity 39 成员/252B)三方比对;ctor 反编译交叉验证

---

### cSimulation
- 状态: **PASS**
- Ghidra 大小: 412B | 文档大小: 412B (0x19C) | 匹配: yes
- 字段比对: 无不一致。Ghidra 104 字段与 types_common.h 逐字段一致(含 0x39/0x55/0x87/0x175/0x18D/0x195 padding、双 Mutex@0x94/0xD8、pMapHashedStringUint[24]@0x110、13 个 nRef*@0x128-0x158、pVecUnknown17C@0x17C)
- 证据:
  - IDA ctor `0xf71d2`:0x00 vtable = 0x456728 ✓;0x1C vtable2 = 0x45675C ✓;0x08/0x24 RBTree 锚点自指 ✓;0x3C flTimeScale = 1.0f ✓;0x40 pEntityManager = operator new(0x138) ✓;0x5C pGame = a3 ✓;0x6C flTimeStep = 0.001f ✓;0x74 nField_0x74 = -1 ✓;0x48 cSimTime 子对象 ✓;0x88-0x90 / 0xCC-0xD4 两组 vec 头 + Mutex×2 ✓;0x110-0x124 hash_map 头(0x11C/0x120 自指)✓;0x128-0x158 nRef 块 = -2 ✓;0x170 pBPWorld = new(0x34) ✓;0x194 bUseThreadedPhysics = 1 ✓;0x198 flProfilerTime ✓
  - CheckPointer `0x315e2` 间接确认:pEntityManager@0x40(`*(v2+64)`)、nSimStep@0x44(`*(v2+68)` 作版本快照)、pLuaState@0x58(`v3+88`)
- 问题清单: 无

### cGame
- 状态: **PASS**
- Ghidra 大小: 304B | 文档大小: 304B (0x130) | 匹配: yes
- 字段比对: 仅命名微差 `pVecPrefabs_capacity`(Ghidra)vs `pVecPrefabs_cap`(文档),偏移/类型一致;19 个 pPerf* 指针块 0xDC-0x124 与文档 pPerf[19] 一致
- 证据:
  - 间接验证(cSimulation ctor `0xf71d2`):`*(v8+96)` = pGame+0x60 → cEventDispatcher<cGameEvent>::RegisterListener ✓;`*(v8+296)` = pGame+0x128 → cEventDispatcher<SystemEvent>::RegisterListener ✓(与文档 pGameEventDispatcher@0x60 / pSystemEventDispatcher@0x128 吻合)
  - 文档 vtable 0x4567d8(tier0 已验,本次未重复 decompile)
- 问题清单: 无(仅命名风格差异,不构成错误)

### cEntityManager
- 状态: **WARN**
- Ghidra 大小: 309B (0x135, alignment=1) | 文档大小: 309B | 匹配: yes(见问题3 的 sizeof 注记)
- 字段比对:
  - `pSimulation@0x0C`:Ghidra 类型 **-BAD-**(悬空数据类型的坏引用),文档/IDA 应为 `cSimulation*`(类型缺失,偏移正确)
  - vec 块命名边界不一致:文档 `componentLists_begin@0x14`,Ghidra 无该字段、首个字段为 `dwComponentLists_end@0x14`;文档注释 "×9" 但列出 10 组名字,且 `wallUpdateTypes_begin@0x1C` 与 `componentLists_cap@0x1C` 在文档内自相重叠。偏移跨度(0x14-0x84→pComponentFactory@0x88)双方一致
  - 其余字段全部一致:Mutex@0x8C、nField_0xC4/C8/CC、pEntityPool[40]@0xD0、pSpatialHash@0xF8、nUiRootGuid@0xFC、entityPositionMap RBTree@0x114、destroyedEntityPositions@0x128、bIsProcessingNewEntities@0x134
- 证据:
  - IDA ctor `0xd2796`:0x00 vtable = off_456624 ✓;0x04 计数=0 ✓;0x0C pSimulation = a3 ✓;0xD0 `Pool<cEntity,FakeLock>::Pool(this+208, 100)` ✓;0xFC nUiRootGuid = -1 ✓;0x104 flLastCameraPosition = KleiMath::Vector3 Zero ✓;0x114-0x124 RBTree 头(0x11C/0x120 自指)✓;0x128-0x130 destroyed 头=0 ✓;0x134 bIsProcessingNewEntities = 1 ✓;0xF8 pSpatialHash = new(0x28) ✓
  - **vec 块结构证据**:ctor 将 dword +4..+33(0x10..0x84,恰 30 个 dword = 10 vec × 12B)连续清零,止于 pComponentFactory@0x88 → 真实布局疑似 **10 个 vec 自 0x10 起**(componentLists_begin 实为 0x10,文档/Ghidra 均未正确建模);需以设置 componentLists begin 的函数做最终裁定
- 问题清单:
  1. `pSimulation@0x0C` 在 Ghidra 中类型为 -BAD-,需重建为 `cSimulation*`
  2. vec 块命名/计数不一致:文档 "×9"+ componentLists_begin@0x14 与 Ghidra "无 begin" 相互矛盾;ctor 证据指向 10 vec @ 0x10-0x84,建议以该证据为准统一(涉及 componentLists_begin@0x10 是否建模)
  3. 大小注记:Ghidra/文档记 309B(0x135,未对齐),但 IDA ctor `operator new(0x138)` 表明 C++ sizeof = **312B(0x138,4 字节对齐)**;Ghidra struct alignment=1 偏小
  4. 文档 vtable 记 "0x4567d8 附近",实际 ctor 写入 0x456624(cEntityManager 自身 vtable)

### cEntity
- 状态: **FAIL**(偏移/大小/关键槽全部正确,但 2 组字段名与 IDB 基准互换 + 若干基准外的臆测命名)
- Ghidra 大小: 252B | 文档大小: 252B (0xFC... 0xFC=252, 39 成员基准) | 匹配: yes
- 字段比对(基准 = IDB cEntity 39 成员定义,即文档声明的"恢复基准";type_inspect 实测):
  - **0x50/0x54 互换**:Ghidra `pUINode@0x50 / pWorldNode@0x54`;IDB+文档 `worldNode@0x50 / UINode@0x54`
  - **0xD4/0xD8 互换**:Ghidra `pTransformComponent@0xD4 / pNetworkComponent@0xD8`;IDB `networkComponent@0xD4 / transformComponent@0xD8`
  - **0xF4 命名冲突**:Ghidra `bRetired` vs IDB `disableUnregisterLuaNetVars`
  - 基准为 unknown 处 Ghidra 臆测命名:0x59 `bSelected`(IDB unknown_0x59)、0xA8 `dwPristineTagHashes`(field_0xa8)、0xCA `bCanSleep`、0xCB `bClickable`、0xCC `bInlimbo`、0xCF `bAllComponentsCanSleep`(IDB unknown_0xca/cb/cc/cf)、0xE4 `dwBBoxProvider`(field_0xe4)、0xF8 `dwSleepCheckState`(field_0xf8)
  - 类型质量:Ghidra 大量指针字段退化为 dword(dwName/dwPrefab/dwGameStep/dwNet_dirty_flags 等),文档/IDB 有完整类型(char*/uint32/cHashedString/StdVector*);0x40 类型名 `cDontStarveSim*` 与文档/IDB `cSimulation*` 不一致(同一类型两名)
  - 其余一致:guid@0x04、prefabNameHash@0x10、children@0x18、parentEntity@0x24、followerComponents(RBTree 24B)@0x28、vec_components@0x44、tagset[72]@0x60、luaNetVarsMap@0xAC、dirty_flags@0xC4、worldposition@0xE8
- 证据:
  - **+0xDC 关键验证通过**:Ghidra `pAnimStateComponent@0xDC`(220);IDB `animStateComponent@0xdc (cAnimStateComponent*)`;Tier1 CheckPointer `0x315e2`:`*(EntityByGUID + 220)` 刷新代理组件槽 = cEntity 组件索引槽 ✓ 三方互证一致
  - GetEntityByGUID `0xd309a`:按 `*(entity+4)`(guid)二分查找 allEntities,返回实体指针(支撑 CheckPointer 的 +220 访问)
- 问题清单:
  1. **0x50/0x54 字段名互换**(pUINode ↔ pWorldNode),与文档及 IDB 基准相反
  2. **0xD4/0xD8 字段名互换**(pTransformComponent ↔ pNetworkComponent),与 IDB 基准相反
  3. 0xF4 命名冲突:bRetired vs disableUnregisterLuaNetVars(IDB 为准)
  4. 8 处基准 unknown 字段被赋予未经验证的臆测名(bSelected/dwPristineTagHashes/bCanSleep/bClickable/bInlimbo/bAllComponentsCanSleep/dwBBoxProvider/dwSleepCheckState),建议回退为 unknown 命名直至有证据
  5. 指针字段类型退化为 dword、0x40 类型名 cDontStarveSim 与 cSimulation 不统一(类型质量,不影响偏移)

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| cSimulation | PASS | 无;IDB 无完整 struct,ctor 0xf71d2 逐字段验证通过 |
| cGame | PASS | 无实质问题(仅 pVecPrefabs_capacity/cap 命名微差);经 cSimulation ctor 间接验证 0x60/0x128 衔接 |
| cEntityManager | WARN | pSimulation@0x0C 类型 -BAD-;vec 块命名/计数与文档矛盾(ctor 证据:10 vec @ 0x10-0x84);sizeof 实为 0x138=312B 而非 309B;vtable 文档地址不准(实 0x456624) |
| cEntity | FAIL | 0x50/0x54 与 0xD4/0xD8 两组字段名互换(与 IDB 基准/文档相反);0xF4 bRetired 命名冲突;8 处臆测命名;指针类型退化为 dword。关键槽 +0xDC = pAnimStateComponent 三方互证通过 |
