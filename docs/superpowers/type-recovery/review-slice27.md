# Slice 27 Review — ComponentLuaProxy / SimLuaProxy / MapLuaProxy

> 二进制:`dontstarve_steam` (macOS i386, base 0x1000, 当前 Ghidra 程序 `dontstarve_steam`)
> 对照文档:`docs/superpowers/type-recovery/tier1-luaproxy.md` + `tier3-b-map.md` §15 + `ghidra-writeback-tier0.md` (Tier 1 回写表)
> 方法:ghidra-mcp `get_struct_layout` + `decompile_function` 交叉验证
> ⚠️ **idalib-mcp 不可用**:会话 f9cdc808 报 `Session not found`,`idb_list` 返回 0 会话;且 `idb_open` 不在只读白名单内 → 无法做 IDA 侧抽查。改用 Ghidra 只读 `decompile_function` 对同一批证据地址验证(0x30fde / 0xed356 / 0x48b00),结论等效。
> 注:共享 context 中「Review 清单」残留为 Mutex/cHashedString/cHashedStringCSL/cEntityComponent,与本任务 Target(ComponentLuaProxy/SimLuaProxy/MapLuaProxy)不符;以 Target 为准执行。

---

### ComponentLuaProxy
- 状态: **PASS**
- Ghidra 大小: 20B | 文档大小: 20B (0x14) | 匹配: yes
- 字段比对: 无实质差异。Ghidra `/ComponentLuaProxy`:
  - 0x00 `pVtable` (void*) / 0x04 `pComponent` (void*) / 0x08 `pSimulation` (void*) / 0x0C `dwGuid` (uint) / 0x10 `nVersionSnapshot` (int)
  - 文档(tier1 §1): 0x00 pVtable / 0x04 pComponent / 0x08 pSimulation / 0x0C guid / 0x10 versionSnapshot — 仅命名差异(`dwGuid` vs `guid`、`nVersionSnapshot` vs `versionSnapshot`),偏移与类型全同
- 证据: `ComponentLuaProxy<cAnimStateComponent,AnimStateLuaProxy>::Add` @ 0x30fde (Ghidra decompile):
  - `operator_new(0x14)` → 对象 20B ✓
  - `*(pAVar3) = PTR_vtable_0045018c + 8` → vtable @ +0 ✓
  - `*(pAVar3+4) = AddComponentToEntity<...>(...)` → pComponent @ +4 ✓
  - `*(pAVar3+8) = *(entity+0x40)` → pSimulation @ +8 ✓
  - `*(pAVar3+0xC) = *(entity+4)` → guid @ +0xC ✓
  - `*(pAVar3+0x10) = *(simulation+0x44)` → versionSnapshot @ +0x10 (0x44=68,与文档一致) ✓
  - 死路径(iVar2==0)写 +8=0/+0xC=0xFFFFFFFF/+0x10=0,与布局无冲突
- 问题清单: 无

### SimLuaProxy
- 状态: **PASS**
- Ghidra 大小: 20B | 文档大小: 20B (0x14) | 匹配: yes
- 字段比对: Ghidra `/SimLuaProxy`:
  - 0x00 `pSimulation` (cSimulation*) / 0x04 `nUNKNOWN_0x04` (int) / 0x08 `nField_0x08` (int) / 0x0C `bField_0x0C` (byte) / 0x10 `nField_0x10` (int)
  - 文档(tier1 §3): 0x00 pSimulation / 0x04 (未初始化) / 0x08 nField_0x08=-1 / 0x0C bField_0x0C=0 / 0x10 nField_0x10=-2 — 偏移/类型全同;+0x04 文档标注未初始化,Ghidra 以 `nUNKNOWN_0x04` int 占位,合理
  - padding: +0xC 为 1B byte,0xD–0xF 三字节空洞,0x10 收尾,总 20B,无错位
- 证据: `SimLuaProxy::SimLuaProxy` @ 0xed356 (Ghidra decompile): ctor 写 `nField_0x08 = -1`、`nField_0x10 = -2`、`pSimulation = 0`、`bField_0x0C = 0`;不写 +0x04 — 与文档表逐字段吻合(补充:文档表未列 ctor 写 pSimulation=0,实际有写,无冲突)
- 问题清单: 无(附注:ctor 实际置 pSimulation=0,建议 tier1 文档字段表可补充,非错误)

### MapLuaProxy
- 状态: **PASS**
- Ghidra 大小: 20B | 文档大小: 20B (0x14) | 匹配: yes
- 字段比对: Ghidra `/MapLuaProxy` 与基类 `ComponentLuaProxy` 完全同构:pVtable/pComponent/pSimulation/dwGuid/nVersionSnapshot(5×4B);文档(tier3-b-map §15)确认其为 `ComponentLuaProxy<MapComponent,MapLuaProxy>` 子类、无额外字段、布局沿用 tier1 模板 — 一致
- 证据: `MapLuaProxy::SetSize` @ 0x48b00 (Ghidra decompile): 调用 `ComponentLuaProxy<MapComponent,MapLuaProxy>::CheckPointer()`,通过 `this->pComponent`(+4)调 `MapComponentBase::SetSize(...)` — 与 tier3-b-map 记录逐字一致 ✓
- 问题清单: 无实质问题。附注:Ghidra 中 `/Demangler/MapLuaProxy`(1B)与 `/Demangler/ComponentLuaProxy<MapComponent,MapLuaProxy>`(1B)占位仍与新建的 `/MapLuaProxy` 20B 并存 — 与 EntityLuaProxy(/Demangler 1B + / 16B)同一惯例,Demangler 自动生成,不影响使用;如需整洁可后续清理(非本只读任务范围)

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| ComponentLuaProxy | PASS | 无;字段命名 dwGuid/nVersionSnapshot 与文档 guid/versionSnapshot 仅为命名差异 |
| SimLuaProxy | PASS | 无;+0x04 nUNKNOWN_0x04 合理占位;ctor 另写 pSimulation=0(文档未列,非错误) |
| MapLuaProxy | PASS | 无实质问题;Demangler 1B 占位并存(惯例,可清理) |

## 结论
三个 LuaProxy 类型在 Ghidra 中的 struct 布局(名称/偏移/类型/大小)与 tier1-luaproxy.md、tier3-b-map.md 文档完全一致,经 0x30fde(Add, operator new 0x14 + 5 字段初始化)、0xed356(SimLuaProxy ctor)、0x48b00(SetSize → CheckPointer + pComponent@+4)三处反编译交叉验证通过。无字段错位、无大小不匹配、无 padding 异常。IDA 侧因会话不可达未能抽查(只读约束禁止 idb_open),Ghidra 侧证据等价。
