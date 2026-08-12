# Review Slice 25 — cPhysicsComponent / EnvelopeComponent / cImageComponent / cSoundEmitterComponent

> 二进制:`dontstarve_steam`(macOS i386, base 0x1000)
> 审查范围:Ghidra 回写 struct 布局 vs `tier2-components.md` + `types_common.h`(cEntityComponent 基类)
> 方法:get_struct_layout 读取 + ctor/dtor 反编译交叉验证 + 原始反汇编抽查(每类型 decompile ≤2)
> 注意:idalib-mcp 会话 f9cdc808 **不可达**(server_health: Session not found;idb_list: 0 sessions),IDA 交叉验证不可用,改用 ghidra-mcp decompile_function/disassemble_function 完成同等验证。
> 另注:`types_common.h` 中**无**这 4 个 struct 的定义(仅含 cEntityComponent 基类),故文档基准为 tier2-components.md。

---

### cPhysicsComponent
- 状态: PASS
- Ghidra 大小: 108B | 文档大小: 108B | 匹配: yes
- 字段比对: 全部一致。Ghidra: base(16B) + pTransformComponent@16, flRadius@20, flMass@24, flHeight@28, flStationaryDamping@32, pPhysicsWorldSim@36, nECollisionShape@40, flFriction@44, flMotorVelX/Y/Z@48/52/56, flSavedMotorVelX/Y/Z@60/64/68, pRigidBody@72, pCollisionShape@76, pCompoundShape@80, pMotionState@84, flRestitution@88, bActive@92, bDontRemoveOnSleep@93, pad@94, dwCollisionFlags@96, nCollisionMask@100, nCollisionGroup@102, wPristineFlags@104, wDirtyFlags@106。与 tier2(108B、27 字段、+72/+76/+80/+84 四个对象指针)完全对应。
- 证据:
  - ctor @ 0x6770c 原始反汇编逐字段核对,全部写操作落在 struct 偏移上:+0x14=0x3f800000(flRadius=1.0f)、+0x1C=1.0f(flHeight)、+0x2C=1.0f(flFriction)、+0x58=0x3f000000(flRestitution=0.5f)、+0x5C=1(bActive)、+0x5D=0(bDontRemoveOnSleep)、+0x64 dword 0x10000 = nCollisionMask(低16位 0)+nCollisionGroup(高16位 1)、+0x48/0x4C/0x50/0x54 四个指针清零。tier2 记载的关键常量 1065353216=1.0f、1056964608=0.5f、0x10000 全部吻合。
  - dtor @ 0x67936:若 pRigidBody(+0x48) 非空,先经 pPhysicsWorldSim(+0x24) 从物理世界移除再经 vtable+8 释放;pCollisionShape(+0x4C)/pCompoundShape(+0x50)/pMotionState(+0x54) 均经 vtable+4 释放。与 tier2 "+72/+76/+80/+84 对象指针经 vtable 释放" 一致。
- 问题清单: 无(仅风格提示:基类字段命名为 `pBase_cEntityComponent` byte[16] 而非 typed cEntityComponent,布局等价;不构成问题)。

---

### EnvelopeComponent
- 状态: PASS
- Ghidra 大小: 28B | 文档大小: 28B | 匹配: yes
- 字段比对: 全部一致。Ghidra: cEntityComponent base(16B) + pVecEnvelopes_begin@16 / end@20 / cap@24。与 tier2 布局表 `+0x10/+0x14/+0x18` 完全对应。
- 证据:
  - ctor @ 0x348fc:基类构造 + vtable(`PTR__EnvelopeComponent_00454be8`) + vec begin/end/cap 三指针清零。与 tier2 "基类 + vtable + this+4/5/6 = vec 头" 一致。
  - dtor @ 0x3496c:遍历 pVecEnvelopes_begin..end,每元素为 4B uint(hash),调用 `EnvelopeManager::DeleteEnvelope(hash)`,随后 `operator_delete(begin)`。与 tier2 "vec 存 Envelope hash(uint),经 EnvelopeManager::DeleteEnvelope 释放" 逐字吻合。
- 问题清单: 无

---

### cImageComponent
- 状态: PASS
- Ghidra 大小: 20B | 文档大小: 20B | 匹配: yes
- 字段比对: 全部一致。Ghidra: cEntityComponent base(16B) + pTexture@16(void*)。与 tier2 布局表 `+0x10 pTexture` 完全对应。
- 证据:
  - ctor @ 0x3d31c:基类构造 + vtable(`PTR__cImageComponent_00454e28`) + pTexture 清零。
  - dtor @ 0x3d370:pTexture 非空时 `(**(code **)(*pTexture + 0x18))(pTexture)` 释放,即经对象 vtable+24 释放 Texture。与 tier2 "this+4 (+16) 对象指针,经 vtable+24 释放" 一致。
- 问题清单: 无

---

### cSoundEmitterComponent
- 状态: WARN(布局/大小正确,字段命名与容器语义有改进空间)
- Ghidra 大小: 84B | 文档大小: 84B | 匹配: yes
- 字段比对: 大小一致;Ghidra 字段为 base(16B) + pVtable@16 + nField_0x14..nField_0x50(16 个 int,@20..80)。tier2 未给逐字段名,仅要求 84B 与 `+52/56` vec 头观察,均满足。
- 证据:
  - ctor @ 0x7610a:基类 + vtable(`PTR__cSoundEmitterComponent_00455ae8`) + 各字段清零;`nField_0x34`(+52) 与 `nField_0x38`(+56) 均被置为 `&nField_0x2C`(+44)。与 tier2 "+52/56 哨兵指向 &+44" 观察一致。
  - dtor @ ~0x76252(vtable 0x455ae8 的 [DATA] xref 定位):揭示真实容器结构 ——
    - +16/+20(`pVtable`/`nField_0x14`)= `FMOD::Event*` 数组 begin/end,dtor 逐个 `FMOD::Event::release` 后 `operator_delete(pVtable)`;
    - +28..+39(`nField_0x1C` 起)= `std::vector<std::string>`(begin@28/end@32/cap@36),dtor 调 `~vector(&nField_0x1C)`;
    - +40..+63(`nField_0x28` 起,24B)= `std::map<cHashedString, FMOD::Event*>` 内嵌 RBTree 头:header 哨兵 @ +44(color@44, parent@48, left@52, right@56, count@60),空树约定 left/right = &header —— 与 ctor 写 `+52=+56=&+44` 吻合;dtor 以 `&nField_0x2C` 为 end 哨兵迭代并 `_M_erase(&nField_0x28)`;
    - +64(`nField_0x40`)= bool 标志(非 0 时 StopAllNamedSounds + 释放事件);
    - +68/+72(`nField_0x44`/`nField_0x48`)= 两个堆上 `vector<DirtyEventInfo>` 指针,dtor `~vector` + `operator_delete` 各自释放;
    - +76(`nField_0x4C`)= 0x3f800000 = 1.0f(float);+80(`nField_0x50`)= 0。
    所有偏移/大小与 Ghidra struct 完全一致,无字段错位。
- 问题清单:
  1. 字段名 `pVtable`@+16 有误导性:该类的实际 vtable 在 +0(cEntityComponent base),+16 实为 `FMOD::Event*` 数组 begin(+20 为 end),建议改名(如 pEventArray_begin)。
  2. 三个容器区域(+28 vector<string>、+40 map<cHashedString,FMOD::Event*>、+68/+72 vector<DirtyEventInfo>*)仅以 `nField_*` int 表示,布局正确但语义未标注,建议后续按容器类型细化。
  3. tier2 报告把 +52/+56 哨兵解释为 "vec 头 + 内联缓冲",实际为 std::map 内嵌 RBTree header 的空树约定(观察事实正确,语义解释需修正为 map)。
  4. `nField_0x40` 实为 bool、`nField_0x4C` 实为 float 1.0f,类型可细化。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| cPhysicsComponent | PASS | 无;ctor 原始反汇编 + dtor 逐字段核对全部吻合,108B/27 字段/4 对象指针位置正确 |
| EnvelopeComponent | PASS | 无;28B,vec begin/end/cap @ +16/+20/+24,ctor/dtor 行为与 tier2 一致 |
| cImageComponent | PASS | 无;20B,pTexture@+16,dtor 经 vtable+24 释放确认 |
| cSoundEmitterComponent | WARN | 布局/大小正确(84B,ctor 哨兵 +52/+56=&+44 确认);仅命名/语义问题:pVtable@+16 实为 Event 数组 begin、+28 vector<string>、+40 map<cHashedString,FMOD::Event*>、+68/+72 vector<DirtyEventInfo>* 未标注,tier2 "内联缓冲" 解释应修正为 map 内嵌 header |

## 备注
- IDA 会话不可达(见文件头),交叉验证改用 Ghidra decompile(每类型 ≤2 次:physics 2+disasm 1、Envelope 2、cImage 2、cSoundEmitter 2),证据强度等价。
- 4 个 struct 在 Ghidra 根路径各仅一份定义,无重复/冲突(/Demangler 下的同名条目为 demangler 工件,size 1,非 struct 定义)。
- 本报告只读,未对 Ghidra/IDA 做任何写入。
