# Review Slice 12 — DontStarveGameService / DontStarveSystemService / cNetworkLuaProxy / cAccountCommunication

> 二进制:`dontstarve_steam` (macOS i386, base 0x1000)
> 工具:ghidra-mcp (G, program `dontstarve_steam`) + idalib-mcp (I, session `f9cdc808`, healthy)
> 对照:`docs/superpowers/../../3rd/dst/game_decompiler/types_common.h` + `tier3-d-network.md` (§13/§14/§16/§20)
> 方法:get_struct_layout 读 Ghidra 现状 → 与 types_common.h / tier3-d-network.md 字段表比对 → ctor/dtor decompile 交叉验证(每类型 2 次,未超预算)
> 只读审查:未做任何写操作。

---

### DontStarveGameService

- 状态: PASS
- Ghidra 大小: 36B | 文档大小: 36B (0x24) | 匹配: yes
- 字段比对: 全部一致,无差异
  | Ghidra (offset/size/type/name) | 文档 (types_common.h + tier3-d §13) | 一致 |
  |---|---|---|
  | +0x00 / 4 / void* / pVtable | +0x00 pVtable | ✓ |
  | +0x04 / 4 / void* / pSystemService | +0x04 pSystemService (DontStarveSystemService*) | ✓ |
  | +0x08 / 4 / int / nField_0x08 | +0x08 nField_0x08 =0 | ✓ |
  | +0x0C / 4 / int / nField_0x0C | +0x0C nField_0x0C =0 | ✓ |
  | +0x10 / 20 / byte[20] / pM_achievements | +0x10 m_achievements std::map<cHashedString, AchievementId> (20B, header@+0x14) | ✓ |
- 证据: I ctor 0x1a3b2 — `*(DWORD*)thisa = &unk_4549E0` (vtable@+0);`+1 = a3` (pSystemService@+4);`+2/+3 = 0` (nField_0x08/0x0C);map 头初始化 `+4/+5/+6 = 0` 后 `+7/+8 = (char*)thisa+20` → 树基@+0x10、header@+0x14(left/right 自引用@+0x1C/+0x20),与文档 dtor `_M_erase(this+0x10)` 一致。byte[20] 覆盖 +0x10..+0x23 完整容器区。
- 问题清单: 无。(m_achievements 以 byte[20] 建模而非嵌套 map 结构,属建模精度问题,布局等价,不记为问题)

---

### DontStarveSystemService

- 状态: PASS
- Ghidra 大小: 164B | 文档大小: 164B (0xA4) | 匹配: yes
- 字段比对: 全部一致,无差异
  | Ghidra (offset/size/type/name) | 文档 (types_common.h + tier3-d §14) | 一致 |
  |---|---|---|
  | +0x00 / 4 / void* / pVtable | +0x00 pVtable | ✓ |
  | +0x04 / 4 / int / nField_0x04 | +0x04 nField_0x04 =0 | ✓ |
  | +0x08 / 4 / int / nField_0x08 | +0x08 nField_0x08 =0 | ✓ |
  | +0x0C / 4 / void* / pCacheMap | +0x0C pCacheMap std::map<...>* (堆 0x18) | ✓ |
  | +0x10 / 36 / byte[36] / pM_playerId | +0x10 m_playerId GameService::PlayerId (36B) | ✓ |
  | +0x34 / 4 / byte[4] / pFlags_0x34 | +0x34 4×bool ={0,1,1,1} | ✓ |
  | +0x38 / 4 / int / nField_0x38 | +0x38 nField_0x38 =4 | ✓ |
  | +0x3C / 4 / int / nField_0x3C | +0x3C nField_0x3C =7 | ✓ |
  | +0x40 / 84 / byte[84] / pCallbacks | +0x40..0x93 7×回调项 {obj,fn,0} 各 12B | ✓ |
  | +0x94 / 16 / int[4] / pLuaRefs | +0x94..0xA0 4×int = -2 | ✓ |
- 证据: I ctor 0x24116 — `*thisa = &unk_454A28` (vtable@+0);`+1/+2 = 0`;`PlayerId::PlayerId(this, thisa+16)` (36B@+0x10);`+13 = 16843008 (0x01010100)` → flags_0x34 4×bool {0,1,1,1} 逐字节吻合;`+14 = 4, +15 = 7` (nField_0x38/0x3C);回调 7 项 obj@+0x40/0x4C/0x58/0x64/0x70/0x7C/0x88、fn@+0x44/0x50/0x5C/0x68/0x74/0x80/0x8C、0@+0x48/0x54/0x60/0x6C/0x78/0x84/0x90(OnStoragePrepared→OnCacheFileSynchronized 顺序与文档一致);`+37..+40 = -2` (luaRefs@+0x94);`operator new(0x18)` + `v2[3]=v2[4]=v2+1` → pCacheMap@+0x0C 指向堆上 std::map 头,与文档一致。
- 问题清单: 无。

---

### cNetworkLuaProxy

- 状态: WARN
- Ghidra 大小: 32B | 文档大小: 32B (0x20, 报告标 ≥32B) | 匹配: yes
- 字段比对: 全部一致,无差异
  | Ghidra (offset/size/type/name) | 文档 (types_common.h + tier3-d §20) | 一致 |
  |---|---|---|
  | +0x00 / 4 / void* / pVtable | +0x00 pVtable | ✓ |
  | +0x04 / 4 / int / nField_0x04 | +0x04 UNKNOWN_0x04 (ctor 未写) | ✓ |
  | +0x08 / 20 / byte[20] / pMap_like_0x08 | +0x08 map_like_0x08 容器头部 (20B) | ✓ (建模一致,语义存疑) |
  | +0x1C / 4 / void* / pNetworkContext | +0x1C pNetworkContext | ✓ |
- 证据: I ctor 0x18e4f6 — `*a1 = &unk_457188` (vtable@+0);+4 未写 (UNKNOWN_0x04);容器头初始化 `a1[2..6] = 0`(+8/+0xC/+0x10/+0x14/+0x18)后 `a1[4] = a1[5] = a1+2` → left@+0x10 = right@+0x14 = &this+8,**std::map 头初始化模式**(树基@+8, header@+8, count@+0x18);`a1[7] = *(*(cNetworkManager::mInstance[0]+0x110)+0x20)` (pNetworkContext@+0x1C)。I dtor 0x18e724 — 仅 vtable 回写 + Log + `cEventListener<SystemEvent>::~cEventListener(thisa)`,**无 `_M_erase`/容器清理** → +0x08 容器从未按 map 使用/销毁,与 tier3-d §20 未解决项一致。
- 问题清单: +0x08 `map_like_0x08` 具 std::map 头初始化模式但 dtor 不擦除、全生命周期无插入/查找证据,容器语义存疑(可能为 tClientProxy 列表变体容器或未用字段),标 UNKNOWN — 按任务要求标 WARN。布局本身(偏移/大小/类型)与文档完全一致。

---

### cAccountCommunication

- 状态: WARN
- Ghidra 大小: 193B | 文档大小: 196B (0xC4) | 匹配: **no** (差 3B 尾部 padding)
- 字段比对: 全部字段偏移/类型一致,仅结构总大小差 3B
  | Ghidra (offset/size/type/name) | 文档 (types_common.h + tier3-d §16) | 一致 |
  |---|---|---|
  | +0x00 / 4 / void* / pVtable | +0x00 pVtable | ✓ |
  | +0x04 / 44 / byte[44] / pM_netId | +0x04 m_netId cNetID2 (44B) | ✓ |
  | +0x30 / 1 / byte / bField_0x30 | +0x30 bField_0x30 =0 | ✓ |
  | +0x34 / 16 / byte[16] / pStrs | +0x34..0x40 4×std::string | ✓ |
  | +0x44 / 4 / int / nField_0x44 | +0x44 nField_0x44 =0 | ✓ |
  | +0x48 / 56 / Mutex / Mutex | +0x48 Mutex (56B) | ✓ |
  | +0x80 / 40 / byte[40] / pM_accountEvents | +0x80 m_accountEvents std::deque<AccountEvent> (40B) | ✓ |
  | +0xA8 / 4 / void* / pAccountManager | +0xA8 pAccountManager | ✓ |
  | +0xAC / 4 / int / nField_0xAC | +0xAC nField_0xAC =0 | ✓ |
  | +0xB0 / 4 / int / nField_0xB0 | +0xB0 nField_0xB0 =0 | ✓ |
  | +0xB4 / 4 / int / nField_0xB4 | +0xB4 nField_0xB4 =0 | ✓ |
  | +0xB8 / 8 / Timer / Timer | +0xB8 Timer (8B) | ✓ |
  | +0xC0 / 1 / byte / bField_0xC0 | +0xC0 bField_0xC0 =0 | ✓ |
  | (无) | +0xC1..0xC3 尾部 padding 3B (文档 0xC4=196B) | ✗ 缺失 |
- 证据: I ctor 0x142070 — `*thisa = &unk_456D68` (vtable@+0);`cNetID2::Clear(this)` (44B@+4, 与 §16 证据 cNetID2::Clear@0x1623a2 一致);`*thisa+48 = 0` (bField_0x30@+0x30);4×`std::string(..., thisa+52/56/60/64, "")` (strs@+0x34..0x40);`+17 = 0` (nField_0x44@+0x44);`Mutex::Mutex` (56B@+0x48);`deque<AccountEvent>::deque(thisa+32)` (+0x80, 40B);`+42 = a3` (pAccountManager@+0xA8);`+43/+44/+45 = 0` (nField_0xAC/0xB0/0xB4);`Timer::Timer(thisa+184)` (@+0xB8);`*thisa+192 = 0` (bField_0xC0@+0xC0)。I dtor 0x142302 — deque@+0x80 + Mutex@+0x48 + 4 string@+0x34..0x40 销毁,**无任何 > +0xC0 的访问** → 缺失 3B 纯尾部 padding,无字段错位。
- 问题清单: Ghidra 中结构总大小 193B vs 文档 196B (0xC4),缺 +0xC1..+0xC3 尾部 3B padding(alignment=1 下 Ghidra 未补尾部对齐)。所有 13 个字段偏移/类型正确,dtor 无越界访问,功能无影响;建议按文档补 3B 尾部 padding 至 0xC4 以与 cSteamAccountCommunication 基类布局(子类分配 0x11C)对齐。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| DontStarveGameService | PASS | 无 |
| DontStarveSystemService | PASS | 无 |
| cNetworkLuaProxy | WARN | +0x08 `map_like_0x08` 容器语义存疑(map 头初始化但 dtor 不擦除,从未按 map 使用),布局本身与文档一致 |
| cAccountCommunication | WARN | Ghidra 193B vs 文档 196B(0xC4),缺 +0xC1..+0xC3 尾部 3B padding;字段全部正确,无错位 |

## 结论

4 个类型的 Ghidra struct 布局与 `types_common.h` / `tier3-d-network.md` 字段级完全一致(名称、偏移、类型逐项核对 + ctor/dtor 反编译交叉验证)。2 个 PASS、2 个 WARN:
- cNetworkLuaProxy 的 WARN 是任务预判的 +0x08 容器语义问题(已由 dtor 无擦除佐证),非布局错误;
- cAccountCommunication 的 WARN 是唯一实测差异:Ghidra 总大小 193B,缺文档 196B 的 3B 尾部 padding,无字段错位、无越界访问。
