# Ghidra void* 指针字段类型纠正计划 (2026-08-10)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 Ghidra (`dontstarve_steam`, macOS i386) 已建 struct 中所有可确定的 `void*` 指针字段,按已翻译的类型列表逐个纠正为具体类型,消除反编译可读性损失。

**Architecture:** 只读盘点 agent 按子系统枚举 Ghidra 已建 struct 的 `void*` 字段 → 对照「翻译列表」(types_common.h + remaining 报告 + unbuilt + raknet-review)生成 结构体→字段→目标类型 纠正表 → 主 agent 统一回写 `modify_struct_field` → 抽查验证。沿用已验证的「并行只读调查 + 主 agent 统一回写」模式(Tier 3 验证成功)。

**Tech Stack:** ghidra-mcp(modify_struct_field / get_struct_layout / delete_data_type / save_program)、只读 agent(scout)、types_common.h、docs/superpowers/type-recovery/*.md

## Global Constraints

- **只读 agent 禁止写 Ghidra**;所有 `modify_struct_field` 由主 agent 执行(会话竞争保护)。
- 目标二进制固定:`dontstarve_steam`(macOS i386);Android `libDontStarve.so` 不在本次范围。
- **类型名冲突**:`/Demangler/*` 下存在 1B 同名占位(自动生成)。纠正前若目标类型名与占位冲突,先 `delete_data_type` 删占位。
- 字段类型目标必须来自「翻译列表」证据;无证据字段保持 `void*` 并在报告标注「待定」。
- 可引用已建类型(如 `Replica3`、`BitStream`、`cNetworkComponent`);引用前确认类型存在(`get_struct_layout` 或 `search_data_types`)。
- i386:指针 4B;改类型不改字段偏移/大小(类型 size 必须 ≤ 原字段 size,否则 `modify_struct_field` 失败 → 拆字段处理)。
- 每次批量修改后 `save_program`。
- 报告中文、符号英文;每 struct 的修改行记录:struct → 字段 → 旧类型 → 新类型 → 证据来源。

---

## 背景盘点(已确认)

| 来源 | 规模 |
|---|---|
| types_common.h | 130 struct,220 `void*` 字段,44 带类型注释 |
| remaining-a..e + f1..f4 | ~143 struct(98+45),字段类型在报告 |
| unbuilt-types.md | 27 struct |
| raknet-review.md + r1 | 16 RakNet 类型(已建正式 struct) |
| Ghidra demangler 占位 | 与真实 struct 同名冲突 |

### 已确认可纠正的高价值字段(样例,来自 types_common.h 注释)

| struct | 字段 | 当前 | 目标 |
|---|---|---|---|
| cEntity | worldNode | void* | SceneGraphNode* |
| cEntity | networkComponent | void* | cNetworkComponent* |
| cEntity | transformComponent | void* | cTransformComponent* |
| cEntity | animStateComponent | void* | cAnimStateComponent* |
| cEntity | transformprovider | void* | cTransformProvider* |
| cEntityManager | pSpatialHash | void* | cSpatialHash\<cEntity\>* (需建/确认) |
| cSimulation | pLuaState | void* | lua_State* |
| cSimulation | pWorldSim | void* | WorldSim* |
| cSimulation | pEntityManager | void* | cEntityManager* |
| cSimulation | pGame | void* | cGame* |
| cSimulation | pMainCamera | void* | cCamera* (待确认) |
| cNetworkComponent | replica3/bitStream | 已接线 | (已完成) |
| cNetworkReplica/Connection | base | 已接线 | (已完成) |

**注意:** types_common.h 的 vector 三件套(`*_begin/_end/_cap`)、vtable 指针(`pVtable/p__vtf`)、红黑树节点(`*_parent/_left/_right`)通常**保持 void***,元素/节点类型未知时不做猜测纠正。

---

## Phase 0(前置):同步 types_common.h ← Ghidra 已建 struct

> 发现:`types_common.h` 仅 129 struct,Ghidra 已建 ~300(remaining A–E 98 + F 45 + unbuilt 27 + RakNet 16 + Tier0–3)。**缺口 ~180 struct 未进头文件**。且 Ghidra 部分字段已纠正(如 `cEntityManager.pSimulation` 已是 `cSimulation*`),头文件仍是 `void*` — 同步方向:Ghidra → 头文件。

**Files:**
- Modify: `docs/superpowers/../3rd/dst/game_decompiler/types_common.h`
- Read(只读): Ghidra `get_struct_layout` 各已建 struct
- 产出: 同步后 `types_common.h` + `voidstar-audit.md`(字段类型基线)

**枚举方法(已确认可行):**
- `list_data_types`/`search_data_types` **无法枚举根路径 struct**(只列 demangler/指针引用)
- 根路径 struct 只能**按文档清单逐个 `get_struct_layout`** — 清单来源:remaining-a..e/f1..f4 报告、unbuilt-types.md、raknet-review、types_common.h 现有 129
- 每 struct 一次 `get_struct_layout` 即得完整字段表

- [ ] **Step 1: 汇总已建 struct 清单**
  从 6 类文档合并出 Ghidra 应存在的 struct 全名单(~300)。去重、排除枚举/静态/抽象/Tier4。
- [ ] **Step 2: 逐个 dump 布局**
  对清单每个 struct 调 `get_struct_layout`(program=`dontstarve_steam`),记录:size、每字段 偏移/类型/名。不存在或 Size=1 → 标「缺失(仅 demangler 占位)」。
- [ ] **Step 3: 生成 C 定义并合并**
  按 types_common.h 现有风格(`struct X { type name; // off` / 行尾 `// total`)为每个缺失 struct 生成定义;字段类型优先用 Ghidra 实际类型(已纠正的如 `cSimulation*`),否则 `void*` + 注释。
  合并策略:已有 129 保留;Ghidra 已纠正字段 → 更新头文件对应行;新增 struct → 追加到对应子系统区块。
- [ ] **Step 4: 冲突与依赖检查**
  类型引用完整性:struct 引用的子类型(如 `Mutex`、`Timer`、`cEntityComponent`)需在头文件已定义或同批加入;模板名(如 `cSpatialHash<cEntity>`)标注待展开。
- [ ] **Step 5: 验证**
  `gcc -fsyntax-only` 或等效检查头文件可编译(需 stub 缺失的 Tier4 类型);统计:新增 N / 更新 M / 缺失 K。

**产出物:** 同步后 `types_common.h`(struct 数从 129 → ~300)、`voidstar-audit.md` 记录每 struct 来源与字段类型基线。

**注意:** 同步后,Phase 1 的「翻译列表」即更新为「types_common.h 同步版」— void* 纠正的字段证据从该文件读取。

---

## Phase 0.5: 文档发现 — 生成 void* 字段总清单

**Files:**
- Read: `docs/superpowers/../3rd/dst/game_decompiler/types_common.h`(同步后)
- Read: `docs/superpowers/type-recovery/remaining-{a..f}*.md`、`unbuilt-types.md`、`raknet-review*.md`
- 产出: `docs/superpowers/type-recovery/voidstar-audit.md`(主 agent 汇总)

- [ ] **Step 1: 提取翻译列表映射**
  从同步后的 types_common.h + 6 类文档提取 `struct → 字段名 → 目标类型` 映射,去重合并为统一表。vector 三件套/vtable 指针/红黑树节点标记为「保持 void*」。
- [ ] **Step 2: 枚举 Ghidra 已建 struct**
  对每个已建 struct 调 `get_struct_layout`,列出含 `void*`/`void *` 的字段(结构体、偏移、当前类型)。
- [ ] **Step 3: 生成纠正表**
  匹配 Step1×Step2:命中 → 记目标类型;未命中但字段名有明确语义 → 标「推断」;其余 → 「待定」。输出 `voidstar-audit.md`。
- [ ] **Step 4: 冲突检查**
  列出目标类型名与 demangler 1B 占位冲突的条目(需先删占位),以及「目标类型不存在于 Ghidra」的条目(需先建类型)。

## Phase 1: 按子系统分片纠正(并行 agent,主 agent 回写)

**Files:**
- Modify: Ghidra struct(经主 agent `modify_struct_field`)
- 产出: 每片报告 `voidstar-slice-<sub>.md`

**分片(每片 = 一个只读调查 agent,产出「struct→字段→目标类型→证据」表,不写 Ghidra):**
- [ ] S1 网络/RakNet: cNetworkComponent、cNetworkManager、cNetworkConnection、cNetworkReplica、cNetworkRPCManager、cNetworkVoiceManager、cPendingConnection、cNatTraversal、cSteam*、tCheshireCat、cShardManager 等
- [ ] S2 实体/场景: cEntity、cEntityManager、cSimulation、cGame、cDontStarveSim、WorldSim、SceneGraphNode、MapComponent 族、GroundCreep 等
- [ ] S3 渲染: Renderer、GameRenderer、Texture/VertexBuffer/IndexBuffer 管理器、TDataCache*、ShadowRenderer、VFXEmitterManager、SimplexNoise 等
- [ ] S4 UI/输入: WindowManager、cUIScreen、c*Widget、cConsoleInput、DontStarveInputHandler、IInputDevice、SDLInputManager 等
- [ ] S5 系统/杂项: cApplication、cLogger、cInventoryManager、cSoundSystem、cMasterServer、HttpClient2、CurlRequest、GameServiceImpl、FileSystem、ZipSaver 等

**回写规则(主 agent 执行):**
- [ ] 对每个「确定」条目:`modify_struct_field(struct_name, field_name, new_type)`;失败(类型 size>字段)则拆字段或标待定。
- [ ] 对「推断」条目:仅当字段名唯一且类型已存在时纠正,否则保留 void* 并记录。
- [ ] demangler 占位冲突:先 `delete_data_type` 删占位,再修改引用。
- [ ] 每片完成后 `save_program`。

## Phase 2: 验证

- [ ] **Step 1: 抽查**
  对每片 ≥3 个已改 struct 调 `get_struct_layout`,确认新类型生效、size 不变。
- [ ] **Step 2: 反编译冒烟**
  对 2–3 个依赖字段的函数(如 `cNetworkComponent::Serialize`、`cSimulation::Update`)反编译,确认指针解引用已带类型。
- [ ] **Step 3: 汇总**
  更新 `voidstar-audit.md`:纠正 N / 保持 M / 待定 K;把「待定」字段列表留给下一轮。
- [ ] **Step 4: save_program**
  最终 `save_program(dontstarve_steam)`。

---

## 验收

- [ ] 全部「确定」条目已回写,`get_struct_layout` 抽查通过,size 无变化
- [ ] 无 Ghidra 会话竞争(只读 agent 未写)
- [ ] `voidstar-audit.md` 记录每字段证据与来源
- [ ] demangler 占位冲突已处理
- [ ] program 已保存

## 反模式守卫

- 禁止无证据猜类型(字段名相似 ≠ 同类型)
- 禁止改 `_begin/_end/_cap` 三件套与 vtable 指针(除非元素/节点类型已知)
- 禁止把未知指针改成 `int`/`uint` 之类有损类型
- 禁止在只读 agent 中写 Ghidra
