---
name: macos-crossarch-symbol-migration-ghidra-mcp
description: "Cross-architecture (i386→x86_64) DST macOS symbol migration in Ghidra MCP: sequential feature extraction, channel set, tiered apply with provenance, pitfalls"
---

# 目标

在 Ghidra（headless + MCP）里把带符号的旧 macOS 二进制（i386，如 DST r181048）的函数名迁移到无符号的新 x86_64 二进制（如 r759671），按类分轮、每轮都能度量精度并回退。

适用：同一产品的跨架构版本（i386→x86_64）。不适用跨产品（单人版→DST）——那只能当参考施主。

## 0. 先确认产品身份

```bash
python -c "d=open(r'<binary>','rb').read(); print([s for s in (b'Don.t Starve Together', b'Don.t Starve', b'322330', b'RakPeer') if s in d])"
```

DST 有 `Don't Starve Together`/`322330`/RakNet；单人版有 `Don't Starve`/`_hamlet`/`shipwrecked_` 且没有 RakNet、没有 `cNetworkManager`/`cShardManager`/`cAccountManager`。跨产品迁移会污染名字。

## 1. 打开程序（不要导入新文件）

- 用 `load_program_from_project`，路径即项目里的程序名（例 `/macos_dontstarve_steam_x86_r181048`）。
- **坑**：项目里多个程序的内部名都叫 `dontstarve_steam`，同时打开第二个会把第一个顶掉；`list_open_programs` 只会显示一个。因此两侧特征分两次导出，离线比对。
- 关闭时 `close_program`) 传 name 可能一次关掉多个同名程序（closed_count 会 >1），这是预期。

## 2. 特征导出（每侧各跑一次 inline 脚本）

写到 `build/symmatch/mac_xarch/<tag>.*.tsv`，tag 用指针宽度区分：`dontstarve_steam_x86` / `_x64`（`currentProgram.getDefaultPointerSize()` 判断，否则两侧同名文件互相覆盖）。

| 文件 | 列 | 说明 |
|---|---|---|
| `.funcs.tsv` | addr, size, name, namespace, source | `getFunctions(true)`，不含 external |
| `.strings.tsv` | insn_addr, string | 只取 `Listing.getDataAt` 返回 String 的引用 |
| `.calls.tsv` | insn_addr, callee_addr | `ReferenceType.isCall()` |
| `.bind.tsv` | name, func_addr, table_base, stride | 扫非执行块里的 `{namePtr, funcPtr, ...}` 连续 ≥3 条；stride = 2/3/4/5/6 × 指针宽 |

Inline 脚本限制：**不能定义方法/函数**（脚本体直接插入类体）；用 `Long.toHexString`、`toAddr(long)`，字符串读取要手写循环；`bufferedReader`/`PrintWriter` 可用。

绑定表扫描要点：只要求 slot0→可打印字符串、slot1→执行段且 `getFunctionAt != null`，连续 ≥3 条成表；跳过 `__cstring/__objc/LINKEDIT` 块。单独跑一个 bind 脚本，便于先跑通再调 stride。

## 3. 匹配通道（离线 Python）

| 通道 | 规则 | 实测（i386→x64, DST） |
|---|---|---|
| `bind` | 注册名两侧各自唯一 | 782 对 |
| `bindtab` | 注册表按条目序列 LCS 对齐，逐槽同名 | 452 对 |
| `str` | 唯一字符串引用（两侧各只 1 个函数引用，≥10 字符） | 1,053 对 |
| `self` | 函数体字符串等于自身限定名（升权用） | 39 对 |
| `strvote` | 共享字符串计票（≥2 票、Jaccard≥0.4~0.5、双向唯一最优） | 510 候选 |
| ~~`imm`~~ | 立即数多重集（≥0x10000，非镜像地址） | 仅 44 候选、误配高，**不单独用** |
| ~~`graph`~~ | callee/caller 邻域传播 | 误配（Save→Reset 级），**只当参考** |

合并后按 `(donor,target)` 一对一去重（同一侧多候选直接丢弃），再把 donor 限制到目标类别（引擎类 = 有 namespace 且不是 Global/`<EXTERNAL>`/dylib 路径）。

## 4. 分轮与落名

- Tier A = ≥2 条独立证据；Tier B = 单通道 + `self`。只落这两级；Tier C（单通道）只进 review。
- 目标已有非 `FUN_` 名字时：
  - 完全同名 → 只补命名空间；
  - 同短名不同类 → `kind=same-short`，可批量改命名空间；
  - 短名也不同 → `kind=different`，不覆盖，进 `review_conflicts.tsv` 人工判断（可能是新版改名）。
- 落名脚本：按命名空间路径逐段 `createNameSpace(parent, seg, USER_DEFINED)`，DuplicateName 时 `getNamespace(seg, parent)` 兜底，自己维护 `HashMap<path, Namespace>` 缓存（`SymbolTable.getNamespaces(ns)` 不存在）。
- 注释写 `sym:<donor> <限定名> tier=<A|B|D|NS> old=<旧限定名>`，可逐条回退；回退清单另存 `applied_*.tsv`。
- `save_program` 持久化。

## 5. 度量与副作用

- 覆盖口径：施主唯一限定名 ∩ 目标唯一限定名，不要按函数数（调度器/thunk 会重复）。
- 给目标补命名空间后，数据库里原有的次符号/标签会变成函数主符号，具名函数数会突然暴增几千——这些不是本轮写入的，先按注释前缀（`same-arch`/`cross-arch`/`sym:<donor>`）分账再下结论。
- 外部导入符号在 Ghidra 独立地址空间里恒为 0 引用，"未使用导入"要用同名本地 stub 是否有引用来判断，不能直接数 refs。

## 6. 验证

- 抽查 1–3 个新落名地址：`get_function_by_address`，再用脚本打印 `namespace::name` 与注释（工具只回短名）。
- 每轮结束记录：应用条数、覆盖变化、剩余 review 数。
