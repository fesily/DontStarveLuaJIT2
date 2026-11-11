---
name: macos-dst-i386-x64-symbol-migration
description: DST macOS i386 r181048 → x86_64 r759671 符号迁移：Ghidra MCP 特征导出、贴图/注册表/字符串投票/构造函数锚定 vtable 通道、分层落名与可逆审计
---

# macOS DST 跨架构符号迁移（i386 → x86_64，Ghidra MCP）

适用：`macos_dontstarve_steam_x86_r181048`（施主，符号完整）→ `macos_dontstarve_steam_x64_r759671`（目标，几乎无符号）。同产品（DST），但跨架构，opcode hash/函数大小/相邻序不可用。

## 0. 前置：只用项目内程序，顺序打开

- `load_program_from_project` 打开，`close_program` 关闭；两个程序内部名都叫 `dontstarve_steam`，**不能同时打开**（同名冲突，`close_program` 可能一次关掉多个）。
- `load_program_from_project` 不跑分析；先查 `analysis_status` 的 `analyzed`。

## 1. 特征导出（每个程序跑一遍，按指针宽度自动分文件）

inline 脚本无法定义方法，全部写在脚本体里；tag = `dontstarve_steam` + (`_x64` if ps==8 else `_x86`)。

输出到 `<out>/<tag>.*.tsv`：

| 文件 | 内容 | 关键点 |
|---|---|---|
| `.funcs.tsv` | addr, size, name, namespace, source | `getFunctions(true)` 不含 external，需另遍历 `getExternalFunctions()` 才能对上 `getFunctionCount()` |
| `.strings.tsv` | insn_addr, string | `lst.getDataAt(to)` 且 `getValue() instanceof String`，长度≥4 |
| `.calls.tsv` | caller_insn, callee_addr | `ref.getReferenceType().isCall()` |
| `.bind.tsv` | name, func, table_base, stride | 指针宽度感知：读 `ps` 宽指针，扫描非执行块，找连续 ≥3 条 {name→可读字符串, func→`getFunctionAt()!=null`}，strides = 2/3/4/5/6 × ps |
| `.imms.tsv` | addr, "hex hex …" | 标量立即数 0x10000..0xffffffff 且不落在内存镜像内；实测跨架构无用，可跳过 |
| `.vtables.tsv` | vtable_addr, count, "func …" | 非执行块里连续 ≥3 个指向函数入口的指针 run |
| `.vtrefs.tsv` | vtable_addr, count, "ref_func …" | 对每个 vtable 起始地址 `getReferencesTo`，取 `getFunctionContaining(from)`（构造函数锚点） |

## 2. 通道与精度

| 通道 | 规则 | 实测 |
|---|---|---|
| `str` 唯一字符串 | 字符串两侧各只被一个函数引用，长度≥10 | 有效，少量同串异函数误配 |
| `str-set` 集合投票 | 共享字符串计票 ≥2、Jaccard ≥0.4/0.5、双向唯一最优 | 有效，是后续主力 |
| `bind` 注册名唯一 | 同一注册名两侧各只指向一个函数 | 高精度 |
| `bindtab` 表序列对齐 | 按表 base 分组，名字序列 LCS，逐槽同名才配 | 高精度，能救回同名方法 |
| `self` 自证 | 函数体字符串等于自身限定名（允许尾部 `(`） | 只用于把单通道升权 |
| `graph` 图传播 | 已配对 callee/caller 邻域投票，score≥4、margin≥2、双向唯一 | 只在"目标已有同名方法"时可信（用于改命名空间）；`different` 一律丢弃 |
| `vtable` | 构造函数引用做锚点配对 vtable → 等长才按槽对齐 → 逐槽要求字符串/被调支持 | 偏移投票不可靠；锚点法 94 表 / 40 可信槽 |
| `imm` 立即数 | 共享常量计票 | 跨架构无效，别用 |

分层：A = ≥2 通道；B = 单通道 + self；C = 单通道（仅 review）；R = 图传播丢弃项。

## 3. 应用（可逆）

apply TSV 列：`target_addr, namespace, short_name, tier, donor_qualified, evidence`。

Java 脚本要点：
- 命名空间缓存 `HashMap<path, Namespace>`，逐段 `createNameSpace`，失败再 `st.getNamespace(seg, parent)`；
- 只对 `FUN_*` 改名，已有名字不覆盖（除非证据与短名一致）；
- 注释统一写 `sym:<donor_tag> <限定名> tier=<T> [old=<旧限定名>]`，同时把旧名写进 `applied_*.tsv` 便于回退；
- 结束 `save_program`。

命名空间路径若含函数局部作用域（`Cls::method(sig)::Local`），先按 `ns.split('(')[0]` 截断，避免 `::` 切分错乱。

## 4. 验收与口径

- 覆盖 = 施主唯一限定名 ∩ 目标唯一限定名（demangle、去一个前导下划线、`类型::函数名`）；
- 冲突审计：强通道配对但目标已有异名 → 按目标函数注释来源分类（`same-arch: seed` / `cross-arch` / `sym:r181048` / 无注释），同短名不同类只改命名空间，完全异名留人工；
- 需注意：给函数补命名空间会让数据库里旧的次符号/标签成为主符号，具名数会跳增，不能用具名数糊当迁移量。

## 5. 复用脚本

`C:\Users\fesil\DontStarveLuaJIT2\build\symmatch\mac_xarch\match_xarch.py`（加载/通道/分层/输出），特征与 apply 记录同目录；`gen_symbol_md.py` 在 `build/symexport/`（符号表按类聚合导出）。
