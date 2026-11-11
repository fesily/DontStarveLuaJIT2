---
name: macos-xarch-symbol-migration-ghidra-mcp
description: Use when migrating function symbols between same-product macOS DST builds across architectures (i386→x86_64) via Ghidra MCP; not same-arch or cross-product transfers
---

# 同产品跨架构（i386 → x86_64 Mach-O）符号迁移

适用：DST macOS 版之间迁移函数名（如 r181048 i386 DST → r759671 x86_64 DST）。不适用同架构版本同步（那条路可用 opcode hash/大小）。

## 前置检查（先做，避免白干）

1. **确认是同一产品**：`strings` 里看 `Don't Starve Together` / `Don't Starve` + `_hamlet` + `shipwrecked_`。单人版与联机版不是同一符号空间（单人版无 RakNet、无 `cNetworkManager`/`cShardManager`），只能当参考。
2. **用项目里已有程序**，不要 `load_program` 新副本；用户明确反对重复导入。
3. 两个程序常常同名（都叫 `dontstarve_steam`），`load_program_from_project` 打开第二个会顶掉第一个 → 必须**顺序开关**：导出施主特征 → 关闭 → 打开目标 → 导出目标特征。

## 特征导出（inline Java via run_script_inline）

inline 脚本只能写语句体：**不能定义方法**（helper 函数会编译失败，报「找不到符号」）。指针宽度用 `currentProgram.getDefaultPointerSize()`。

输出四张表（文件名带 `_x86`/`_x64` 区分）：
- `<tag>.funcs.tsv`：addr, size, name, namespace, SymbolSource
- `<tag>.strings.tsv`：instruction_addr, string（只取 `Listing.getDataAt(to)` 且 `getValue() instanceof String`，长度≥4）
- `<tag>.calls.tsv`：caller_insn, callee（`refType.isCall()`）
- `<tag>.bind.tsv`：name, func_addr, table_base, stride

绑定表扫描要点（`luaL_Reg` 类 `{name, func, 0…}`）：
- stride 取 `ps*2 … ps*6`（i386 常见 8/16，x86_64 常见 16/32/40/48）。
- 一条 entry 的判据：slot0 指向可打印字符串、slot1 指向可执行块且 `getFunctionAt(fa)!=null`。
- 要求连续 ≥3 条 entry（`{0,0}` 终止）。只要求「连续 3 个函数指针」是错的，槽位 2+ 是 0。
- 跳过 `__cstring/__objc/__ustring/LINKEDIT` 块。

## 匹配通道（按可信度）

| 通道 | 做法 | 实测 |
|---|---|---|
| `bindtab` | 按 `(table_base,stride)` 分组，对名字序列做 LCS 对齐，逐槽同名才配对 | 452 对，噪声低 |
| `bind` | 注册名在两侧各自唯一 → 配对 | 782 对 |
| `str` | 某字符串在两侧各只被一个函数引用（≥10 字符） | 1,053 对，仍有同串异函数误配 |
| `self` | 函数体字符串等于自身限定名 → 单通道升权 | 39 对 |
| `graph` | 由已配对集合做 callee/caller 邻域传播 | 误配高（如 `cDontStarveSettings::Save`→`HttpClient::Reset`），只进审查 |

合并后按 (donor,target) 一对一，丢弃多对多。Tier：A=≥2 通道；B=单通道+self；C=单通道（审查）；R=graph（不应用）。

## 落名前检查

- 目标已有名字时比较**短名**：完全相同 → 只补命名空间；短名相同但 ns 不同 → 补 ns；真不同 → 跳过（可能目标侧改名，如 `TwitchComponentLuaProxy`→`BroadcastingComponentLuaProxy`、`SteamWorkshop::DownloadTempMods`→`SteamModWorkshop::RefreshSubscribedMods`）。
- 只对 `FUN_*` 做 rename，已有非自动名绝不覆盖。

## 应用脚本（inline Java）要点

- 命名空间：用 `HashMap<String,Namespace>` 缓存，逐段 `createNameSpace(parent, seg, SourceType.USER_DEFINED)`；重复时 `catch` 后 `symbolTable.getNamespace(seg, parent)`。`SymbolTable.getNamespaces(ns)` 在 Ghidra 12 不存在。
- `fn.setName(short, SourceType.USER_DEFINED)` + `fn.getSymbol().setNamespace(ns)` + `fn.setComment("sym:<donorRev> <qualified> tier=<T>")`。
- 先 `dry=true` 跑一遍核对 rows/rename/nsOnly，再改 `dry=false`；最后 `save_program`。

## 验证

- 抽查 `get_function_by_address` 看改名结果。
- 留出集只能用目标的 `IMPORTED` 原始名（本例 685 个，命中极少），主要靠「多通道一致 + 已有名不冲突」控制精度。

## 复用

- 匹配器：`build/symmatch/mac_xarch/match_xarch.py`；特征/落名脚本以 inline Java 运行过，可重放。
