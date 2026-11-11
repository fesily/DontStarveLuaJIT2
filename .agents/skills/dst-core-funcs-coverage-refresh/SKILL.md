---
name: dst-core-funcs-coverage-refresh
description: "Refresh DST core-function symbol coverage (CORE_FUNCS_2.2.1.md, ledger, coverage metric) after new names are applied; fixes the denominator universe and flattened nested-type attribution."
---

# DST 核心函数覆盖率刷新（DontStarveLuaJIT2）

在给 Windows 二进制新命名若干函数后，同步三处产物：名字导出 → 覆盖率 → 台账 → 文档两列。

## 0. 前置
Ghidra 项目 `C:/Users/fesil/dst`，程序名 `dontstarve_steam_x64_live.exe`，脚本目录 `C:/Users/fesil/ghidra_scripts`。
MCP headless server 可能已关闭；`analyzeHeadless ... -noanalysis` 可直接用。

## 1. 导出名字（唯一权威来源是 DB）
```bash
GH="$HOME/Desktop/ghidra_12.1.3_PUBLIC/support/analyzeHeadless.bat"
"$GH" C:\\\\Users\\\\fesil dst -process "dontstarve_steam_x64_live.exe" -noanalysis \
  -scriptPath C:\\\\Users\\\\fesil\\\\ghidra_scripts \
  -postScript DstExportNames.java C:/Users/fesil/DontStarveLuaJIT2/build/symmatch/vt2/win_names_liveNNN.tsv
```
只数 `USER_DEFINED` 行；输出首行 `names: ... user_named_functions=N`。

## 2. 重算覆盖率与台账
```bash
cd C:/Users/fesil/DontStarveLuaJIT2
python tools/symmatch/manual/coverage.py build/symmatch/vt2/win_names_liveNNN.tsv
python tools/symmatch/manual/ledger.py   build/symmatch/vt2/win_names_liveNNN.tsv
```
必须满足的不变量：
- `coverage.py` 的分母 == `len(android_pairs())`（当前 4,975），**不是** `CORE_FUNCS_2.2.1.md` 里 `导出函数` 列之和（4,811，仅直接作用域）。用后者会让全命名时度理 >100%。
- 台账各行数之和 == 分母；`named + unproven + verdict + absent + inlined + stub == 4,975`。
- 新增测试 `CoverageUniverseTest` 就是钉这条，跑 `python -m pytest tests/performance/test_symmatch.py -q`（应 9 passed）。

## 3. 刷新文档两列
```bash
python tools/symmatch/manual/annotate_core_funcs.py   # 幂等
```
写回 `3rd/dst/game_decompiler/CORE_FUNCS_2.2.1.md` 每行末尾的 `未迁移` / `否定迁移`：
- `未迁移` = `unproven` + 证据无结论的 `verdict` 行；
- `否定迁移` = `absent` / `inlined` / `stub` / `folded`；
- 其余为已迁移。核对脚本打印的 `open`/`neg` 与文档唯一类型求和一致（注意 `cShardClientComponent` 在文档中出现两次，跨行求和会重复）。

## 4. 类归属规则（容易踩的三个坑）
1. 表用**扁平名**（`GameService_PlayerInfo`、`QuadTreeNode_Node`、`tCheshireCat_*`、`AStarSearch_*`、`JobThread_ThreadPhysics`、`SHA256_Klei`），dynsym 反混淆是 C++ 作用域 → 两个工具都必须先试 `"_".join(parts[:i])`。
2. **最具体行优先**：边界从方法往外走，扁平名先于单组件判断，否则 `QuadTreeNode::Node::*` 会被外层 `QuadTreeNode` 抢走。
3. 匹配同时接受 `A_B` 与 `A::B` 两种类的写法，但 `SHA256_Klei` 是真实下划线名，不能盲目替换。

## 5. 记录
每轮把方法、参数与否定结论追加到 `build/symmatch/manual/STATUS.md`；已命名的地址同步进 `SESSION_APPLIED.md`（由 `w*_apply.tsv` 汇总）。
