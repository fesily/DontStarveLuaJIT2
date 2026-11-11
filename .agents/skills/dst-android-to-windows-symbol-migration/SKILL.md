---
name: dst-android-to-windows-symbol-migration
description: "Migrate Android ARM64 full symbols to the stripped Windows x64 DST binary via Ghidra: binding-table + string anchors, BSim, labeled-pair calibration; not same-arch diffing."
---

# DST 跨架构符号迁移（Android ARM64 有符号 → Windows x64 无符号）

适用：Android `libDontStarve.so`（全符号）与 Windows `dontstarve_steam_x64.exe`（无符号、无 PDB、RTTI 关闭）之间迁移函数名。**不适用**同架构版本 diff（那用 Version Tracking）。

## 前置事实（不要重新论证）
- Ghidra 原生跨架构只有 **BSim**（反编译器 P-code 余弦）。Function ID = 字节哈希，同架构；Version Tracking 的 correlator 只有 bytes/instructions/mnemonics/duplicate，**跨不了架构**。
- GhidraMCP 的 `bulk_fuzzy_match` / `find_similar_functions_fuzzy` 依赖 `calleeNames` + mnemonic 块哈希 → 跨架构必 0 命中，别用。
- Windows 侧无 PDB、无游戏类 RTTI（只有 std/CRT 的 `.?AV`）→ 没有类名锚点。
- MCP 执行 Java 脚本需 `GHIDRA_MCP_ALLOW_SCRIPTS=1`（默认关闭，报 `Script execution disabled`）。没开时可用 `read_memory` 每 4KB 一段拉 `.text/.rdata/.data/.pdata`（~21 ms/次），在 eval 里离线用 capstone 分析。
- BSim H2 单进程占用，且非共享项目被 Ghidra 锁 → 对项目**副本**跑 `bsim generatesigs`。

## 步骤

### 0. 固定输入
确认 Ghidra 里加载的 Windows 程序与磁盘 exe 是同一镜像：对比 `.rdata/.data` 段 VA（`list_segments`）与可执行文件 PE 头。不一致（DST 常见，因 patcher/多版本）先决定用哪份，否则地址全漂。

### 1. 绑定表锚点（最高性价比，~100% 精度）
两边 `.data` 都有 24 字节步长表 `{const char* name, void* func, 0}`。扫描条件：
- 第 0 字指向只读段内的可打印 NUL 结尾串（2–64 字符）
- 第 1 字指向 `.text`
- 第 2 字 == 0

两侧各自提取 → 名字本身就是 Lua 绑定的 C 函数名；同名 join 得 1:1 对（DST 实测 1,340 对），直接给 Windows 函数命名并可设原型 `int f(lua_State *L)`。

### 2. 唯一字符串锚点
Windows 侧「唯一字符串 → 唯一函数」+ 该字符串在 Android `.rodata` 存在 → 迁移。
- Windows x64：capstone `md.skipdata=True` 线性扫描，取 `mem.base == X86_REG_RIP` 的操作数，目标落在 `.rdata` 且可解析为串（≥5 字符）。**必须设 skipdata，否则 5.3MB 只能反汇编 59k 条就停。**
- 每个函数只命中一个新名的前提是「该串只被一个函数引用」；多串同名时用「串集合」而非单串。
- `.cpp`/断言串用于给函数打 TU 标签，后续分桶。

### 3. 用 1,340 对标注集校准打分器
特征：串集合 Jaccard、唯一串命中、立即数集合 Jaccard（ARM64 `movz/movk` 需先重组 64 位常量）、BSim 余弦、指令/块/圈复杂度比值、被调函数已命名比例、数据引用集合、异常表（x64 `.pdata` vs ARM64 `.eh_frame`）。
留出 200 对盲测：Top-1 ≥95%、误配 <2% 才允许写回。

### 4. BSim（唯一跨架构分）
```bat
cd <ghidra>/support
bsim createdatabase file:C:\bsim\dst medium_nosize
bsim generatesigs ghidra:/<projdir>/<projname> C:\bsim\sigs --bsim file:C:\bsim\dst
bsim commitsigs file:C:\bsim\dst C:\bsim\sigs
```
`medium_nosize` = 忽略 ≥4 字节 varnode 尺寸差异，压掉 ARM64/x64 宽度噪声。

### 5. 一对一分配 + 传播
按 TU/类/调用者集合分桶，桶内 Hungarian，不用最近邻（会多对一，并在 MSVC `/OPT:ICF` 折叠函数上错并）。只接受 `top1 - top2 ≥ margin`；把已接受结果回灌重算「被调函数已命名比例」，迭代 2–3 轮。

### 6. 写回
- **不要**用 `merge_program_documentation`（按同地址合并，跨架构无意义）。
- 逐条 `apply_function_documentation` / 改名 + 原型，plate comment 记录来源 Android 地址与依据，打 tag `sym:exact|sym:bsim|sym:guess`。

## 覆盖率现实基线（DST 实测）
分母取 Windows 侧 ≥8 指令函数（21,073）：绑定表 6.2% + 唯一串 7.2% + 集合 Jaccard 3–5% + BSim/分配 25–32% + 传播 8–15%，全自动高精度落 50–65%；70–80% 需分档 + 人工过 2–4k；约 28% 无字符串叶子函数基本不可自动判定。

## 验收断言
同一 Windows 函数不得两名；写入名必须存在于 Android 符号表；各 TU 命名率无断层。
