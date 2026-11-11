---
name: dst-cross-arch-symbol-migration
description: "Migrate Android (symbol-bearing) DST engine symbols onto a stripped Windows x64 build via lua-binding tables, string anchors, BSim and labeled-pair calibration; also pin build fingerprints and measure anchor yield without Ghidra script access."
---

# DST 跨架构符号迁移 (Android ARM64 → Windows x64)

适用：Android `libDontStarve.so` 有完整（demangle 后）符号，Windows `dontstarve_steam_x64.exe` 剥符号，需要把名字迁过去。Ghidra project: `C:/Users/fesil/dst.gpr`（12.1.3 + GhidraMCP 6.0.0，端口 8089）。

## 0. 先钉 build（否则一切白做）
指纹四元组：`sha256 + PE TimeDateStamp + .rdata/.data RVA + 绑定名集合哈希`。
- 读 PE 节表用 Python（`MZ`→`0x3c`→`PE\0\0`→节表 `VA@+12, VS@+8, RawPtr@+20, RawSize@+16`）。
- 若 Ghidra 程序的节表布局与本机文件不一致 ⇒ 导入后被 Steam 更新覆盖，必须重导。已知：Instance 里那份是旧 build（`.rdata 0x14050d000`），当前 exe 是 `.rdata 0x514000` / `PE ts 2026-10-01`。
- 同源判定：旧 build 的绑定名集合应 ⊂ 新 build（实测 1,449 ⊂ 1,456）。

## 1. Lua 绑定表（最高价值、100% 精确、跨架构无关）
表中 `{char* name → 只读段, void* func → .text, 0}`，**24 字节步长**（.data 内）。
- 扫法：按 8 字节步长遍历 `.data`，取 `(q0,q1,q2)`，要求 `q2==0`、`q0` 指向可打印 ASCII 串（`.rdata`/`.rodata` 内，2–64 字符）、`q1` 落在 `.text` 内。
- Ghidra 里没有脚本权限时：eval 里 `await tool.mcp__ghidra_mcp_read_memory({address:hex,len,program})` 分页 4KB 拉段（>40KB 输出会被 elide），本地处理。
- 表内的函数都是 `lua_CFunction`，原型统一 `int f(lua_State *L)`；用 `set_function_prototype` 写。
- 两边同名条目 join ⇒ 直接得到跨架构 1:1 标注对（实测 1,340 对，1,229 条 Windows ≥8 指令），用于训练/校准打分器、做留出验收。

## 2. 字符串锚点
- capstone（`CS_ARCH_X86/CS_MODE_64, detail=True, skipdata=True`）线性扫 `.text`，取 `X86_OP_MEM + base==RIP` 的 `disp` → 目标落 `.rdata` 且是字符串起点。**必须 `skipdata=True`**，否则遇非法字节提前停（实测只解出 59k 而不是 1.4M 条指令）。
- AArch64 侧不需要解引用，只做“串是否存在于 `.rodata`”的集合判断即可估上限。

## 3. 结构化匹配（只用于剩余部分）
- 唯一原生跨架构能力是 **BSim**（decompiler P-code，余弦）：`support/bsim createdatabase file:<db> medium_nosize` → `generatesigs ghidra:/<project_dir>/<project_name> <sigs>` → `commitsigs`。H2 单进程占用 + project 会被锁 ⇒ 对项目**副本**跑。
- VT 的 correlator 只有 bytes/instructions/mnemonics/duplicate ⇒ 同架构；FID 是字节哈希 ⇒ 同架构。别指望它们跨架构。
- ghidra-mcp 的 `bulk_fuzzy_match`/`find_similar_functions_fuzzy` 跨架构无效（特征依赖 calleeNames + mnemonic 块哈希）。
- 分派用桶内 Hungarian + `top1-top2` margin，禁止最近邻（MSVC `/OPT:ICF` 会折叠多个源函数到一个目标）。

## 4. 验收
- 从 1,340 对里留 200 对盲测：Top-1 ≥95%、误配 <2% 才允许写回。
- 分档 tag：`sym:exact` / `sym:bsim` / `sym:guess`；每档抽 100 反编译对照（≥90% / ≥100% 门槛分别对待）。
- 写回**逐条**用 `apply_function_documentation` / `set_function_name`；`merge_program_documentation` 是“同地址合并”，跨架构不可用。

## 5. 现实预期
- 绑定表 6.2% + 唯一字符串 7.2%（重叠 85）≈ 13.4% 精确种子。
- 全自动交付 50–65% @≥90% 精度；70–80% 需要人工复核 2–4k；7,053 个无字符串叶子基本不可自动判定。
- 分母要写死：`Windows 侧 ≥8 指令的非 funclet 函数`（实测 21,073 / 25,087 条 .pdata RUNTIME_FUNCTION，Ghidra 只认出 17,637）。
