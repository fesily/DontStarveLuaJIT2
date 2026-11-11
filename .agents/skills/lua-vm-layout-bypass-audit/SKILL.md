---
name: lua-vm-layout-bypass-audit
description: "Audit a statically linked Lua 5.1 game binary for engine code that bypasses the Lua API and touches lua_State/TValue/Closure layout directly; decompiler-anchored scan, ABI-constant census, false-positive triage."
---

# 判定「引擎有没有越过 Lua API 直接按 VM 内存布局读写」

适用：静态链接 PUC Lua 5.1 的 Windows x64 游戏 exe（Ghidra + ghidra-mcp），且 Lua 区块已全部具名。

## 关键前提

Lua 区块必须先具名（否则 `^lua_|^luaL_|^luaopen_` 的 callee 名集合为空，普查全废）。用 `build/symmatch/vt2/win_names_*.tsv` + `calleesets_win.tsv`。

## 三步

1. **API 调用点普查**（纯本地 join，秒级）
   - `calleesets_win.tsv` 逐行取 callee 名，正则 `^(lua_|luaL_|luaopen_)`，排除落在 Lua 区块地址区间内的函数。
   - 产出 `lua_api_callers.json`：函数地址/名/大小/命中的 API 列表。
   - 顺带做内部符号检查：命中非公开名（`index2adr`、`luaH_*`、`luaV_*`、`luaD_throw`）的要人工排除撞名（`resize`/`void`/`int` 这类通用名会假阳性）。

2. **布局越界扫描**（`~/ghidra_scripts/DstLuaLayout2.java`）
   - 反编译每个候选，抓 `lua_xxx(EXPR, …)` 的**括号配平后的首参表达式**（必须支持单参数调用 `lua_gettop(L)`，否则一条都抓不到——踩过）。
   - 再在同一函数文本里搜 `(EXPR + 偏移)`；任何偏移都报，不要只查 0x10/0x18/0x28/0x30（固定清单会漏，也会显得像没跑）。
   - **必须分批**：MCP `run_ghidra_script` 有 30s 传输超时，500 函数/批约 2–4s；整包 2130 个一次跑会 timeout（脚本侧其实会跑完并写出文件，但结果状态未知，别依赖）。
   - 判定：命中要逐个看 EXPR 是不是真 `lua_State*`。典型误配：EXPR = `param_1`（C++ 对象）时，`param_1+0x10/+0x18/+0x28/+0x30` 会让指令级扫描产生大量假阳性。

3. **ABI 常量扫描**（`~/ghidra_scripts/DstLuaConstScan.java`）
   - 立即数 `0xffffd8f0/ef/ee`（-10000/-10001/-10002 = registry/env/globals）+ `0x78`（`sizeof(lua_Debug)`）。
   - `0x78` 单看没用（任何结构体都有），要和「调用 Lua API 的函数集合」取交集才可信。

## 已验证的判据 / 陷阱

- **`sizeof(lua_Debug)` 在 x64 是 0x78**：`4+pad + 5*8 + 4*4 + LUA_IDSIZE(60) + int i_ci`。引擎用固定 5 槽数组 + `+= 0x78` 步进 = 唯一真实的结构体尺寸依赖。
- 引擎取 L 的典型形态：`*(undefined8 *)(param_1 + 0xb0)`（cSimulation 的 m_L），后续全交给 API；这种形态说明「干净」。
- 不要把「伪索引常量」说成「内存布局」：那是 ABI 常量级耦合，结论里要分开列。
- `lua_gethookcount`/`lua_setallocf`/`lua_newstate` 在引擎里出现属正常（自建 state、hook 检测），不是旁路。

## 交付物

- `lua_api_callers.json`、`lua_internal_calls.json`
- `build/symmatch/vt2/batches5/o0*.tsv`（布局扫描命中，需逐条证伪）
- `build/symmatch/vt2/luaconst_hits.tsv`（ABI 常量）
- 报告模板见 `build/symmatch/manual/LUA_API_BOUNDARY_R759671.md`：API 普查表 → 布局扫描「0 真命中 + 误报清单」→ ABI 常量表 → 私有入口 → 复现命令。
