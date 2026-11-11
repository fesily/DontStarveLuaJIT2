---
name: luajit-injector-unhooked-layout-audit
description: "Audit which non-hooked functions of an engine-embedded PUC Lua still hardcode VM object layout and will break under a LuaJIT-based API injector (intersect replaced-API set with engine direct callers, classify layout users, prove dead code, no-op hook)."
---

# 目的

给定「游戏 exe 静态链接了一份被厂商改造过的 PUC Lua 5.1」+「一个把 API 换成 LuaJIT 的注入器」：
找出**哪些没被劫持的函数仍在用 PUC 的对象布局**，也就是换成 LuaJIT 后会读错/写坏的地方。

## 1. 先定"已劫持集合"

不要凭印象：直接读注入器的替换清单。

```bash
# DontStarveLuaJIT2 基线
grep -oP '^\s*([A-Za-z_]\w*)\s*=' src/DontStarveInjector/plugins/plugin_core_vm/GameLua.def | tr -d ' ='
# 也可看 LuaApi.hpp 的 LUA_API_DEFINES 系列
```

得到 100+ 个名字（含 `lua_newstate`、`lua_newthread`、`luaL_newstate`、所有 `luaopen_*`）。

## 2. 找"引擎直接调用、且不在替换集合"的 Lua 侧函数

需要两份导出（Ghidra MCP 脚本在 `~/ghidra_scripts/`）：

```
DstExportNames.java      <out.tsv>   # addr / end / size / name / source / evidence
DstExportCalleeSets.java <out.tsv>   # addr / name / size / callee1,callee2,...
```

然后把**调用者限定在 Lua 区块之外**，求差集：

```python
BLOB=(0x140482210,0x14049f790)          # 用 DstRegionGaps/边界扫描确定
replaced = {...}                         # 第 1 步
blob = {name: addr for addr,name in names if BLOB[0]<=addr<=BLOB[1]}
for caller_addr, caller_name, callees in callee_sets:
    if BLOB[0] <= caller_addr <= BLOB[1]: continue      # 只要引擎侧
    for c in callees:
        if c in blob and c not in replaced: report(caller_name, c, blob[c])
```

注意 `thunk_` 前缀和 `DLL::` 前缀要剥掉再比较（xref 名 != callee 名是常见假阴性来源）。

结果通常只有个位数 —— 这就是"注入器管不到、却会被引擎执行的 PUC 代码"。

## 3. 分类：谁真的碰布局

对第 2 步的每个函数，反编译看是否出现下列任一特征（有即是布局依赖）：

| 特征 | 含义 |
|---|---|
| `== 6` / `CMP dword [x+0x8], 6` | `TValue.tt`（LUA_TFUNCTION 等） |
| `byte [x+0xA] == 0` | `Closure.isC` |
| `[x+0x20]` 再 `[+0x78]` / `[+0x40]` | `Closure->l.p` → Proto 字段 |
| 对 `L` 取 `+0x10/+0x18/+0x28/+0x30/+0x38` | `top/base/ci/savedpc/stack_last` |
| 调用内部符号（`index2adr`、`luaS_newlstr`、`luaH_*`、`luaD_throw`） | 绕过 API 边界 |

全局变量操作（如写 float 全局、读错误串指针）**不算**布局依赖 —— 换成 LuaJIT 也无害。

## 4. 验证"这些内部函数到底跑不跑"

两个反证方向，任一成立就是死代码：

- **初始化点已被替换**：例如 Klei 的 `L+0xC1` 只在 `lua_newstate` / `luaE_newthread` 里置 1；这两个函数在替换集合里 ⇒ 读它的人拿不到有意义的值。
- **入口库已被替换**：例如 `luaopen_io` 在替换集合里 ⇒ PUC 的 iolib（以及它内部的路径护栏）根本不会被注册。

配合 `DstFlagC1Scan.java` 这类"偏移 X 的读写点扫描"可以一次证明某字段只有 N 个访问者。

## 5. 修法：优先"空操作 hook"，不要移植布局

替换后的 VM 没有原字段，正确做法是让写侧变成 no-op，而不是在 LuaJIT 里重建结构。
前提是先确认读侧契约，例如：

```
引擎: luaL_loadbuffer(L, src, n, "@"+path)  →  writer(L, -1, path)
reader(PUC): return *(Proto+0x78)+0x18        // 裸路径
reader hook: src[0]=='@' ? src+1 : src        // 已经做了同样的剥离
```

⇒ writer 直接空实现即可。hook 用签名扫描（`MemorySignature`）+ `ds::gum::replace`，与本仓库
`GameLuaContextJit.cpp` 的 `InstallGameFuncChunkNameHook()` 放一起。

签名要用反汇编现取，别猜。取法是 `disassemble_bytes` 目标函数前 48–64 字节，把
`CALL rel32`、`Jcc rel8` 的位移字节改成 `??`：

```
48 89 5C 24 10 56 48 83 EC 20 4D 8B D0 48 8B F1
E8 ?? ?? ?? ?? 83 78 08 06 48 8B D8 75 ?? 48 8B 10
80 7A 0A 00 75 ?? 48 83 C9 FF          # lua_setchunkname (r759671)
```

## 6. Ghidra 侧的坑

- `load_program_from_project` 之后当前程序可能仍是别的库；**跑任何 apply 脚本前先 `switch_program`** 到目标 exe（否则会对着 32 位 macOS 程序跑，`AddressOutOfBounds` 在 0x14.. 处炸，虽然无写入）。
- 跨架构迁移留下的"引擎符号盖在 Lua 库函数上"必须清掉：判定方法是反编译体，看调用的是 `lua_*` API 还是引擎类。本仓库历史上有 9 个（`lua_pushcclosure`、`luaO_chunkid`、`luaL_checkany`、`add_value`、`pusherror`、`ll_register`、`aux_close`、`g_write`、`lua_setlevel`）。
- 名字风格要贴 5.1 而不是 5.3：`prefixexp` / `breakstat` / `auxgetinfo` / `newkey` / `freestack` / `findindex` / `lessequal` / `Arith` / `luaI_openlib` / `luaL_typerror` / `luaL_loadfile`。
