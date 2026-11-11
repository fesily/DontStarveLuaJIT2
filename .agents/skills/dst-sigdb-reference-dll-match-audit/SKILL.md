---
name: dst-sigdb-reference-dll-match-audit
description: "Verify DST reference lua51.dll build flags (/O2 /Ob2) by byte-matching against the game, then audit the regenerated signature DB offline (uniqueness + anchor alignment)."
---

# 前提

DST 签名库由 `signature_updater create` 生成,输入是 `Mod/deps/lua51.dll`(参考构建,LUA51_PATH)+ 游戏 exe 的静态扫描。参考 DLL 的优化开关必须与游戏内静态 Lua 一致,否则字节匹配失败。

## 1. 先审参考 DLL

```python
# 解析 PE: machine / Rich header / import 表 / 导出表
```

必须满足:

- machine `0x8664`;
- Rich header 显示 VS2008(build 30729 一类),即用 VS2008 cl 构建;
- 导入 `MSVCR90.dll`(/MD,与 x64 Release 工程的 RuntimeLibrary=2 一致);
- 导出 131 项(含 `lua_setfuncchunkname` / `lua_getfuncchunkname`)。

编译命令参照 `src/lua51/build_lua51.bat`:`cl /LD /O2 /Ob2 /MD ... /DLUA_BUILD_AS_DLL`,直接列 29 个 .c,**不要**走 .sln/msbuild(该环境没有 .NET)。

## 2. 三个易失败函数的字节对比

从 DLL 导出表取 RVA,与游戏 exe 的对应函数逐字节比:

| 函数 | 预期 |
|---|---|
| `luaL_pushresult` | 仅 `call rel32` 不同 |
| `lua_getupvalue` | 仅 `call rel32` 不同 |
| `lua_isstring` | `call` 位移 + `lea` RIP 相对位移不同 |
| `luaL_checklstring` / `luaL_prepbuffer` | 仅位移 |
| `luaL_loadstring` | 应 40/40 全同 |

若差异明显多于 4~8 字节,说明参考构建没开 `/Ob2`(同 TU 的 `lua_type`/`aux_upvalue`/`emptybuffer` 未内联)。

## 3. 生成时看这几条日志

```
update signatures [luaL_pushresult:0x...]: 0 to 7904
update signatures [lua_getupvalue:0x...]: 0 to 5792
update signatures [lua_isstring:0x...]: 0 to 1312
create signature [lua_setfuncchunkname]: 6304
```

RC=0 以外还要求日志里 **没有** `no byte match` / `deferring` / `already claimed`。

## 4. 离线校验整份 JSON(不依赖工具自证)

- `offset` 是相对 **Lua 模块基址**的偏移;基址可由任一已知函数反推:`base = target_va - offset`(客户端 RVA 0x482210,服务端 0x41B110)。
- 扫描区间 `[base, .text 末尾]`(注意:必须从 base 开始,否则 base 之前的同名字节序列会造成假歧义)。
- 每条 pattern 必须:① 唯一命中;② `hit + pattern_offset == base + offset`(`pattern_offset` 为负表示锚点在函数入口之后)。
- 两个条件全部满足才算库可用;否则游戏启动时会走整库重解析。

## 5. 常见误判

- 用十进制/十六进制混算 `target - offset` 会差 0x30、0x100 之类,先统一为整数再算。
- 直接整文件扫描(而非从 Lua 基址起)会把 `.text` 前缀里的通用序章当成重复命中,误报几十条不唯一。
