---
name: dst-item-server-callstack-guard
description: "DST unravel/weave fails with local E_BALANCE_MISMATCH: locate the PC anti-tamper call-stack guard and its chunkname helper (Win 0x140483B20 / Linux 0x4AC6D0), name it in Ghidra, hook it for LuaJIT"
---

# DST item-server call-stack guard (E_BALANCE_MISMATCH)

## When to use

- DST 拆解/编织（unravel/weave）失败，`client_log.txt` 出现
  `[BarterLoseItem_Complete Failure:200] {"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}`
- 玩家看到 "Failed to contact Klei Servers"（写死文案，非真断网）
- 换了 Lua VM（LuaJIT / PUC fork）后**必然**复现、重启无效、关 mod 就好
- 不要先去查签名/价格链：先确认这条 guard

## 机制（r759671 起，Windows + Linux 都有）

Lua 绑定 `TheItems:BarterLoseItem` 在发请求前：

1. `traceback 格式化器` 用 `lua_getinfo(L,"Slf",&ar)` 逐帧取函数，再调**引擎私有 helper** 从函数对象取 chunkname，拼成
   `[C]:-1[string 'scripts/...']:LINE...`
2. 与硬编码期望栈逐字节比较（Windows `DAT_140680C08`；Linux 两组：`barterscreen.lua:86` 与 `:114`）
3. 不等 → **本地**生成 `{"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}` 并走失败回调；服务端未收到请求

helper 的语义（无符号、PC-only）：

```c
char *luaGetFuncChunkName(lua_State *L, int idx) {
  TValue *tv = <取栈值指针>;                 // Klei 改造的 lua_topointer 返回 TValue*
  if (*(int*)(tv+8) != 6) return 0;          // LUA_TFUNCTION
  void *cl = *(void**)tv;
  if (*(char*)(cl+0xa) != 0) return 0;       // isC == 0
  void *p = *(void**)(cl+0x20);              // Proto*
  void *n = *(void**)(p+0x78);               // chunkname holder
  return n ? (char*)n + 0x18 : 0;
}
```

LuaJIT 的 GCfunc/GCproto 布局不同 → `tt@+8` 不是 6 → 每帧返回 NULL → 渲染 `[**untrusted** …]` → guard 必挂。

## 定位（Windows）

```bash
# 字符串
grep -a -o -b "[**untrusted** %s]:%d" exe
grep -a -c "Slf" exe
# 反汇编：找引用 "Slf"/"[string '%s']:%d" 的 lea → 格式化器
# 格式化器里 ASCII "Slf" 之后、返回 char* 的 call = helper
```

r759671 基线：
| 物 | 地址 |
|---|---|
| helper | `0x140483B20`（`lua51::luaGetFuncChunkName`） |
| 其 callee（返回 TValue*） | `0x140482210`（Ghidra 名 `lua_topointer`，实为 index2adr 语义） |
| 格式化器 | `0x1401010E0` |
| 期望栈串 | `0x140680C08` |
| 伪造 JSON | `0x1404FDC58` |

helper 签名（唯一命中，51 字节）：

```
48 83 EC 28 E8 ?? ?? ?? ?? 83 78 08 06 75 ?? 48 8B 00 80 78 0A 00 75 ??
48 8B 40 20 48 8B 40 78 48 85 C0 74 ?? 48 83 C0 18
```

## 定位（Linux，WSL Steam）

```bash
B="$HOME/.steam/steam/steamapps/common/Don't Starve Together/bin64/dontstarve_steam_x64"
grep -a -o -b "untrusted" "$B"                  # → 0x4E1220（文件偏移 == .rodata vaddr）
objdump -d -Mintel "$B" > /tmp/d.is
grep -n "# 4e1208\|# 4e120c" /tmp/d.is          # "Slf" / "[string '%s']:%d" 引用点 → 格式化器
# 该处 mov esi,-1; mov rdi,rbp; call <helper>
```

r759671 基线：helper `0x4AC6D0`，callee `0x4AAD50`，格式化器调用点 `0x1C137B`（`mov esi,-1; call 4ac6d0`）。
Linux 签名：

```
f3 0f 1e fa e8 ?? ?? ?? ?? 48 89 c2 31 c0 83 7a 08 06 75 ?? 48 8b 12 80 7a 0a 00 75 ??
48 8b 42 20 48 8b 40 78 48 8d 50 18 48 85 c0 48 0f 45 c2 c3
```

## Ghidra 命名规范（必做）

- 命名空间 `lua51`（见 `docs/ghidra-namespace-classification.md`）
- 名字 `luaGetFuncChunkName`，原型 `char * luaGetFuncChunkName(void *L, int idx)`
- plate comment 写：PUC 布局路径、唯一调用者（traceback 格式化器 / 调用栈 guard）、伪造 `E_BALANCE_MISMATCH` 的后果、LuaJIT 下失效原因与注入器替代实现、另一平台地址
- Windows/Linux 两个 program 用**同一名字**，互相在 comment 里交叉引用

### Headless Ghidra 的两个坑

1. `load_program` **不会**替换同名 program：`success` 后 `switch_program` 仍可能是旧对象。用不同文件名（如 `dst_linux_r759671`）加载，并用 `search_byte_patterns` 校验字符串地址/`.text` 长度确认是最新。
2. ELF 的 `endbr64` 入口常被并进相邻函数：`getFunctionAt` 返回 null、`getFunctionContaining` 也 null，但 `getFunctionsOverlapping(AddressSet)` 能找到父函数。先 `DisassembleCommand`，`parent.setBody(parent.getBody().subtract(range))`（返回 void），再 `fm.createFunction(...)`，否则 `OverlappingFunctionException`。

## 补丁（本仓库）

`plugin_core_vm/game/GameLuaContextJit.cpp`：

- `GameLuaFuncChunkName(L, idx)`：`GetGameLuaContext().api` 的 `lua_type` → `pushvalue` → `lua_getinfo(">S")` → `settop` 还原 → `ar.what[0]=='C'` 返回 NULL → 返回 `ar.source` 剥 `@`
- `InstallGameFuncChunkNameHook()`：`MemorySignature` + `ds::gum::replace`，在 `ReplaceApis()` 末尾调用一次；失败只 warn（签名布局变化）
- 目前 `#ifdef _WIN32`；Linux 需要同样分支（用上面 Linux 签名）

`luajit/src/lj_debug.c`：`lua_getinfo_game` 的 `@` 剥离必须写 `iar.source`，写在 `ar->source` 会被 `memcpy` 覆盖（死代码）。

## 验收

- `DontStarveInjector_client.log`：`hooked game lua chunkname helper at …`
- `client_log.txt`：`[BarterLoseItem_Complete Success:200] {"Error":false,…,"NewCurrency":…}`，不再出现 `E_BALANCE_MISMATCH`
- 判别真伪：`Failure:200` + `ErrorCode` 是本地伪造；真正的网络失败没有该 JSON
