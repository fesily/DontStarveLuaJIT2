---
name: dst-mod-luajit-fingerprint-mask
description: "让受保护 mod 看不到 LuaJIT 特征（PUC 5.1 抹平）：改 jit.runtime 的 HideGlobalJIT mask、按源码定值、离线+游戏内验证。Use when: 扩展/修改 HideGlobalJIT 指纹 mask、mod 检测 LuaJIT、'跟 PUC 5.1 不一致的地方都抹平'、验证 mod 在 LuaJIT 下的行为。"
---

# DST LuaJIT 指纹 mask（PUC 5.1 抹平）

## 位置

- 实现：`Mod/plugins/jit_runtime.lua` → `HideGlobalJIT(ctx)` 末尾调用 `MaskPuc51Fingerprint(ctx)`；沿用既有 `HideGlobalJIT` 开关（默认开），**不加新选项**。
- `Mod/plugins/` 与工坊 mod 3444078585 的 `plugins/` 是同一 inode（目录联接）⇒ 改动客户端/服务端即时生效，无需重新发布。

## 原则：按源码定值，不要运行时探测

先查本树源码（`luajit/src/*`、`src/lua51/src/*`）再决定遮什么：

1. `luajit/src/lj_arch.h`：默认 `LUAJIT_ENABLE_LUA51COMPAT=1` 驱动一大批 5.1 兼容开关（`LJ_DS_STRING_DUMP_FIX`、`LJ_DS_HOOKTABLE`、`LUA_COMPAT_MATH`、`LJ_UNPACK_PATCH`、`LUA_COMPAT_STRFMT`…）——**语言层差异大多已被 VM 自己修掉**。
2. `LUA_COMPAT_DISABLE_FUNCTION_BUILTIN_INFO = LUAJIT_ENABLE_LUA51COMPAT` ⇒ `tostring(C函数)` 不打印 `builtin#`（本构建 116 个库函数 0 命中）⇒ **builtin 探测无需 mask，别写运行时探测**。
3. `lib_init.c`：`lj_lib_load`（随 VM 打开）含 `jit` ⇒ 清 `package.loaded.jit` 后 `require("jit")` 永久失败；`lj_lib_preload` 含 `ffi` ⇒ 可重载，**保留 `package.preload.ffi`**，只清 `package.loaded.ffi`。
4. LuaJIT 独有可 require 名：`jit.*`（lib_jit.c）、`table.new`/`table.clear`（lib_table.c）、`string.buffer`（lib_string.c）——PUC 5.1 都没有。
5. `lib_debug.c:255/266` 注册 `debug.upvalueid/upvaluejoin`（PUC 5.1 没有）⇒ 置 nil。
6. `string.dump`：PUC 头 = `LUA_SIGNATURE "\033Lua"` + `LUAC_VERSION 0x51` + `LUAC_FORMAT 0`（`src/lua51/src/lua.h:30`、`lundump.h:28,31`）；LuaJIT = `\x1bLJ` + GC64 `BCDUMP_VERSION 0x80`（`lj_bcdump.h`）。实测同函数：stock 133 B vs LJ 72 B；**stock 头里只有 magic/version/format 稳定**（其后尺寸字节随 VM 状态变，两次 dump 可不同）⇒ 只复刻稳定前缀（`"\27Lua\81\0"`）并按非 LuaJIT 长度补足（×2）。别用被 dump 函数的 env 判归属（会误伤 `jit.bc`/`bcsave` 这类“分析 mod 函数”的工具）。
7. `newproxy(fn)` 可调用代理是本树补丁（`lj_arch.h:939-940`、`lib_base.c:622`）；stock 只接受 nil/boolean/proxy，报 `bad argument #1 to 'newproxy' (boolean or proxy expected)`。

## 两层落地（缺一不可）

- **mod env 级前端（无条件，尾调用也拦得住）**：在 `ModManager:InitializeModMain` hook 里给非豁免 mod env 换 `env.require` / `env.string`（副本 + 伪造 dump）/ `env.newproxy`。
- **全局兜底（显式 `GLOBAL.*` 直取）**：包 `_G.require` / `string.dump` / `newproxy`，调用栈上**跳过 C 帧、自身 mask 帧、游戏全局环境帧**取第一个“有主”帧判归属——游戏里 pcall/require 被注入器用 Lua 包过，只取“第一个 Lua 帧”会停在引擎包装上。
- 归属记录：hook 里把 mod env 记进弱表；豁免工具链自身 env（`ctx.mod_env`）与 `luajit_compatible` mod（后者照旧注入 `env.jit`）；工具链/引擎/控制台工具保持真实 API。

## 已知边界（写进注释/文档）

- `GLOBAL.string.dump(...)` 的**尾调用**写法（`return GLOBAL.string.dump(f)`）替换掉 mod 帧，栈判定看不到（env 级前端覆盖常规写法）。
- worldgen 状态走 `Mod/modworldgenmain.lua`（只藏 `jit`），`HideGlobalJIT` 不在那里执行。
- `package.preload.ffi` 保留（可重载性换一点指纹残留）。

## 验证

1. 离线：`python tests/plugin/run_jit_runtime_mask.py`（spec：`tests/plugin/jit_runtime_mask_spec.lua`；ctest `plugin_jit_runtime_mask`）。覆盖：mod 视角 stock 化、引擎/工具链不受影响、Lua pcall 包装后仍拦、尾调用 env 前端、plugin-env 不误伤、compat mod 豁免、dump 前缀+长度、newproxy 行为。
2. 游戏内：`builds/moyuxuanli_decoded/game_env_test.py force3`（专用服务器 + 注入器 LuaJIT + 探针 mod）；探针只看 `[probe]` 行：期望 `jit_global=false`、`ffi require ok=false`、`require jit/jit.opt=false`、`table.new/string.buffer=false`、`upvalueid/upvaluejoin=false`、`string.dump head=?Lua`、`newproxy(fn) ok=false`。探针 mod 的 env 只有白名单全局——一律 `GLOBAL.*`（且探针必须有 `GLOBAL`/`env` 字段才能在离线 spec 里模拟）。
