---
name: ghidra-lua-entry-ffi-triage
description: 用 Ghidra MCP 在带符号游戏二进制(优先 Android libDontStarve.so)里梳理 lua 层入口/引擎注册的 Lua 接口，判断哪些能用 LuaJIT FFI 调用、哪些必须留在 C 侧。
---

# 目标

回答"这些 lua 层入口/引擎注册的 Lua 接口能不能改写成 FFI 函数、哪些不可以"，结论必须落在某个**带符号二进制**的实际代码上。

**先问清对象**：是 (A) `lua_*` API 本体，还是 (B) 引擎自己注册给 Lua 脚本的接口(引擎暴露面)。用户说的"引擎注册的 lua 函数"= B。两者判据不同，别答错对象。

# 0. 落点

- `list_open_programs` → 选带符号目标(Android `libDontStarve.so`, AARCH64, 静态 LuaJIT, image_base 0x100000)。
- 导出实现体在 `0xc31xxx–0xc33xxx`(Klei 厂商扩展) 与 `0xc39xxx–0xc4xxxx`(核心 API)；引擎→Lua 入口是 GOT thunk `0x00e9xxxxx–0x00ebxxxxx`(`adrp x16,0xf1d000 / ldr x17,[x16,#off] / br x17`，槽在 `0xf1dxxx`)；`get_xrefs_to <thunk>` 列出引擎调用点。

# 1A. 若是 `lua_*` API（对象 A）

三层：GOT thunk(可拦截层) / VM+兼容实现区 / 引擎注册进 Lua 的入口。认锚点：`FUN_00c28bec` 裸 VM call、`FUN_00c28bb0` 受保护 call、`FUN_00c32f38` growstack、`FUN_00c2602c` lua_error throw、`FUN_00c2f774/8d4` index/newindex(内部再调 VM 跑 __index)。

# 1B. 若是引擎注册的 Lua 接口（对象 B）

- 引擎**不用** `luaL_register`(只有 stock `luaopen_package` 用)；逐个 `lua_pushcclosure(L,fn,0); lua_setfield(L,GLOBALSINDEX,"name")`。**xrefs to pushcclosure thunk 即全部注册点**。
- 成组注册点：`WorldSim::SimThread` 构造(一次注册十几个全局函数)、各 `X::Register`、`Lunar<T>::Register`(代理对象：建 metatable + `__index`/`__tostring`=`tostring_T`/`__gc`=`gc_T`/`__call`=`new_T`/方法表经 `thunk`)。
- 逐个 `batch_decompile` 被注册的函数，看函数体内部调了什么。

# 2. 判据

**对象 A（lua_* API）三条同时成立才可 FFI**：① 只依赖绝对字段/进程全局(`L+0x10`=global_State/`L+0xNN`)，不读 C 帧 `base(L+0x20)`/`top(L+0x28)`；② 不重入 VM；③ 不 longjmp(不调 error/luaL_error/luaL_check*/不触发栈增长溢出)。通常只剩纯状态访问器(厂商 executionerror 三件套 + get/setuserdata + gethook/mask/count + get/setallocf + atpanic + status + typename + version)。

**对象 B（引擎注册的 Lua 接口）**：
1. **内部(直接或传递)回调 Lua 的一律不适合** —— 函数体出现 `lua_call/lua_pcall/luaL_loadbuffer/lua_dump/lua_gc`、调 Lua 函数、跑元方法/`__gc`、或纯栈操作。
2. **硬约束**：`int(lua_State*)` 形包装即使内部纯 C，也**不能**被 FFI 直调 —— FFI 不建 Lua C 帧，`base/top` 仍指调用方 Lua 帧，`luaL_check*(L,1)` 读垃圾、`lua_push*` 错位丢返回值。
3. 所以**真正可 FFI 的是包装内部那个普通 C 例程**（`ffi.cdef` 绑它），不是 Lua 包装本身。

# 3. 输出

- 分类表：接口 / 地址 / 反编译所见关键调用 / 可否 FFI / 命中哪条判据；已取证的写地址，仅按同族形状归类的标 `[INFERENCE]`。
- 对象 A 必说的方向性结论：FFI 只能**调用** C 符号，不能**提供**引擎 GOT 导入入口 ⇒ 引擎→Lua 侧入口/兼容层架构上不可能用 FFI 改写。
- 指出仓库自研桥落点(如 `GiType` 签名型 trampoline：`injector/GameInjectorApply.cpp::read_arg/push_ret` 调 `_luaL_check*/_lua_isnoneornil/_lua_push*`，`GiType::LuaCFunction` 原样安装)天然落进"不可 FFI"类。
- 用 `learn` 记录：地址布局 + 注册机制 + 内部锚点表 + 判据，避免下次重推。
