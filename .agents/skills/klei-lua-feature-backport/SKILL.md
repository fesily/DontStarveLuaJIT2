---
name: klei-lua-feature-backport
description: "Back-porting binary-only Klei Lua 5.1 features into src/lua51 with LUA_KLEI_* switches, matching struct offsets exactly"
---

# 把 Klei 的 Lua 二进制特性回填到 src/lua51（带开关）

## 何时用
出货二进制里有、vendored 源码（`src/lua51/src`）还没有的 Lua 改动，需要落回源码并保持 ABI 与二进制一致。

## 步骤

1. **先判类别**，别把编译产物当新增：
   - `grep -rn "Klei" src/lua51/src/*.c src/lua51/src/*.h` 与 `grep -rn "LUA_KLEI_" src/lua51/src/lua.h` —— 带注释的才是已入源码的增量（如 `lua_setexecutionerror`、`lua_settimeslice`、`luaC_callGCTM_ForFinalizingUserData`、`LUA_GCALLOWGCSTEP`）。
   - 宏外置副本（`luaC_checkGC`、`luaK_codeAsBx`、`luaM_malloc`…）与函数拆分件不算新增。
   - 5.2/5.3 风格名字但语义是 stock 的（`luaL_pushmodule`→`luaI_openlib`、`suffixedexp`→`prefixexp`、`gotostat`→`breakstat`、`funcnamefromcode`→`auxgetinfo`、`luaH_newkey`→`newkey`、`luaV_arith`→`Arith`）先改名，不要包成“新增”。

2. **从二进制取三样东西**：字段偏移（反编译读 `+0xNN`）、入口语义（调用者 + 常量/字符串）、数据表（`strchr` 用的字符集、扩展名白名单、模式串 `"wa+"`）。

3. **加开关**到 `lua.h` 的 Klei 块（默认 1），并在 `lua51.def` / `lua_head.h` 加导出。

4. **落字段 + 配套三处**（最容易漏）：
   - 结构体：`Proto` 末尾加指针（`maxstacksize` 之后 → +0x78）；`lua_State` 末尾加字节（`allowed_gcstep` 之后 → +0xC1）。
   - 构造：`luaF_newproto` 置 NULL。
   - GC：`traverseproto`（lgc.c）`stringmark()`，否则字符串被回收。
   - 初始化：`preinit_state`（lstate.c）清零，否则是垃圾字节。

5. **编译器实测偏移**（不靠手算）：写探针 `offsetof` 程序，`gcc -m64 -I. probe.c` 跑一遍，和二进制对齐后再往下写。

6. **C89 约束**：Lua 5.1 源码要求声明在语句之前；插入护栏时把 `FILE **pf = newfile(L);` 拆成声明 + 赋值。

7. **验证**：
   - 全部 `.c` 编译：`gcc -m64 -O2 -c -I. -o out/$f.o $f.c`（排除 `lua.c/luac.c/new.c/print.c`）。
   - 负向：`-DLUA_KLEI_XXX=0` 再编一遍，确认特性真的消失。
   - 运行时：MinGW 链接除 `loadlib.c` 外的对象，`luaopen_package` 打桩；`luaopen_io` 必须经 `lua_cpcall` 调用（io 库把表装进 C 函数环境，顶层直调会 panic `no calling environment`）。
   - 回归用例：`src/lua51/test/klei_additions_test.c`。

## 坑

- 只加字段不改 GC/init → 悬垂指针或随机行为（实测 `allowed_unsafedata` 拿到 `0x4F`）。
- `strcmp` 比对扩展名要把结尾 NUL 算进去：二进制比较 5 字节对应 `path+len-4`，`.json` 是 6 字节对应 `path+len-5`。
- `strtok` 会改写入参：护栏函数接收 `strdup` 后的副本。
