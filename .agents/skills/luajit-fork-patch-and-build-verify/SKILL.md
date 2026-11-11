---
name: luajit-fork-patch-and-build-verify
description: "Editing/building/verifying the bundled LuaJIT fork (luajit/src) on Windows: LF/CRLF pitfalls, LJ_DS_* switch convention, MinGW build, export+probe verification"
---

# 改这个仓的 LuaJIT fork（luajit/src）时

## 1. 编辑源码：必须保住换行符
Windows 上 `open(f,"w")` 会把 `\n` 写成 `\r\n`。本仓 `luajit/src` 多数文件是 **LF**，但 `lj_io_patch.h` 是**混排**（部分 CRLF、部分 LF）——用 Python 重写整文件会把 diff 变成整文件重写。

做法（二选一）：
- 文本级：`open(f, encoding="utf-8", newline="")` 读、`open(f, "w", encoding="utf-8", newline="")` 写。
- 混排文件：读 `rb`，用**字节锚点**替换，新插入的行沿用相邻行的 EOL（例如 `b"...\n#elif ...\n"` vs `b"...\r\n#define ...\r\n"`）。

改完用 `git -C luajit diff --numstat` 自查：只应看到你真正动的行数（几十行），一旦看到几千行，就是 EOL 被改了 → `git checkout --` 重来。

## 2. 沿用以有的 DS 开关约定
`luajit/src/lj_arch.h` 里：`#ifndef LJ_DS_XXX / #define LJ_DS_XXX LJ_DS`（或 `LUAJIT_ENABLE_LUA51COMPAT`），每个都带 provenance 注释。新功能要：字段/遍历/初始化/入口全部 `#if` 包住，`lua.h` 里加同风格的 `LUA_API` 声明块，关掉后符号应完全消失。

## 3. 构建（本机可用 MinGW）
```bash
cd luajit/src && mingw32-make -j4               # 产出 lua51.dll + luajit.exe
mingw32-make -j4 XCFLAGS=-DLJ_DS_XXX=0           # 关开关的对照构建
touch lj_load.c                                  # 头文件改动后 lj_load.o 可能不重编（LJ_IO_PATCH_IMPLEMENTATION 在那）
```
注意：`lib_io.c` 的 `__MINGW32__` 分支引用 `lj_fseeko64/lj_ftello64`，HEAD 曾缺声明（已在 `lj_io_patch.h` 补 `_fseeki64/_ftelli64` 包装）；MSVC 分支没这问题。

## 4. 验证
- 导出：`objdump -p lua51.dll | grep <symbol>`（`LUA_BUILD_AS_DLL` 下 `LUA_API` 就是 dllexport）。
- C 探针：`gcc -I luajit/src probe.c -Lluajit/src -llua51`，把 `lua51.dll` 放同目录，用 `cmd.exe /c probe.exe` 跑（bash 直接执行 .exe 会 command not found）。
- 该 fork 的 `lua_dump` 是 3 参（`L, writer, data`），不是 5.1 的 4 参。
- GC 相关改动要有“大量同长度字符串 + 多轮 full GC”后再读的用例；但注意这种探针**探测不到**“字符串已被回收、内存尚未复用”，负向对照全绿不代表 mark 可省——按 GC 契约保留 mark。
