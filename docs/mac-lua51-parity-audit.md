# macOS DST 内嵌 Lua 5.1.4 ↔ src/lua51 逐函数行为审计

日期：2026-10-03 · 对象：`dontstarve_steam`（macOS 客户端，x86:LE:32，带本地符号）
基准：`src/lua51`（工作树，含 Klei 改造）· Android（LuaJIT）按用户要求不在本审计范围。

## 0. 结论摘要

- 可同名匹配 **541** 个函数：**517 个 identical（95.6%）**、**24 个 modified**、0 个无法判定。
- 二进制新增 Lua 函数 **2 个**（均为 GC 扩展）：`luaC_callGCTM_ForFinalizingUserData`、`TimeLeftForGCTimeSlice`；
  另有 1 个"看似新增"实为宏改名：`luaL_openlib` ≡ 树的 `luaI_openlib`（lauxlib.h:27 `#define luaI_openlib luaL_openlib`，函数体逐指令一致）。
- 源码有、二进制无独立符号 171 个 —— 逐一分类为**内联**（clang -O2）或**未注册 static 被消除**或**未编译分支**，无"被删功能"遗漏。
- 分歧集中在 5 个区域：
  1. **GC 子系统（最大分歧）**：二进制是时间片驱动、6 状态、扫描期直接终结 userdata、延迟释放表的成体系改造；树的 `lua_settimeslice` 仍是记录用空桩，`luaC_step/singlestep/sweeplist/atomic` 仍为原版。
  2. **lstate 初始化/关闭**：`preinit_state` 未初始化 `L+0x70`（延迟表链）与 `L+0x74`（allowed_gcstep，`luaC_checkGC` 的门）；`lua_close` 走 `..._ForFinalizingUserData`。
  3. **字节码加载**：二进制 `luaU_undump` 无条件拒绝（"Disallowed functionality"），树仍是完整加载器。
  4. **io/os（Klei 引擎集成+沙箱）**：`io.open` 路径安检、`os_date` 重写、io 走 KleiFile VFS、标准句柄 close 语义改变等 10 项。
  5. **package/laudblib 杂项**：`package.path/cpath` 缺省在 mac 上也用 `data\scripts\...`、`findfile` 走 VFS、`db_errorfb` 用 `ar.source`、`errfile` 不剥离 `@`。
- 核心 VM（lapi/lvm/lparser/lcode/lstrlib/ltable/ldebug/ldo/ltm/lzio…）**全部一致**，说明 src/lua51 重建质量高；上述差异均为"树尚未复刻的 Klei 客户端行为"或"树自身的布局/初始化缺陷"。

## 1. 方法与可复现性

- 符号约定：Mach-O C 符号带前导下划线；`_luaD_call` = C `luaD_call`；Ghidra 反编译前缀 `lua51::`。
- 素材（已清理的临时目录 `.tmp_lua_audit/` 曾包含，皆可重建）：
  - 二进制全函数表（19,771 项）经 `list_functions_enhanced` 分页 + `artifact://` 回读；
  - 全部 541 个匹配函数经 `batch_decompile` 批量反编译落盘后逐函数人工比对（12 个并行审计 agent，按源文件分片）；
  - 库注册表直接从数据段内存读出（`list_globals` 定位 + `read_memory` + 函数表映射），不依赖伪代码；
  - 关键疑难处以 `disassemble_bytes` 指令级复核。
- ABI 对照（x86 32 位，二进制实测）：TValue=12B（value 8B + tt @+8）；`lua_State`：top+0x08, base+0x0C, l_G+0x10,
  ci+0x14, stack+0x20, base_ci+0x28, nCcalls+0x34, hookmask+0x38, allowhook+0x39, hook+0x44, l_gt+0x48,
  env+0x54, openupval+0x60, gclist+0x64, errorJmp+0x68, errfunc+0x6C, **延迟表链+0x70, allowed_gcstep+0x74**；
  `global_State`：gcstate+0x15, GCthreshold+0x40, totalbytes+0x44, gcpause+0x50, gcstepmul+0x54,
  panic+0x58, mainthread+0x68, **tmname 数组基址+0xA8**（+0xB0 = tmname[TM_GC]）。

## 2. 函数清点

| 类别 | 数量 | 说明 |
|---|---|---|
| 同名匹配 | 541 | 517 identical / 24 modified |
| 二进制无独立符号 | 171 | 内联 / 未注册被消除 / 未编译分支（见 §6） |
| 二进制新增 | 2 | `luaC_callGCTM_ForFinalizingUserData` @0x32f1ef、`TimeLeftForGCTimeSlice` @0x32f00c |
| 宏改名 | 1 | `luaL_openlib`(0x327697) = 树 `luaI_openlib`（逐指令一致，判 identical） |

误报排除：`hash_lookup@0x325049` 实为 libzip（`source/libzip/ziphash.cpp:199`）；`unpack@0x3148c2`、`error_set@0x31288d`、`printIGD@0x3171b0` 位于引擎区，非 Lua 核心；`src/lua51/src/new.c` 为逆向草稿、未参与编译。

## 3. 判定统计（按源文件）

| 文件 | identical | modified | 文件 | identical | modified |
|---|---|---|---|---|---|
| lapi.c | 73 | 0 | ltable.c | 17 | 0 |
| lbaselib.c | 42 | 0 | llex.c | 15 | 0 |
| lcode.c | 43 | 0 | lvm.c | 14 | 0 |
| ldebug.c | 22 | 0 | ltablib.c | 13 | 0 |
| ldo.c | 22 | 0 | lfunc.c | 10 | 0 |
| lstrlib.c | 29 | 0 | lobject.c | 9 | 0 |
| lmathlib.c | 29 | 0 | lzio.c | 5 | 0 |
| lparser.c | 32 | 0 | ldump.c | 4 | 0 |
| ltm.c | 3 | 0 | lstring.c | 3 | 0 |
| lmem.c | 3 | 0 | linit.c | 1 | 0 |
| lauxlib.c | 40 | 2 | lundump.c | 5 | 1 |
| loadlib.c | 12 | 2 | ldblib.c | 19 | 1 |
| loslib.c | 5 | 1 | liolib.c | 26 | 9 |
| lgc.c | 15 | 5 | lstate.c | 6 | 3 |
| (binary-only GC) | — | 2 | **合计** | **517** | **24+2** |

## 4. modified 明细（24 项同名函数 + 2 项新增）

### 4.1 GC 子系统（lgc.c 5 项，lstate.c 关联 3 项）★最大分歧
二进制是一套**时间片驱动的 6 状态 GC**，与树的原版（5 状态、工作信用步进）结构性不同：

- `lua_settimeslice @0x32f037`：二进制 `movss [0x4646a4],xmm0` 写入全局 float `_gc_timeSlice`；
  **树的 lgc.c:617-621 是空桩 `(void)seconds`**（注释已记录二进制行为，但实现未补）。
- `luaC_step @0x32f5b0`：改为 `StartLuaGCTimer@0xff6a5` + `while ((float)GetLuaGCTimer() < _gc_timeSlice)` 的时间预算循环
  （`TimeLeftForGCTimeSlice` 被内联 5 处）；状态 3 用 `sweeplist(count=1)` 在时间循环里扫；
  6 个 gcstate：**4 = 释放 L+0x70 延迟表链**，5 = finalize/pause（树枚举只有 5 个，GCSfinalize=4 直接 GCTM）。
- `singlestep @0x32f83e`：扫描完成后先进状态 4（对 `luaH_free` 逐个释放 L+0x70 上挂起的表），再进状态 5。
- `sweeplist @0x32f336`：
  (1) tt=7 userdata：**扫描期即调用 `__gc`**（保存/恢复 allowhook 与 GCthreshold=2*totalbytes）然后释放（树 freeobj 只释放）；
  (2) tt=5 table：若存在 `__gc` 则挂到 **L+0x70 延迟链**（保护 udata finalizer 期间仍被引用的元表），树立即 `luaH_free`。
- `atomic @0x330050`：**删除了 `luaC_separateudata(L,0)` 调用**（正常周期不再把可终结 udata 搬去 tmudata；只有 lua_close 调）；
  separateudata 的 xref 只有 lua_close。
- `luaE_newthread @0x3375a5` / `lua_newstate @0x3377c9`：字段初始化几乎全对（currentwhite 0x21、marked 0x61、rootgc=L、
  uvhead 自链、gcpause/gcstepmul=200、totalbytes=0x164 等），但二进制内联的 `preinit_state` 还会置 **L1+0x70=0、L1+0x74=0**；
  **树的 preinit_state（lstate.c:84-105）两者都没初始化** → 树构建中 `allowed_gcstep`（`luaC_checkGC` 的门，lgc.h:80-82）
  对新线程是未定义值；`reserved[8]` 还把字段位置推到 +0x78（32 位二进制为 +0x74）。
- `luaC_callGCTM_ForFinalizingUserData @0x32f1ef`（新增）：循环 tmudata 首元素 → 接回 mainthread 链 → makewhite →
  有 `__gc` 则调用（allowhook/GCthreshold 保存恢复）→ **清空 udata->metatable**。唯一调用者 `lua_close@0x337b8e`。
- `TimeLeftForGCTimeSlice @0x32f00c`（新增）：`(float)GetLuaGCTimer() < _gc_timeSlice`；无直接调用者（全部内联进 luaC_step）。
  注：数据区 0x4f4e8b 的"引用"位于一张 ULEB128/增量表内，并非函数指针。
- `lua_close @0x337b57`：调 `..._ForFinalizingUserData`（树的 lstate.c:204 调 `luaC_callGCTM`，从不清理元表）；
  其余一致（separateudata(L,1)、errfunc=0、保护循环 callallgcTM、close_state）。
- 引擎侧协议（本次补证，解释 Klei 为何要这两样东西）：`cSimulation::IncrementalGarbageCollect@0x0fd061` 每帧
  `used=lua_gc(L,LUA_GCCOUNT,0)` → `used > nGCThreshold` 时 `lua_gc(L,LUA_GCCOLLECT,0)` 并重设阈值 `used*1.5` →
  `DoGarbageCollection(flTimeStep,L)@0x0f7746` = `lua_settimeslice(flTimeStep)` + `lua_gc(L,LUA_GCSTEP,0)`；
  `cSimulation::DoGarbageCollect@0x0fd713` = 强制 `lua_gc(L,2,0)`。
  `lua_gc` 的全部调用点（Update/Reset/NewLuaState/SimThread/Main/~cSimulation/luaB_* 等）中**没有任何一处传 8**（LUA_GCALLOWGCSTEP），
  且 `luaB_collectgarbage` 的选项表也无 8 → 客户端 `allowed_gcstep` 恒为 preinit 的 0，
  **分配触发的 GC（luaC_checkGC）在 mac 上完全关闭，GC 全部由引擎按帧预算驱动**（TimeLeftForGCTimeSlice）。

### 4.2 io/os（liolib.c 9 项 + loslib.c 1 项）★Klei 引擎集成/沙箱
- `io_open @0x3308f2`：**新增路径安检** —— 反斜杠转 `/`；绝对路径或含 `:` → `luaL_error("invalid filepath")`；
  相对路径按 `/` 分段，`..` 净深度 < -2 报错。打开走 `fopen_external`（仅 `mode=="w"` 按写，`a/r+/w+` 一律按读）。
- `luaopen_io @0x3303af` / `createstdfile @0x330584`：**标准句柄不再有 io_noclose 环境**，
  改为私有环境 `__close=io_fclose` → `io.close()`/`io.stdin:close()` 会真的关闭标准流（树是 io_noclose 拒绝 + `cannot close standard file`，该串在二进制中不存在）。
- `io_gc @0x3315f1`：新增 `f!=stdin/stdout/stderr` 守卫才 aux_close。
- `io_fclose @0x33061f`：`*p=NULL` 仅在成功时；fclose→`fclose_external`（KleiFile 池化/DecRef）。
- `io_pclose @0x3305e2`：退化为固定失败三元组桩（无 popen 注册，死代码）。
- `g_write @0x330bd4`：数字走 `sprintf("%.14g")` + `LuaIntegration::fwrite_external`（对 stdout 特判不写出直接返回 1）；
  字符串按 `==l` 判成功。树走 libc fprintf/fwrite。
- `g_read @0x330d94` / `io_readline @0x331325`：`clearerr/ferror` 变桩（空/恒 0）→ **读错误分支成死代码**（不再返回 nil+strerror+errno，也不再抛错）。
- `os_date @0x33484a`：**重写为单次 `strftime(buf[256])`**，失败 → `luaL_error("date format too long")`；
  树为逐转换符循环（buff[200]、无错误路径）→ 空/超长格式、无效转换符、长字面文本行为不同。
- io 的 open/close/read/gets/write 底层全部经 KleiFile VFS（ferror/clearerr 为桩）；fflush/fseek/ftell/setvbuf 仍为 libc。

### 4.3 loadlib / ldblib / lauxlib / lundump（配置与输出差异）
- `luaopen_package @0x333253`：二进制在 mac 上仍用 `LUA_PATH_DEFAULT="data\scripts\?.lua;data\scriptlibs\?.lua"`、`CPATH=""`
  （即 luaconf.h 的 `_WIN32` 分支常量 @0x3b6ace），但 `LUA_DIRSEP` 保持 POSIX（`/\n;\n?\n!\n-`）；
  **tree 的 luaconf.h 在非 `_WIN32` 下会给 `./?.lua;/usr/local/share/...`** → 若按 tree 构建 mac 版，package.path 与官方不一致（影响 mod 脚本查找）。
- `findfile @0x333ce3`：`readable()` 改走 `_fopen_external`（KleiFile::OpenWrite/OpenRead + DEV 层 + Wait/Close），
  **文件存在性判断走引擎 VFS/压缩包层**，非 cwd stdio。
- `db_errorfb @0x32bf86`：改用 `ar.source`（+0x10，剥前导 `@`）而非 `ar.short_src`（+0x24）→ traceback 在 `=` chunk 名、超长路径、字符串 chunk 情形输出不同；其余（"LUA ERROR stack traceback:"、"(%d,1)"、`in function '%s'`/`?`/`in main chunk`）一致。
  **复核**：用 `db_getinfo@0x32b6a6` 的字段映射交叉验证（该函数把 `local_6c`→`"source"`、`local_58`→`"short_src"`），确认 `db_errorfb` 里被格式化的是 `source`；
  而树 ldblib.c:353-359 的注释自称"short_src … macOS decompile @0x0032bf86"——注释与实测不符（代码也按 short_src 实现），需一并修正。
- `errfile @0x32802a`：**不剥离 `@`**（树 lauxlib.c:561 有 `+1`）→ "cannot open @xx.lua: ..." 形式；非字符串回退用零填充 Buf[8]（一致）。
- `luaL_loadfile @0x327dfa`：① 树的两条拦截路径（hashbang/编译字节码）不 fclose，二进制先 fclose（**指令级复核**：0x327ee0 判 filename!=NULL → 0x327efa CALL `fclose_external`；0x327f2c-0x327f33 编译字节码路径无条件 fclose_external 后 return 1）→ 树有句柄泄漏；
  ② stdin+'#' 路径二进制把残留栈值 6 当 `%s` 实参传给 `lua_pushfstring("...Hashbang blocked.")`（**指令级复核**：0x327e9f `MOV [ESP+8],6` 供前一次 `lua_pushlstring("=stdin",6)`，随后 0x327edb 直接 CALL `lua_pushfstring` 未重写该槽）→ 潜在坏指针解引用，树传 filename（"(null)"）反而安全；
  ③ 二进制的文件 I/O **全程走引擎 VFS 包装**：打开 `fopen_external@0xff6db`（strcmp(mode,"w")? KleiFile::OpenWrite : OpenRead，带 "DEV" 层 + Wait；超时 6 → Close+NULL）、取字符 `getc_external@0xff77b`（KleiFile::Read 1 字节）、回退 `ungetc_external@0xff7a3`（Tell-1+Seek）、EOF/读 `feof_external/fread_external`（见 getF）、错误 `ferror_external=恒 0`（使 readstatus 分支死代码）、关闭 `fclose_external@0xff7cd`（句柄表摘除+池回收+DecRef）；树全部为 libc stdio。
- `luaU_undump @0x33b7d0`：**无条件拒绝预编译 chunk**：名字修正后直接
  `luaO_pushfstring(L,"%s: %s in precompiled chunk", name, "Disallowed functionality")` + `luaD_throw(L, LUA_ERRSYNTAX)`
  （反汇编确认无分支；`_f_parser@0x32e54c` 仍按 0x1b 分发过来）。完整 loader 尾段（0x33B86B-0x33B937）
  及 `LoadFunction/LoadString/...` 因 `luaD_throw` 未标 noreturn 而被编译保留但不可达。
  树 lundump.c:195-209 仍是完整加载器 → **官方 mac 客户端上 `load/loadstring/loadfile` 的字节码 chunk 必定失败**。

## 5. 树侧待办（可执行）

按重要性排序（1–4 为行为级，5–9 为集成/输出级）：

1. **lgc.c**：若要复刻官方 mac 行为，需补时间片 GC：`lua_settimeslice` 落值、`luaC_step` 时间预算循环
   （引擎 `StartLuaGCTimer/GetLuaGCTimer`）、6 状态枚举（+状态4 释放 L+0x70 链）、`sweeplist` 内 userdata 终结与表延迟释放、
   `atomic` 去掉 `separateudata(L,0)`；若不打算复刻，应在注释中明确"有意差异"（影响 `__gc` 触发时机与 GC 步进预算）。
2. **lstate.c**：`preinit_state` 补 `L->函数级 delayed list = NULL`（L+0x70）与 `L->allowed_gcstep = 0`（L+0x74）；
   `lua_close` 增加并使用 `luaC_callGCTM_ForFinalizingUserData` 等价物（终结后清 udata 元表）。
3. **lstate.h**：`char reserved[8]` 与 32 位二进制不符（allowed_gcstep 应在 +0x74）；建议按平台条件化（32 位 reserved 4 字节）。
4. **lundump.c**：决定是否复刻 `Disallowed functionality` 拒绝（若要"与官方客户端一致"则需要）。
5. **liolib.c**：路径安检（`invalid filepath`）、标准句柄 close 语义、`ferror/clearerr` 桩、io 写读走引擎 VFS —— 复刻需引擎侧 `*_external` 符号配合；
   KFS 集成是"替换游戏内 Lua"时的关键（否则 mod 的 io.open 访问不到游戏资源）。
6. **loslib.c**：`os_date` 复刻单次 strftime + 错误路径。
7. **loadlib.c**：mac 也用 `data\scripts\?.lua;data\scriptlibs\?.lua` 缺省；`readable()` 走 KleiFile（若目标环境提供）。
8. **ldblib.c**：`db_errorfb` 改回 `ar.source`（去 '@'），并修正 ldblib.c:353-359 与实际不符的注释（注释写 short_src，实测为 source）。
9. **lauxlib.c**：`errfile` 去掉 `+1`；`luaL_loadfile` 拦截路径补 fclose（并修 stdin+『#』实参）。

### 5.1 修复记录（差异组 4，2026-10-03）

（注：§4.3 的 `db_errorfb` 项与 §5 第 8 条已在提交 `2ca7d2b1` 中修复——改用 `ar.source` 并同步了注释；`errfile`/`luaL_loadfile` 等待办仍未处理。）

- `lstate.h`：`char reserved[8]` → `GCObject *tobefreed`（+0x70；随架构自适大小，**32 位下使 allowed_gcstep 落在 +0x74**）。
- `lstate.c`：`preinit_state` 补 `L->tobefreed = NULL;` 与 `L->allowed_gcstep = 0;`（与二进制内联 preinit 一致）。
- `lgc.c` / `lgc.h`：新增 `luaC_callGCTM_ForFinalizingUserData`（`GCTM` 增加 `clearmeta` 参数：终结后清 udata 元表）；`lua_close` 改调它（其余 `singlestep`/`luaC_callGCTM` 调用保持 `clearmeta=0`）。
- `lua.c`：独立解释器作为宿主显式 `lua_gc(L, LUA_GCALLOWGCSTEP, 1)`，否则 dev 版不再自动 GC（游戏客户端由引擎每帧 `lua_gc(L,GCSTEP,0)` + emergency 开关驱动，见 §4.1）。

验证（mingw gcc 16.2 全量编译 + 运行）：
- 冒烟：正常 collect 路径 `__gc` 恰 1 次；协程（`luaE_newthread` 的 preinit）正常；`lua_close` 路径新函数执行、退出码 0；树自带 `test/hello.lua` 正常。
- 门 A/B（C 宿主）：门关（preinit 默认 0）时 2000 个 udata 在大量分配后 **0 次**自动终结；`lua_gc(L,LUA_GCALLOWGCSTEP,1)` 后同规模 **2000 次**自动终结。
- 32 位字段偏移为解析推导（前置各字段偏移此前已在 32 位二进制上逐一对齐），如需实测请走项目自带 32 位构建（本机无 32 位工具链）。
- 顺带观察（非本次引入；树与二进制同构）：`luaL_loadfile` 的两处 `errfile(L,"OLDFILEACCESSMETHOD",...)` 会把随后 `lua_load` 的 chunk 名留成该错误串（实测错误前缀即 `cannot OLDFILEACCESSMETHOD …`），是否需与官方行为进一步核对可另开一条。

### 5.2 LuaJIT 侧 traceback/命名 parity 修补（2026-10-04）

引擎嵌入的 Lua 5.1 与本项目 LuaJIT 变体（`lua51DS.dll`，`jit`/`jit_gen`）在**同一份 mod 报错**上输出的 traceback 曾不一致，逐行 diff 定位到四处，均在 `luajit/src/`：

1. **metamethod 帧名（已修）**：5.1 `getfuncname`（ldebug.c:544-555）只在调用方指令是 `OP_CALL/OP_TAILCALL/OP_TFORLOOP` 时取名，metamethod（VM 直接调用的 `__index`/`__newindex`…）帧得到 `namewhat == ""`，`db_errorfb` 于是不打印后缀；LuaJIT `lj_debug_funcname`（lj_debug.c:365-369）对这些帧返回 `"metamethod"` + 事件名，于是打出 `in function '__index'`。
   实测：`scripts/strict.lua(23,1) in function '__index'`（jit）vs `scripts/strict.lua(23,1)`（game VM）。
   修法：新增宏 `LJ_DS_DEBUG_FUNCNAME_PATCH`（`lj_arch.h`，默认 `= LJ_DS_TRACEBACK_PATCH`），置位时跳过该分支（`#else` 保留原行为）。
2. **`=(tail call)` 虚拟帧后缀（已修）**：引擎对 `what == 't'` 也打印 `" ?"`（mac `_db_errorfb` @0x0032bf86 反编译：`if ((what=='C')||(what=='t')) pushlstring(" ?")`，5.1 `info_tailcall` 设 `what="tail"`）；LuaJIT 的 patched 分支只匹配 `'C'`，`=(tail call)` 帧无后缀。
   修法：`LJ_DS_TRACEBACK_PATCH` 分支改为 `'C' || 't'` → `" ?"`（tail 帧没有 C 函数指针，不能走 `at %p`）。
3. **Lua 尾调用（帧消除）行文本（已修）**：5.1 对 **Lua** 被调者做真尾调用（`OP_TAILCALL` → `luaD_precall` 返回 PCRLUA，帧被替换、`ci->tailcalls++`），`db_errorfb` 对每个被消除帧打一行 `        =(tail call) ?`（`info_tailcall`：`what="tail"`、`source="=(tail call)"`、`namewhat=""`）。上游 LuaJIT 的 patched 打印器把同样多的虚拟层（`lj_debug_getinfo` 的 `i_ci == 0`）折叠成 `\t(...tail calls...)` 标记行。
   修法：`lj_debug.c` 的 `LUA_COMPAT_TAILCALL_COUNT` 短路分支加 `&& !LJ_DS_TRACEBACK_PATCH` → 虚拟层落到常规渲染，输出 `        =(tail call) ?`（依赖第 2 条的 `'t'` → `" ?"`）。
4. **深层尾调用的压缩走法（已修）**：超过 `TRACEBACK_LEVELS1(12)` 后进入压缩分支。上游 LuaJIT 用 `lua_getstack(L1, -10, &ar); level = ar.i_ci - TRACEBACK_LEVELS2;`——DS 的尾计数层给每个被消除帧造一个虚拟层，而**所有虚拟层的 `i_ci` 都是 0**，`level` 因此被算成负值并走回虚拟层：帧被重复打印、夹出幽灵 `=[C] ?`。5.1 `db_errorfb` 用数值走法（`while (lua_getstack(L1, level+LEVELS2, &ar)) level++;`），对虚拟层天然正确。
   修法：`lj_debug.c` 压缩分支在 `LJ_DS_TRACEBACK_PATCH` 下改用 5.1 的 `while` 走法（`#else` 保留上游实现）。

**深层实测**（mod 内 `loadstring` 生成 20 层纯 Lua 尾调用链，链尾报错；同一栈对比）：

| | 帧数 | 伪帧行 |
|---|---|---|
| 修前 jit | 59 | 41（含重复 `chain(1,1)`、幽灵 `=[C] ?`） |
| 修后 jit | 23 | 10 |
| game VM（引擎） | 23 | 10 |

修后 jit 与 game **逐行完全一致**（`diff` 为空）：首部 `chain(1,1)` + 10×`        =(tail call) ?` → 单个 `\t...` → 末尾 10 层真实帧；N=40 时同样稳定在「首 12 + 尾 10」结构。该缺陷是**既有**的（第 1–3 条修改只改行文本，压缩分支与其上游相同）；本次一并修掉。

**复核（Ghidra，mac `dontstarve_steam` x86:LE:32）**：`_db_errorfb` 反编译确认 `local_74 = *namewhat`、`local_78 = name`、`local_7c/6c/68 = what/source/currentline`，与 §4.3 记录一致；`lj_debug.c` 的落点与 5.1 `getfuncname`/`info_tailcall` 语义差异一一对应。

**实测验证**（`tests/game_mods/test_throw_abort`，win 专用服；重建 `luajit-5.1` → `Mod/deps/lua51DS.dll` + 游戏 `bin64/lua51DS.dll`）：
- 含 `SetGlobalErrorWidget` 的 strict traceback：**jit 与 game VM 逐行完全一致**（此前仅差 `in function '__index'` 一行）。
- 同一 mod 内 `top()→mid()→deep()` 两处 Lua 尾调用 + 深处报错：`(...tail calls...)` ×2 → `        =(tail call) ?` ×2，与 game VM **逐行一致**。
- 两 VM 均 `PASS`；mod 报错链、`Error loading main.lua` / `Error during game initialization!` 全同（退出码可落在 `0xC0000409` / `0xC0000005` / `1`，属收尾竞态，测试只报告不断言）。

**已对齐（`LUA_COMPAT_TAILCALL_CFRAME`，2026-10-05）**：`return xpcall(fn, debug.traceback)`（C 被调者尾调用，util.lua:788）现在与引擎一致——`BC_CALLT` 按被调者 ffid 分流，C/FF 被调者按普通调用执行、parser 追加的 `BC_RETM` 把结果转交上层，故 traceback 为 error 站点 → `=[C] in function 'xpcall'` → `in function 'RunInEnvironment'` → 其余不变；`jit.disabletailcall(true)` 不再需要（它仍可用，但会让 Lua 情形失配）。新路径还从调用帧恢复 `KBASE`：`BC_CALLT` 序言把它改成旧 `BASE`，而 `fff_res` 假设“返回时 KBASE 已按调用帧设定”、`vmeta_call` 又用 `KBASE == BASE` 当“来自 CALLT”的标志——不恢复会让 FFH_TAILCALL→`__call` 的角落按旧语义误解（复帧、caller 帧被消除，且随栈布局变化）。门控 = `LJ_DS && LJ_TARGET_X64 && LJ_FR2`（仅 `vm_x64.dasc`）；x86、x64 非 GC64、arm 等后端保持 stock。
**字节码格式（`BCDUMP_VERSION`，2026-10-05）**：CALLT 后跟随的 `BC_RETM` 属于字节码本身，改动前的 dump（stock CALLT、其后无指令）会让 C 返回落到原型之外，故按 `lj_bcdump.h` 的私有改动规则把 `BCDUMP_VERSION` 由 2 升到 `0x80`（宏关时仍为 2）——旧 chunk 现在在 load 时以 `cannot load incompatible bytecode` 拒绝，而不是越界执行；预编译产物（含构建期 `luajit -bg` 的 “Luajitted” 脚本）需用新 VM 重新生成（CMake 规则已把 VM 目标列为依赖，会自动重建）。
**已知（与本改动无关，arenagc 变体既有缺陷）**：用 `luajit-arenagc.exe`/`lua51DS_gengc.dll` 跑 `tests/lua_vm_parity/c_tailcall_values.lua`（其 `check_shape` 的「报错→traceback→`__call`/tostring 元方法」循环即触发）会以退出码 5 静默死亡；把 `LUA_COMPAT_TAILCALL_CFRAME` 置 0 同样复现，说明是 arena GC 变体的既有问题，待独立排查（默认变体不受影响）。

**容量边界（2026-10-05 复核，可接受）**：`PROTO_FIXUP_RETURN`（函数在首个闭包之前就有大量 `return`）会把每个返回点复制到函数尾；本改动给每个 C/FF 尾调用多带一条 `BC_RETM`，因此同一 16 位前向跳转预算（`LJ_ERR_XFIXUP`）更早用尽：实测同一生成函数——开关开接受 4,500 个 `return math.abs(-i)` 站点（40,508 条字节码）、5,000 个即报 `function too long for return fixup`；开关关接受 5,000（35,007 条）、5,500 报错。两者都是**编译期明确报错**（非内存破坏），只影响「首个闭包前有数千个 return 点」的极端生成代码，按现状接受。

**剩余差异（LuaJIT 固有）**：快函数→元方法的 FFH_TAILCALL 路径（`lib_base.c:94/335` → `vm_call_tail`）仍替换快函数帧，`tostring`/`pairs` + `__tostring`/`__pairs` 的报错 traceback 会比引擎少一行 `=[C]`（引擎的 `tostring` 是嵌套普通调用，C 帧保留）；对齐它是独立改动（`vm_call_tail` 需改为"帧上叠加 + continuation 交付"），本次未做。
**同处既有记账差异（2026-10-05 复核，开关显影）**：该 FFH 路径在 JIT 下还会多打一行 `        =(tail call) ?`——解释器进入元方法时（`vm_call_dispatch`→`ins_call`）会清掉该槽的尾计数，而 trace 里 `rec_tailcall` 的计数 IR 保留，于是同一形状（如 `ct() return tostring(obj)`、`obj.__tostring` 返回 `debug.traceback`）在 jit off 下无此行、jit on 下有；把开关置 0 后普通 CALL 版本仍复现（既有缺陷），仅 CALLT 版本不再复现（差异被显影）。修法并入上一条的 FFH 对齐，本次未做。
最小复现：`tests/lua_vm_parity/xpcall_tailcall.lua`（ctest `luajit_parity_xpcall_tailcall`）——4 行 `local function boom() ... end; local function wrapper() return xpcall(boom, debug.traceback) end`；脚本头部逐字记录对齐后的输出（`=[C] in function 'xpcall'` + `<chunk>(31,1) in function 'wrapper'`），并对该形态做断言——若 caller 帧又被消除，用例会在“expected the named xpcall C frame”处失败并提示更新本文档。结果转发（0..N 值）、caller/caller's caller 帧存活与 JIT 一致性由 `tests/lua_vm_parity/c_tailcall_values.lua`（ctest `luajit_parity_c_tailcall_values`）覆盖。

**回归测试**（`ctest -C <cfg> -R luajit_parity`，无需游戏，直接用构建出的 `luajit.exe`）：

| ctest | 文件 | 守住的性质 |
|---|---|---|
| `luajit_parity_metamethod_name` | `tests/lua_vm_parity/metamethod_name.lua` | metamethod 帧 `debug.getinfo().namewhat == ""`、traceback 该帧无 ` in function '...'` 后缀；同时正向校验普通调用帧仍带名字（防过度抑制） |
| `luajit_parity_tailcall_lines` | `tests/lua_vm_parity/tailcall_lines.lua` | 每个被消除尾调用恰好一行 `        =(tail call) ?`、无 `(...tail calls...)`、保留 `LUA ERROR stack traceback:` 头、无 ` in function <src:line>` 回退、顺序为「最内层真实帧 → 依次消除帧」；**深层链（20 层）**：只允许一个 `\t...`、伪帧数落在「首 12 + 尾 10」结构内、同一报告内不得重复打印真实帧（守住压缩走法） |
| `luajit_parity_xpcall_tailcall` | `tests/lua_vm_parity/xpcall_tailcall.lua` | `return xpcall(...)`（对 C 函数尾调用）保留 caller 帧、C 帧按 `OP_TAILCALL` 站点取名——断言 `=[C] in function 'xpcall'` 先于 `in function 'wrapper'`、且无 `(tail call)`；头部记录引擎侧对照输出 |
| `luajit_parity_c_tailcall_values` | `tests/lua_vm_parity/c_tailcall_values.lua` | C 被调者尾调用的结果转发（0/1/2/3/**300** 值、`pcall` 值对、vararg 调用者 `BC_CALLMT`、Lua vararg 被调者、多余目标 nil 填充）、caller 与 caller's caller 帧存活、pcall 在 C 帧内报错时帧名正确、FF fallback 经 `__call` 交付时帧名/调用者帧正确（守 KBASE 恢复）、字节码格式边界（dump 版本必须 `0x80`、重载后仍要跑对、声称 stock 版本 2 的 chunk 必须以 `incompatible bytecode` 被拒）、Lua 尾调用仍消除（常数栈深）；**值与形状断言都在 jit off/on 两态跑，且断言热循环确实编出了 trace**（`jit.util.traceinfo`） |

变异校验（把 `LJ_DS_TRACEBACK_PATCH` 临时置 0 重编）：三用例分别以
`metamethod frame namewhat must be empty (engine parity), got: metamethod`、
`expected 2 '        =(tail call) ?' lines, got 0`（伴随 `stack traceback:` + `(...tail calls...)`）与
`engine traceback header missing:`（头部回退成 `stack traceback:`）失败 ✓；恢复后三者恢复 green。

## 6. 附：171 个"源码有 / 二进制无符号"分类

- **lparser.c (37)**：全部内联（statement/expr/exprstat/if/while/repeat/for 族→`_chunk`；enterblock/enterlevel→block/forbody/…；
  searchvar/indexupvalue/markupval→singlevaraux；parlist/pushclosure→body；closelistfield/lastlistfield→constructor 等）。
- **lcode.c (13)**：全部内联（boolK/nilK→luaK_exp2RK；isnumeral/constfolding→codearith；condjump/dischargejpc→jumponcond/codecomp；
  `luaK_goiffalse`→luaK_infix 的 OPR_OR 分支；getjump/getjumpcontrol→patchlistaux/need_value 等）。
- **lstrlib.c (13)**：全部内联（posrelat/lmemfind→str_find_aux；match* 族→match；add_s/add_value→str_gsub；addquoted/scanformat→str_format；createmetatable→luaopen_string）。
- **ldebug.c (10)** / **ldo.c (5)** / **ltable.c (11)** / **lgc.c (11)** / **liolib.c (6)** / **llex.c (4)** / **ldblib.c (4)** /
  **lvm.c (3)** / **lapi.c (1)** / **lbaselib.c (1)** / **lfunc.c (1)** / **lstring.c (1)** / **lstate.c (1)** / **ltablib.c (1)**：内联（示例：
  getcurrenv→pushcclosure/Ccall/newuserdata；base_open→luaopen_base；set2→auxsort；unlinkupval→luaF_freeupval/close；
  newlstr→luaS_newlstr；preinit_state→lua_newstate/luaE_newthread；traverse*/freeobj→propagatemark/sweeplist 等）。
- **loslib.c (11)**：`os_execute/exit/getenv/remove/rename/setlocale/tmpname` 因**注册表注释移除** → 未注册 static 被编译消除
  （os.pushresult 同去）；getboolfield/setboolfield/setfield 内联进 os_date/os_time。
- **loadlib.c (13)**：`ll_load/ll_sym/ll_register`→ll_loadfunc；`ll_unloadlib`（no-op）被省略；`errorfromcode/pusherror` 属未编译的 DYLD/DLL 分支
  （二进制未定义 `LUA_DL_DYLD`，走通用 fallback：加载 C 模块恒失败 "dynamic libraries not enabled"）；dooptions/modinit/setfenv→ll_module；
  readable/pushnexttemplate→findfile；setpath→luaopen_package；setprogdir 为宏 no-op。
- **lundump.c (7)**：`LoadChar/LoadCode/LoadConstants/LoadDebug/LoadHeader/LoadNumber/error` 内联进 `LoadFunction`（该函数本身因字节码禁令不可达）。
- **ldump.c (7)**：`Dump*` 全部内联进 `luaU_dump`（dump 侧完整存活）。
- **liolib popen 相关**：`io_popen` 未注册（同树注释）；`io_noclose` 被二进制移除（由 `__close=io_fclose` + io_gc 守卫取代）。
- **宏改名（非缺失）**：`luaI_openlib` ⇒ 编译为 `luaL_openlib`（与二进制同名符号一致）；`luaL_getn/luaL_setn/checkint` 因 `LUA_COMPAT_GETN` 未启用走宏。
- **new.c (3)**：逆向草稿文件，未参与编译，忽略。

## 7. 交叉验证记录（摘要）

- lapi 73/73：lua_gc 9 个 case 逐一核对（含 `LUA_GCALLOWGCSTEP=8` 写 L+0x74）；lua_pushvfstring/lua_pushfstring 与源码一致（git 修复仅删除重复定义）。
- lstrlib/lmathlib 58/58：`match` 全指令审计、LUA_MAXCAPTURES=32、`math.random` 用 rand()%（2^31-1）、min/max=MINSD/MAXSD。
- lvm/ltable 43/43：luaV_execute 跳转表 38 个 opcode 逐项核对；MAX_SIZET/MAX_LUMEM=0xFFFFFFFD 等常量与树一致。
- parser/llex 47/47：token 枚举 0x101-0x11f、luaX_tokens 31 项表、转义表逐字节核对。
- executionerror 三件套 + luaD_pcall（`CMP [_g_had_execution_error@0x467d68],0`+CMOVZ，仅读不写、置位返回 1）与树完全一致。
- 注册表逐字节复验：base(24)/co(6)/io(10)/file(9)/os(4)/str(15)/table(9)/math(28)/debug(14)/package(loadlib,seeall)/ll(module,require)/lualibs(7+显式 io/os) —— 与树一致（含 os 沙箱、无 popen）。
- 导出面：`lua51.def` 全部 126 个导出名在二进制中均有符号。
- 运行期提示（本机无法运行 mac 客户端，未实测）：按 A9 结论，在官方 mac 客户端里
  `loadstring("\27Lua...")` 应报 `<name>: Disallowed functionality in precompiled chunk`；
  `os.date("%Y")` 等正常，`os.getenv/execute` 为 nil；`io.open("/abs")` 应报 `invalid filepath`。
