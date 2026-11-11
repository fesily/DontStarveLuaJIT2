---
name: lua51-static-link-symbol-audit
description: "Audit the symbol set of a statically linked (possibly vendor-modified) Lua 5.1 inside a stripped binary: luaL_Reg slot naming, region census for absent functions, API-boundary/layout-bypass scan, and a vendor-additions catalogue"
---

# 目标

对一个**静态链接的 Lua 5.1（可能被厂商改过）**的可执行文件，产出可信的符号表与“哪些是厂商新增/改动”的清单，并能回答“有没有代码绕过 API 直接碰 VM 内存布局”。

# 顺序（每一步都有定义级证据，别跳）

## 1. 先找厂商源码副本

- 仓库里 `grep -rn "Klei" src/<lua 目录>`、`grep -rn "VENDOR_"`；改过的源码通常带注释和 `#if VENDOR_*` 开关 —— **这比逆向可靠，优先引用 file:line**。
- 用厂商源码里出现的字符串（如 `OLDFILEACCESSMETHOD`、`Hashbang blocked`）反查二进制，确认二进制是否同一版本；源码里没有的符号 = 比源码更新的补丁。

## 2. 建立参考构建（关键）

用厂商源码编一个带符号的 dll/exe（同编译器优先），从 Ghidra 导出全部函数名：这份清单是“源码里有啥”的基线。二进制里有、基线里没有的 = 候选新增；反之是缺失/内联。

## 3. `luaL_Reg` 槽位定名（精确，不用相似度）

- 扫非可执行段，逐 8 字节读 `{char* name, fn*}`（fn 只要求落在代码段，不要求已定义函数）；
- 拿 5.1 源码里的 11 张 `static const luaL_Reg`（131 条）当模板，找**步长 16、名字序列全同**的链 → 槽位即地址；
- 表条目差异 = 定义级证据：例如出货版 `iolib` 只有 9 条（无 popen/tmpfile）、`syslib` 只剩 clock/date/difftime/time ⇒ 这些 API 是被删的，不是漏识别。

## 4. 区块普查（区分“没有”和“没建出来”）

- 脚本算「区间内未被任何函数体覆盖的字节」，再 dump 每段的头 32 字节；
- 只有三类可接受：全 `0xCC` 填充、4 字节跳转表、少量无 prologue 的孤儿块；
- 任何完整函数都会以“未覆盖 + 有 prologue”暴露 → 补建函数。别用“名字对不上”当缺席证据。

## 5. 布局越界扫描（只对“引擎侧”有意义）

- 锚点：反编译文本里每个 `lua_xxx(EXPR, ...)` 的**首参表达式**（括号配平，可拿到 `*(undefined8 *)(this+0xb0)`）；
- 找同函数内 `(EXPR + 偏移)`；命中后再人工看是否真是 lua_State（C++ 成员偏移会误报）；
- 局限：锚点要求同函数内有公开 API 调用，且必须排除 Lua 区块本身（库内部当然知道布局）。
- 目标函数多时按 500 个/批跑，避开 MCP 30s 请求超时。

## 6. 名字卫生

- 5.2/5.3/5.4 名字套到 5.1 上会制造假“新增”：`suffixedexp`→`prefixexp`、`gotostat`→`breakstat`、`funcnamefromcode`→`auxgetinfo`、`luaL_pushmodule`→`luaI_openlib`、`luaL_loadfilex`→`luaL_loadfile`、`luaH_newkey`→`newkey`、`luaV_arith`→`Arith`；
- 5.1 里是宏的（`luaC_checkGC`、`luaC_barrier`、`luaD_checkstack`、`luaK_setmultret`、`luaK_codeAsBx`、`luaM_malloc`）出现独立函数是编译产物，不是新增；
- 编译器拆出来的半截函数（poscall 的 hook 段、table resize 的搬移段）用描述性名 + 票注。

## 7. 常见结构偏移（x64，5.1 + Klei）

- `lua_State`：top +0x10、base +0x18、l_G +0x20、ci +0x28、savedpc +0x30、stack_last +0x38、stack +0x40、base_ci +0x50、nCcalls +0x60(16 位)；Klei：allowed_gcstep +0xC0、allowed-unsafedata +0xC1
- `TValue`：value +0、tt +8（4 字节，`==6` 是函数）
- `LClosure`：l.p +0x20、upvals +0x28；`CClosure`：c.f +0x20、upvalue +0x28、isC +0xA
- `Proto`：p +0x20、upvalues +0x38、source +0x40、sizeupvalues +0x48、sizep +0x58；Klei 追加 chunkname +0x78
- `TString`：chars +0x18；`global_State`：GCthreshold +0x70、totalbytes +0x78、gcstepmul +0x90、gcpause +0x94

# 交付物

1. `WIN_NAMES.tsv`（地址 / 名字 / 票注含证据）
2. `VERDICTS.tsv`：每个源码函数一行，状态 = named / absent:inlined / absent:no-out-of-line-copy / absent:removed / absent:merged
3. `ADDITIONS.md`：厂商新增分三类 —— 源码有注释的入口、源码有但无标记的增量、只在二进制里的补丁（含地址+源码 file:line 或行为证据）
