---
name: dst-hardcoded-signature-drift-audit
description: DST 更新后审计 C++ 里写死的 MemorySignature 特征码：对当前客户端/专用服验证唯一性与函数入口，定位漂移字节并给出可核验的替换
---

## 适用
游戏更新后要确认 `src/**` 里写死的 `MemorySignature` 是否仍正确（区别于 Lua 层算法生成的 `Mod/signatures_*.json`）。也可用于"某个插件静默失效/钩子没装"的定位。

## 匹配语义（必须按这个判）
`src/FunctionRelocation/MemorySignature.cpp`
- `scan(nullptr)` = 主模块；`scan(path)` = 指定模块；`scan(base,size)` = 区间。只扫 `prot_flag`（默认 `GUM_PAGE_EXECUTE`）⇒ 只看 `.text`。
- `only_one` 默认 **true**：命中数必须恰好 1，否则 `target_address = 0`（静默失败，调用点通常只是 `if (scan(...))` 跳过）。
- `target_address = 命中rva + pattern_offset`；`scan_function()` 才走 `.pdata` 解析函数入口。
- 尾部 `??` 会被 `normalize_gum_pattern` 裁掉；中间 `??` 正常。

## 步骤
1. 全量取出写死串（含 `only_one=false` 的数组）：`grep -rn'"\([0-9A-F?][0-9A-F?] \)\{4,\}' src`，再用 `grep -n "MemorySignature [a-zA-Z_]\+"` 补字符串数组/多行拼接；读每处上下文确认平台分支（`_WIN32` / `__linux__` / `__APPLE__`）与被扫模块。
2. Python + `pefile` 扫描（比 cdb/Ghidra 快）：把 pattern token 转正则（`??`→`.`），在 `.text` 上 `finditer`；按上面语义判 `len(hits)==1`；`target = hit+offset` 再用 `.pdata`（`RUNTIME_FUNCTION` 12 字节表）判是否函数入口。
3. 客户端与专用服 exe 都扫（`bin64/dontstarve_steam_x64.exe`、`dontstarve_dedicated_server_nullrenderer_x64.exe`）。render 类插件 client-gated（`DontStarveInjectorIsClient` / 路径含 dedicated|nullrenderer），server 0 命中是正常。
4. 漂移定位：把可疑的定长字段逐个换成 `??` 做"放宽—收窄"，看命中数与位置；再反汇编候选处比较常量（结构体成员偏移、`jne rel8`、`mov r8d,imm`、`cmp reg,0x1000` 之类）。同类函数的固定 prologue 常被新函数复用 ⇒ 唯一性破坏多半是"同 prologue 的新兄弟"。
5. 给替换后必须复测：client/server 各 1 命中 + 目标仍是同一函数（`.pdata` 入口、或调用已知相邻锚点验证）。

## 2026-11-06 构建（TS 0x6aed2496）实测漂移
| 站点 | 现象 | 替换 |
|---|---|---|
| `GameNetwork.cpp` RakNet__RPC4__Signal | client **2** 命中（新兄弟 rva 0x1bde27）；真身 client 0x3b7b67(-0x7→0x3b7b60)/server 0x351e27(→0x351e20) | 原 11 字节 + `?? ?? ?? ??` + `48 33 C4 48 89 84 24 20 03 00 00 48 8B 9C 24 90 03 00 00` |
| 同上 ReliabilityLayer ordered-streams | 0 命中：memset 组移到 +0x1110/+0x12F0/+0x1370/+0x16F0 | `48 8D 8B F0 12 00 00 33 D2 41 B8 80`（client 0x3a894a / server 0x342b2a，各 1） |
| `AnimDrawHook.cpp` AnimDCR | 0 命中：成员 0x920→0x928 | `…48 8B 8A 28 09 00 00…`（入口 0xf4920，内部仍调 GetAnimFrame） |
| 同上 ShadowDCR | 0 命中：`[rdx+0x930]`→`[rdx+0x938]` 且 `0F 85 DD`→`0F 85 DA` | 两个常量一起改（入口 0x8f6f0） |
| `GameSignature.cpp` luaSetExecutionError | 0 命中：body 重写（`strncpy` → 内联 strlen + CRT 检查版 memcpy，界 `cmp reg,0x1000`，NULL 消息走只读空串） | 新长串见文件；**解码器也要改** |

## 陷阱
- **解码/消费端的隐含假设同样会随重构失效**：exec-error 的 `decode_execution_error_storage` 原取"窗口第一个 `lea`"，而新 body 先 `lea` 只读空串兜底（实测 helper+0x11 → `.rdata`），照旧规则会把 `.rdata` 当 0x1000 字节可写块交给 VM ⇒ 必须按 `mov [flag], reg` 的寄存器来源回溯块地址（FASTCALL/寄存器迁移、`cmov` 也要考虑）。改签名的同时检查 `size_seen`/`store_seen` 这类结构判定是否还成立。
- `ScanLowest(...)`（`only_one=false` + 取最低地址）没有唯一性护栏：多命中会静默钩到最低那个。能改成要求 `hits==1` 就改。
- 短串（如 `44 8D 76 64`）能唯一是运气，改动后优先加长而不是靠 `??` 放宽。
- 验证完记得编译：`cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target <plugin>`（需 vcvars64；`cmd //c` 在本机 shell 里不传参，用 python `subprocess.run([r'C:\Windows\System32\cmd.exe','/c',bat])`）。

## 不要做
- 不要改 `Mod/signatures_{client,server}.json`（运行期 `SignatureUpdater::create_or_update` 会重解）。
- 不要凭"看起来对"直接落盘；每条替换都要 client+server 双向复测命中数与入口。
