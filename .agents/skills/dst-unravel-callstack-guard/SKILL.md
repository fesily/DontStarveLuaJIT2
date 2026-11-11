---
name: dst-unravel-callstack-guard
description: DST 开 LuaJIT mod 后无法拆解皮肤：客户端硬校验 BarterLoseItem 调用栈并伪造 E_BALANCE_MISMATCH；定位 FUN_140483B20 布局不兼容与修法
---

# 症状

玩家/测试机开着 LuaJIT mod 时无法拆解皮肤；client_log 出现
`[BarterLoseItem_Complete Failure:200] {"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}`，
UI 弹窗写死为 “Failed to contact Klei Servers”。关 mod 即恢复，重启无效。
签名/价格/库存链（ValidateSignature → pricing_cache → BarterDefs）全部正常。

# 判定（先排除误判）

1. 日志里若已有 `saved .../client_save/pricing_cache` 和 `loaded inventory_cache_prod`，说明签名/价格/库存都成功，不要再往签名链查。
2. `E_BALANCE_MISMATCH` 不一定是服务端回的：先看 `BarterLoseItem` 绑定是否走了本地伪造分支（见下）。
3. 弹窗文案来自 `barterqueue.lua BarterQueueFail()` + `STRINGS.UI.BARTERSCREEN.FAILED_TITLE/BODY`，任何失败都显示 “Failed to contact Klei Servers”。

# 关键代码（Windows r759671，地址随版本漂移）

- `TheItems:BarterLoseItem` 绑定 `0x14020D1E0`：
  - `trace = FUN_1401010E0(&str, L)`（遍历 lua_getstack/lua_getinfo("Slf") 生成栈串）
  - `trace == DAT_140680C08`（硬编码期望栈，由 FUN_1404B68F0 初始化）→ 匹配才发请求
  - 不匹配 → 把 `0x1404FDC58` 的 `{"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}` 交给 `BarterLoseItem_Complete(…, 0, 200, …)`
- 期望栈内容：`[C]:-1`、`barterscreen.lua:114`、`imagebutton.lua:216`、`widget.lua:130`×5、`barterscreen.lua:264`、`frontend.lua:440`、`input.lua:166`、`input.lua:752`
- 每帧 chunkname 由私有 helper `FUN_140483B20`（53B，非 Lua API，不在任何 Lua 符号表）用引擎 Lua 布局硬解：
  `tag@+8==6` → `value→Closure`，`isC@+0xa`，`Proto@+0x20`，`*(Proto+0x78)+0x18` = chunkname
- PC 版 `lua_topointer`（`0x140482210`）返回 **TValue\***（PUC index2adr 语义），不是标准 GC 对象指针
- `BarterLoseItem` 请求体（`FUN_14020CEB0`）：`ItemID / ExpectedPrice / ExpectedBalance(=cInventoryManager::GetCurrencyAmount, this+0xB8) / TransID / CurrencyName="SPOOLS" / ClientToken`
- 本地货币来源：`cInventoryManager::ProcessCurrencyMapForLocal` 只取 `CurrencyMap.SPOOLS`；`GetCurrencyAmount` 直接读 `+0xB8`

# 为什么 LuaJIT 必然失败

`lua_getinfo` 已被接到 `lua_getinfo_game` 也没用：压栈的是 LuaJIT 函数对象，而 `FUN_140483B20` 按 PUC 布局读。
实测：引擎 Lua 的 TValue `+8`=6；LuaJIT `lua_topointer` 返回 GCfunc，`+8`=0x801 ≠ 6 → helper 返回 0 → 该帧渲染为 `[**untrusted** …]` → 栈串永远不匹配。

# 修复方向

按签名 hook `FUN_140483B20`，识别 LuaJIT 函数：`lua_topointer`→`GCfunc*`→`isluafunc`→`funcproto`→`proto_chunkname`→`strdata`，返回 chunkname（必要时剥前导 `@`）；非 Lua 函数返回 0。保持原比较逻辑不动。
不要只改 `lua_getinfo_game` 的 `@` 处理（`luajit/src/lj_debug.c`，注意要写 `iar.source` 而不是 `ar->source`，否则被 memcpy 覆盖），那只影响 source 文本，救不了对象布局。

# 交叉验证

- `build/symmatch/inv_libDontStarve_2.2.1.so.jsonl`：Android 2.2.1 无 `[**untrusted**`/`[string '%s']`/`"Slf"` formatter，`lua_getinfo` 只是 8B thunk（LuaJIT），`lua_topointer`(0xd8d924) 是 LuaJIT NaN-box 语义 → 该反作弊是 PC-only，helper 在 Android 符号里查不到。
- 用 `lua51Original.dll` / `lua51DS.dll` 做 ctypes 探针可直接对比 `lua_getinfo("Slf")` 与 `lua_topointer` 的字段/布局差异。

# 注意

- `client_log` 里 `status=FAILED_TO_CONTACT` 是弹窗 OK 回调打印的 status 参数，不代表当次网络事件。
- `-offline` 会整体短路 item server（`+0x49`），此时拆解本来就不可用。
