---
name: dst-lua-binding-native-gate-trace
description: Trace a DST Lua binding (TheItems/TheInventory/TheSim) to its native gate in IDA via the luaL_Reg table; use when a game feature is disabled and you must find the real switch.
---

# DST Lua 绑定 → 原生闸门追踪（IDA/idatabase）

用途：从 `scripts/*.lua` 里看到的 `TheItems:` / `TheInventory:` / `TheSim:` 方法，定位 Windows 客户端里的真实实现与开关条件。不要靠猜“官方有检测”。

## 步骤

1. 打开 IDA 库（`xd://ida`），`open` DST 的 `.i64`（安装在 `bin64/dontstarve_steam_x64.exe.i64`）。
2. `strings('^方法名$')` 拿到字符串 ea。
3. `xrefs_to(ea)` 一般只有一个 `.rdata` 地址，那是 luaL_Reg 表项：`[name_ptr][func_ptr]`。步长可能是 16 也可能是 24（对齐不同），用 `hexdump` 确认，函数指针紧跟在名字指针后。
4. `pseudocode(func)`：绑定函数通常是 3 步（取参 `sub_1404EA150/1404EC0E0` → 转字符串/哈希 `sub_14042FF40` → 调实现）。跟进去读实现。
5. 对“返回价格/布尔”的绑定，重点确认它是查表还是常量：DST 里 `IsBarterQueueEnabled` 是 `lua_pushboolean(1)`，别把它当开关。

## 已验证的锚点（r759671）

| 绑定 | 地址 |
|---|---|
| `TheItems:IsBarterQueueEnabled` | 0x140282110（恒 true） |
| `TheItems:GetBarterSellPrice` | 0x14027AC30（查 qword_140674E38） |
| `TheItems:SetupBarterLoseAllDuplicateItems` | 0x14027F100 → sub_14027EDE0 |
| `TheInventory:CheckOwnership` | 0x1402825B0 |
| `TheInventory:GetOwnedItemCountForCommerce` | 0x140285700 |
| `TheInventory:ValidateWithSignature` | 0x1402832C0 → sub_140248A20 |
| `TheSim:ValidateLineNumber` | TheSim 表 0x140627da8 → 0x1400A2C30 (`xor eax,eax;ret` 空实现) |

## 判定“功能被禁用”的套路

- 先在 Lua 侧找到设置 `Disable()` / 返回 false 的函数（例：`skinsutils.lua IsUserCommerceSellAllowedOnItem`、`playersummaryscreen.lua RefreshUnravelDuplicatesButton`）。
- 该函数的每个原生输入都去二进制里确认数据来源：是本地常量、缓存文件，还是 HTTP 响应。
- 若来自 HTTP：找请求构造（字符串如 `/iap/DST/...`）与响应解析，读出“失败分支做了什么”（清表/置标志），失败分支才是真正的禁用开关。
- 同时检查 `+0x49`(offline) 这类短路标志：`-offline` 会让整条链路不执行，症状与“检测失败”完全一样。

## 日志判据

`client_log.txt` 关键字：`Skins signature`、`inventory server`、`Inventory validation`、`saved pricing_cache`、`Cancelling Get All Items`。
运行时：`=TheItems:GetBarterSellPrice("wilson_none"), TheInventory:CheckOwnership("wilson_none")`。
