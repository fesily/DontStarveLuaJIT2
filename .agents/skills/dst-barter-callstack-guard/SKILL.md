---
name: dst-barter-callstack-guard
description: DST 开 LuaJIT 后无法拆解/编织：调用栈 guard 伪造 E_BALANCE_MISMATCH；定位 helper（Win 0x140483B20/Linux 0x4AC6D0）、修法与签名集落点。
---

# DST 物品服务器调用栈 guard（拆解/编织被禁用）

## 症状

- 开 LuaJIT（或任何改动 VM/脚本栈的 mod）后，拆解/编织必失败。
- UI 只显示 `Failed to contact Klei Servers`（`STRINGS.UI.BARTERSCREEN.FAILED_TITLE/BODY`，`barterqueue.lua` 的 `BarterQueueFail` 是通用文案）。
- `client_log.txt` 关键行：`[BarterLoseItem_Complete Failure:200] {"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}`；随后 `ERROR: Failed to contact the item server. status=FAILED_TO_CONTACT` 只是弹窗 OK 回调打印的 status 参数，不是新网络事件。
- 重启无效、关 LUAJIT 立即正常 → 先怀疑本 guard，而不是签名/网络。

## 真实机制

`cItemServerLuaProxy::BarterLoseItem`（Windows r759671 `0x14020D1E0`）在发 `iap/DST/BarterLoseItem` 前：

1. `FUN_1401010E0` 用 `lua_getstack`/`lua_getinfo("Slf")` 逐帧拼调用栈字符串；
2. 与硬编码期望栈（`DAT_140680C08`，Linux 有 `barterscreen.lua:86` 和 `:114` 两组）逐字节比较；
3. 不等 → 本地伪造 `{"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}`（字符串 `0x1404FDC58`）并走失败回调。**请求根本没发出去。**

每帧 chunkname 由引擎私有 helper 读取（不是 `lua_getinfo` 的 source）：

```
index2adr(L, idx) -> TValue*
  tt @ +8 == 6 (function)
  -> Closure.isC @ +0xA == 0
  -> Proto @ +0x20
  -> Klei 字段 @ +0x78 (TString*)
  -> TString data @ +0x18
```

| 角色 | Windows r759671 | Linux r759671 |
|---|---|---|
| getter helper | `0x140483B20` | `0x4AC6D0` |
| index2adr | `0x140482210` | `0x4AAD50`（FUN_004aab20 的正索引分支） |
| lua_setchunkname | `0x140483AB0` | `0x4AC670` |
| setproto_chunkname | `0x140483A20` | — |
| 调用方 | DoLuaFile `0x140129940`（loader chunkname `"@"+path`，字段存裸 path） / kleiloadlua `0x140129580`（都是裸名） | 同构，DoLuaFile 调用点 `0x1EB7C0` |

LuaJIT 下这些 PUC 结构不存在 → helper 对所有帧返回 NULL → 渲染成 `[**untrusted** ...]` → guard 必失败。

## 修复架构（定制 Lua API，不要 ad-hoc hook）

1. LuaJIT 侧（`luajit/src/lj_api.c`）提供 `lua_ds_setchunkname` / `lua_ds_getfuncchunkname`；getter 读 `GCproto.dschunkname`（仅 loader 可写，loadstring 不能伪造）。
2. `luajit/src/lua.h` 里这两个声明要**无条件**可见（`lua.h` 先于 `lj_arch.h` 被包含，`LJ_DS_*` 宏此时未定义）。
3. 参考实现 `src/lua51`（签名生成的名字来源）导出同名函数：`lua51.def`、`src/lua.h`、`lua_head.h`、`src/lapi.c`；getter 与引擎 helper 同结构，保证 nucleus 匹配。
4. `plugin_core_vm/LuaApi.hpp` 的 `LUA_API_DEFINES` 加这两项 → `ctx->api._lua_ds_*`，`GetLuaExport`/`ReplaceApis` 自动按名替换游戏内两处函数。
5. 签名集 `Mod/signatures_client.json` / `_server.json`（运行时生成、gitignored）：以 index2adr 为基址，offset `6304`（setter）/`6416`（getter），pattern 见文件。client base `0x140482210` → `0x140483AB0/0x140483B20`；server base `0x14041B110` → `0x14041C9B0/0x14041CA20`。

## 验证

- 启动日志：`replace lua_ds_setchunkname (fast): …`、`replace lua_ds_getfuncchunkname (fast): …`。
- 拆解成功：`[BarterLoseItem_Complete Success:200] … "NewCurrency":…`。
- 离线/未登录/`-offline` 时 item server 整体短路，同样拆不了，要先排除。
- 价格/所有权链路可单独探：`TheItems:GetBarterSellPrice(key)`、`TheInventory:CheckOwnership(key)`、`TheInventory:GetCurrencyAmount()`。

## 陷阱

- 同名 `load_program` 不替换旧 program，`switch_program` 仍是旧对象；导入前先核对 PE TimeDateStamp 与字符串地址。
- Ghidra 可能把 helper 并进大函数：按 `endbr64`/`ret` 切出 `[entry, ret]`，先从父函数 body 减去再 `createFunction`，命名空间用 `lua51`。
- 直接 `gum_module_find_export_by_name` 属于临时做法；项目要求把定制 API 固定进 `ctx->api` 与签名集。
