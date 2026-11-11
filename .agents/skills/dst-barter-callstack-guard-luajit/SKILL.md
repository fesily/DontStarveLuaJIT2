---
name: dst-barter-callstack-guard-luajit
description: "DST 开 LuaJIT 后拆解/编织失败并显示 \"Failed to contact Klei Servers\"：本地调用栈反作弊伪造 E_BALANCE_MISMATCH，定位 FUN_140483B20 并 hook 修复"
---

# DST 拆解/编织被 LuaJIT 禁用（本地伪造 E_BALANCE_MISMATCH）

## 症状
- 开 LuaJIT mod 后拆解皮肤/拆解重复/编织失败，弹窗固定为 “Failed to contact Klei Servers”。
- 重启无效，关 mod 即恢复；签名/价格/库存日志看起来全部正常。
- `client_log.txt` 只有一行 `[BarterLoseItem_Complete Failure:200] {"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}`，30s 后出现 `ERROR: Failed to contact the item server. status= FAILED_TO_CONTACT`。

## 判读要点
- 那条 `E_BALANCE_MISMATCH` **不是服务端响应**：客户端在发请求前做调用栈校验，失败就直接伪造该 JSON 并调完成回调。
- `status=FAILED_TO_CONTACT` 是失败弹窗 OK 回调打印的参数（`barterqueue.lua` 的 `BarterQueueFail`），不代表网络。
- 服务端链的证据：`saved .../client_save/pricing_cache`、`loaded inventory_cache_prod`、`Account Communication Success`；出现这些就说明签名/库存/价格都已成功，问题在本地 guard。

## 定位（r759671，PE 时间戳 0x6ADA8C08）
1. `TheItems:BarterLoseItem` 绑定 `0x14020D1E0`：
   - `trace = FUN_1401010E0(L)` 拼栈；`trace == DAT_140680C08` 才发请求。
   - 失败分支引用字符串 `0x1404FDC58` = `{"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}`。
2. 硬编码期望栈（`FUN_1404B68F0` 写入 `DAT_140680C08`）形如：
   `[C]:-1[string 'scripts/screens/redux/barterscreen.lua']:114[string 'scripts/widgets/imagebutton.lua']:216[string 'scripts/widgets/widget.lua']:130...`
   改任何 Lua 行号/包装层都会失配。
3. 栈格式化器 `FUN_1401010E0`：`lua_getinfo("Slf")` 压入函数对象，再调私有 helper `FUN_140483B20` 取 chunkname；取不到就渲染 `[**untrusted** %s]:%d`。
4. helper `FUN_140483B20`（长度 53，唯一签名 `48 83 EC 28 E8 ?? ?? ?? ?? 83 78 08 06 75 ?? 48 8B 00 80 78 0A 00 75 ?? 48 8B 40 20 48 8B 40 78 48 85 C0 74 ?? 48 83 C0 18`）：
   - 按 PUC 5.1 布局硬解析：`TValue.tag@+8==6` → `Closure.isC@+0xA==0` → `Proto@+0x20` → `+0x78` → `+0x18` = chunkname。
   - 它调用的 `0x140482210` 在 PC 上是被 Klei 改过的 `lua_topointer`（返回 **TValue\***，不是 GC 对象）。
   - 只有该格式化器调用它；它不是 Lua C API，mod 的 `lua_*` 替换覆盖不到。
5. LuaJIT 下对象布局不同：实测 `lua_topointer` 返回值 `+8` = `0x801`（≠6），helper 第一步即返回 0 → 每帧 untrusted → guard 必失败。

## 修复（core.vm 插件）
在 `src/DontStarveInjector/plugins/plugin_core_vm/game/GameLuaContextJit.cpp`：
- `ReplaceApis()` 末尾安装一次（`_WIN32` 保护、static 幂等）：
  - `MemorySignature` 扫上面那段签名，`ds::gum::replace` 到 `GameLuaFuncChunkName`。
- 替换实现：
  ```cpp
  auto &api = GetGameLuaContext().api;           // 当前 VM（jit/jit_gen/lua51 均可）
  if (api._lua_type(L, idx) != LUA_TFUNCTION) return nullptr;
  int top = api._lua_gettop(L);
  api._lua_pushvalue(L, idx);
  lua_Debug ar{};
  int ok = api._lua_getinfo(L, ">S", &ar);      // '>' 弹掉函数
  api._lua_settop(L, top);
  if (!ok || !ar.source || (ar.what && ar.what[0]=='C')) return nullptr; // C 闭包与原 helper 一致返回 NULL
  return ar.source[0]=='@' ? ar.source+1 : ar.source;
  ```
- 同时修 `luajit/src/lj_debug.c` 的 `lua_getinfo_game`：`ar->source=...` 写在 `memcpy(ar,&iar,...)` 之前是死代码，改成写 `iar.source` 并判空。

## 验证
- 注入日志出现 `hooked game lua chunkname helper at 0x140483b20`。
- 拆解后 `client_log.txt` 变成 `[BarterLoseItem_Complete Success:200] ... "NewCurrency"`，不再出现 `E_BALANCE_MISMATCH`。
- 若日志是 `helper not found`：客户端改了布局，更新签名（偏移 `0x78/0x18` 属于引擎 Proto 私有布局）。

## 陷阱
- 不要先怀疑签名/网络/离线：先看有没有 `saved pricing_cache` 与 `[BarterLoseItem_Complete Failure:200]` 的 JSON 内容。
- 不要用同名 `load_program` 覆盖 Ghidra 程序（同名返回 success 但不替换）；先对 PE TimeDateStamp 和 `IsBarterQueueEnabled` 地址确认版本。
- Android 2.2.1 没有这套 guard（`inv_libDontStarve_2.2.1.so.jsonl` 无 `[**untrusted**`/`"Slf"`），不要拿它命名该 helper。
