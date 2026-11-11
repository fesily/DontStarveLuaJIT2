---
name: luajit-fork-loadstring-filter-corruption
description: DST mod 在自编译 LuaJIT fork 下加载失败/崩溃（worldgen 时 fail-fast）时，先查 LJ_DS_BIG_UPVAL_PATCH 的 loadstring filter 是否插碎长字符串；含 string.dump 拼接检测、stock/LuaJIT 游戏内 A/B、GAME_LUA_MODULE_NAME 换 VM 复测。
---

# LuaJIT fork `loadstring` filter 破坏长字符串 — 定位与复测

## 适用
受保护/混淆 DST mod 在**自编译 LuaJIT fork**下加载失败（引擎 `MOD ERROR` → fail-fast `0xC0000409`，表现为“创建世界时崩溃”），但原版 Lua 5.1 正常。

## 根因（本仓 fork 特有）
`luajit/src/lj_arch.h`：`LJ_DS_BIG_UPVAL_PATCH` 默认 `= LUAJIT_ENABLE_LUA51COMPAT`（默认 1）。
`luajit/src/lib_base.c` 的 `filter()` 在 `LJLIB_CF(loadstring)` 中改写源码：把每个 `{ … }` 包成
`(function () return { … end)()`（为拆大表构造，规避 LuaJIT 常量上限）。
它**只跟踪 `"…"`**：不跳过 `[==[…]==]`/`[[…]]` 长字符串、`--` 长/行注释、`'…'`。
后果：
- 长字符串 **内容被插入** `(function () return {` / `end)()` → 字符串长度/内容变化 → base-85/自定义解码器撞到非法字符（空格）→ `attempt to perform arithmetic on a nil value` → mod 加载失败。
- 含大量 `{}` 的生成代码被包裹 → 指令数爆炸 → `main function has more than 67108864 bytecode instructions`（`LJ_MAX_BCINS=2^26`）。

## 三步定位
1. **游戏内 A/B**（`tests/harness`，起专用服务器）：
   - stock：`DS_LUAJIT_FORCE_DISABLE_VM=1` + `mods/modsettings.lua`（`ForceEnableMod("workshop-<id>")`）+ 集群 `modoverrides.lua`，`force_enable_mods` 留空；
   - jit：不设该 env，用 `force_enable_mods=workshop-<id>`（注入器 force-enable 只在 LuaJIT 侧生效）。
   - 期望：stock `Registering prefabs`/`World generated`；jit `MOD ERROR`。真实错误取 `ModManager.failedmods[i].error`（引擎 `moderror` 会把第二参当 `level` 丢掉）。
2. **离线同文件复现**：用 PUC `lua51Original.dll`（ctypes driver：`luaL_newstate/openlibs/loadfile/pcall`）与 fork `luajit.exe` 跑同一份“解密后 modmain”+ 桩 env，比较：PUC 解码 OK / LuaJIT 在该行报 arithmetic-on-nil。
3. **决定性检查（拼接检测）**：
   ```
   luajit -e "local t=io.open('MODMAIN','rb'):read('*a'); local f=assert(loadstring(t)); local d=string.dump(f); print(select(2,d:gsub('%(function %(%) return ',''))) "
   ```
   LuaJIT > 0、PUC = 0 ⇒ filter 中招。也可对比 `#literal`（会多出 1274B 之类的增量）。

## 修复 / 验证
- **正解**：在 `filter()` 里跳过 `[=*[ … ]=*]`（含 `--[=*[` 长注释）与 `'…'`（处理 `\`），行注释 `--…` 到行尾；或只在确认 savedata 形态时启用。**不要直接全局禁用**：该补丁用于大表构造规避 LuaJIT 常量上限，禁用它可能让大 savedata 加载失败。
- **验收**：重编 `lua51DS.dll`（`ninja -C builds/ninja-multi-vcpkg -f build-RelWithDebInfo.ninja "luajit/RelWithDebInfo/lua51DS.dll"`，2–3s），二进制应不再含 `(function () return {`；离线解码应通过。
- **换 VM 跑游戏测试**：给服务器进程设 `GAME_LUA_MODULE_NAME=<新 lua51DS.dll 绝对路径>`（`GameLuaContextImpl::LoadLuaModule` 读取），不必覆盖用户文件。
- **等价 A/B 技巧**：在 mod 层用 Lua 闭包包住 `GLOBAL.loadstring`（探针 mod，priority 1 先加载）→ 绕过 C filter → 受影响 mod 会恢复加载，可确认是 filter 还是 mod 自身逻辑。

## 相关坑
- 探针 mod 的 `loadstring` 包装会让 mod 误判/改路径（本次即“探针在就正常、不在就崩”），做结论时要意识到这一点。
- DST mod env 只有白名单 globals：`rawget/select/pcall/error` 等要走 `GLOBAL.*`。
- `io.open` 写文件要绝对路径；`_VERSION` 等在 mod env 里可能取到 stub。
