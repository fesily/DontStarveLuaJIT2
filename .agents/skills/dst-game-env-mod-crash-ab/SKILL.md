---
name: dst-game-env-mod-crash-ab
description: 真实游戏环境(DST 专用服务器+注入器)判断 mod 在 LuaJIT 下加载/建世界崩溃并与原版 Lua A/B；含 frostxx 加密 mod 离线复现与坑
---

# 用途
在**真实游戏环境**里判断某个 DST mod 是否在 LuaJIT 注入器下“加载/建世界崩溃”，并与原版 Lua 做 A/B；对 frostxx 加密 mod 还能离线复现。

# 1. 游戏环境 A/B（tests/harness）
```python
import sys; sys.path.insert(0, "tests")
from harness.cluster import remove_persist_tree, write_offline_cluster
from harness.game_dir import find_server_exe, resolve_game_dir
from harness.inject_env import stage_inject_shell
from harness.launch import DedicatedProc
```
- `stage_inject_shell(game_dir)`：把 Winmm 壳装进 `bin64`，真 Injector 留在 `Mod/Injector.dll`（`DS_LUAJIT_INJECTOR`）。
- **jit 模式**：`proc.start(game_dir, persist_root, cluster, shard, force_mods="workshop-<id>")`；force-enable 由注入器 Lua 框架做（会打印 `[luajit] Force enable mod: ...`）。
- **stock 模式**：`extra_env={"DS_LUAJIT_FORCE_DISABLE_VM": "1"}`（日志 `[core.vm] Lua VM path disabled`），且 **force_enable 不生效**（那是 LuaJIT 侧功能）→ 用 `<game>/mods/modsettings.lua` 写 `ForceEnableMod("<folder>")`，或 cluster 目录 `modoverrides.lua`（`ResolveModname` 认数字 id）。
- 观察点：`Loading modmain.lua`、`Registering prefabs`、`World generated`、`MOD ERROR`、`Error in modimport`、exit code（**0xC0000409=3221226505** = 引擎对 mod 加载错误的 fail-fast，等价“崩溃”）。
- **坑**：`moderror` 只打印第一个参数，真错误文本会丢；真错误在 `ModManager.failedmods[i].error`（控制台查）或 `util.lua:799 RunInEnvironment` 的 traceback（watcher 日志里，含 chunk 源码行）。

# 2. 离线复现（不带游戏）
- frostxx 解密：`python .agents/skills/decrypt-encrypted-mods/scripts/fengxun_decrypt.py <modmain0.lua> out.lua`（`.agents/skills/...` 是实际路径，不是 `.opencode`）。
- 用桩 env 跑解密后 modmain：GLOBAL 里放真实 libs + `_G=GLOBAL`、`MODROOT`、`env` 表；未知名用 permissive stub（mod env 只有白名单：无 `rawget/select/pcall/loadstring`，都要 `GLOBAL.*`）。
- 原版对照：ctypes 驱动 `lua51Original.dll`（`luaL_newstate/openlibs/loadfile/pcall`）；**注意 driver 不会设置 `arg`**，harness 要写成 `local a1=...; local fname=(arg and arg[1]) or a1`，否则 PUC 会跑默认文件，得出错误结论。
- 校验同一源码：打印 `#text` + 字节和，确认两 VM 读到同样字节；再比较各自解析出的长字符串字面量长度/内容。

# 3. 已知判例（3355502149 玉兔）
- stock：加载 OK、World generated；jit：`[string "GLOBAL.setmetatable(env,..."]:129: attempt to perform arithmetic on a nil value` → 0xC0000409。
- 解密后 modmain 的 437KB base-85 payload：PUC 字面量 437,055B 解码成功；LuaJIT 解析成 438,329B（多 64 处 `(function () return … end)()`）→ 第 4934 字节是空格(32)不在字母表 → 解码 nil。
- 规避：mod 的 `LuaVmType` 选项切 `lua51`/`game`（`Mod/modmain.lua:SwitchVm` → `GameInjector.DS_LUAJIT_set_vm_type`）。

# 4. 纪律
- 只往 `game/mods/` 注入副本，结束删除；`modsettings.lua` 用后删；临时改仓库 `Mod/plugins/*.lua`（如 `EnableFrostxxMods`）测试后必须还原。
- 一次只跑一个服务器（同端口），串行执行。
