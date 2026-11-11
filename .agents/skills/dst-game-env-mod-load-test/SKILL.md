---
name: dst-game-env-mod-load-test
description: 用 tests/harness 在真实 DST 专用服务器（注入器/LuaJIT VM）里加载指定 mod，做 stock vs LuaJIT A/B、抓真实加载错误、并验证 LuaJIT 指纹抹平；适合排查“加固 mod 在 LuaJIT 下不工作”。
---

# DST 真实游戏环境 mod 加载测试（本仓库）

适用：需要判断某个（加固/混淆）mod 在注入器 LuaJIT 下能否加载、与 stock 5.1 对比、或验证指纹抹平是否生效时。

## 0. 前置事实
- `tests/harness`：`resolve_game_dir()` / `find_server_exe()` / `stage_inject_shell()` / `cluster.write_offline_cluster(persist, cluster, shard)` / `DedicatedProc.start(game_dir, persist, cluster, shard, force_mods=..., extra_env=...)`；日志经 `proc.logs`（stdout + `server_log.txt` + `DontStarveInjector_server*.log`）。
- `force_enable_mods` 由注入器的 **Lua 框架**执行 ⇒ 只在 LuaJIT 路径有效；`extra_env={"DS_LUAJIT_FORCE_DISABLE_VM":"1"}` 时要用 `<game>/mods/modsettings.lua` 的 `ForceEnableMod("workshop-<id>")` 或 cluster `modoverrides.lua`（`{["<id>"]={enabled=true}}`）启用，二者都写最稳。
- mod 目录注入：`shutil.copytree(src, game_dir/"mods"/"workshop-<id>")`，结束时删除；workshop 原包在 `steamapps/workshop/content/322330/<id>`。
- modinfo 的 `folder_name` 分支可能加“假依赖”坑（目录名不匹配时注入不存在的 workshop 依赖）⇒ 用 `workshop-<id>` 命名最安全。

## 1. 跑 A/B
1. stock 侧：`DS_LUAJIT_FORCE_DISABLE_VM=1` + modsettings/modoverrides。期望日志：`[core.vm] Lua VM path disabled`、`modoverrides.lua enabling <mod>`、`modimport: ../mods/<mod>/…` 级联、`Registering prefabs`。
2. LuaJIT 侧：不设该 env；`force_mods="workshop-<id>"`（多个用 `;` 分隔）。期望：`[luajit] Force enable mod:`、`current vm type: jit`。
3. 需要工具链插件（`jit.tailcall` 等）时，把 LuaJIT2 mod（workshop-3444078585）也复制进 `mods/` 并一起 force-enable。

## 2. 抓真实加载错误（坑）
- 引擎 `moderror(message, level)` **只打印第一个参数**，`MOD ERROR: <mod> (<name>): Mod: <name>` 里没有真错误。
- 解法：出现 MOD ERROR 前/后尽快用 `proc.send_lua("local fm=ModManager.failedmods; print('[q] ERR='..tostring(fm[1] and fm[1].error))")`；查询要在 shutdown 之前发（检测到 MOD ERROR 后立刻发，别等世界生成）。
- 也可直接看 watcher 日志里的 `[string "..."]: … LUA ERROR stack traceback`（引擎会把 error 的 traceback 打到 stdout）。

## 3. mod env 限制
DST mod env 只有白名单全局（pairs/ipairs/print/math/table/type/string/tostring/require/Class/TUNING/GROUP/MODROOT/GLOBAL/modimport/modassert/moderror…），**没有** pcall/select/rawget/rawset/debug/getfenv/error/setmetatable。任何探针/间谍 mod 一律走 `GLOBAL.xxx`（`GLOBAL.rawget`、`GLOBAL.select`、`GLOBAL.pcall`、`GLOBAL.error`）。`getfenv()` 在 modmain 内需先 `GLOBAL.setmetatable(env,{__index=…GLOBAL.rawget(GLOBAL,k)…})` 之后才能从 GLOBAL 取到。

## 4. 指纹抹平验证（如需）
- 被验证目标（xvfb 无关）：`Mod/plugins/jit_runtime.lua` 的 `HideGlobalJIT` → 抹平 PUC/LuaJIT 差异：mod 代码 `require("ffi"|"jit"|"jit.*"|"ffi.*")` 报 stock 式 `module '<n>' not found:`、`debug.upvalueid/join=nil`、`string.dump` 返回 `\27Lua\81\0`+非 LJ 长度、清 `package.loaded.ffi/jit/luajit`、`tostring` 仅在构建输出 `builtin#N` 时改写。
- 机制要点：mod env 由 `ModManager:InitializeModMain` hook 记录；调用者判定必须**跳过 C 帧**（`pcall(require,…)` 的 pcall 帧 env=游戏全局）取第一个“非工具链” Lua 帧，工具链自己的包装帧要登记在 skip 表里。
- 离线冒烟：`luajit builds/moyuxuanli_decoded/mask_test.lua`（期望：mod 视角全被抹平；工具链/引擎视角保持真 API；`luajit_compatible` mod 豁免且仍拿到 `env.jit`）。
- 部署：工坊 mod 3444078585 的 `plugins/` 与仓库 `Mod/plugins` 同 inode（目录联接），改仓库文件即对客户端/服务端生效。

## 5. 判定模板
- stock 成功 + LuaJIT 失败 + 垫片（`LJ_DS_slowtailcall_mods` 已含该 mod）无效 + 伪装判定后失败不变 ⇒ 加固壳的 payload 生成在 LuaJIT 下走形（不兼容），不是“检测到就拒绝”。
- 用户可用的规避：LuaJIT2 mod 的 `LuaVmType` 选项（`Mod/modmain.lua` 的 `SwitchVm` → `GameInjector.DS_LUAJIT_set_vm_type`）切到 `lua51`/`game`。
