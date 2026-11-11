---
name: dst-luajit-worldgen-jit-hiding-triage
description: DST LuaJIT 下世界生成卡死/建世界失败的定位：区分 modmain 与 modworldgenmain 两条加载通道，用专用服务器 harness 做 A/B
---

# DST LuaJIT: 世界生成卡死 / “创建世界”界面卡住

## 先分清两条 mod 加载通道

| 通道 | 触发 | 加载的文件 | 注入器插件是否生效 |
|---|---|---|---|
| 主加载（客户端/服务器主循环） | `main.lua` → `ModManager:LoadMods()` | `modmain.lua` | 是（`jit.runtime` HideGlobalJIT 等） |
| 世界生成 | `scripts/worldgen_main.lua` → `ModManager:LoadMods(true)` | **只有 `modworldgenmain.lua`**（`scripts/mods.lua:579`） | **否** |

⇒ modmain 里做的 jit 隐藏/补丁在世界生成阶段**不生效**。仓库的补救通道是 **`Mod/modworldgenmain.lua`**（`WORLDGEN_MAIN` 判定 + `rawset(GLOBAL,"jit",nil)` + 清 `package.loaded.jit`，priority 2e53 最先加载）。

## 复现（专用服务器建世界）

`python builds/myth_hang/run_myth.py jit [秒]`

- `MYTH_MODS=id1,id2,...` 指定 workshop id（脚本从 `steamapps/workshop/content/322330/<id>` 拷到 `mods/workshop-<id>`）。
- `MYTH_RUNTIME_MOD=3444078585`（默认）把运行时 mod 以 **junction**（`mklink /J mods/workshop-3444078585 -> <repo>/Mod`）挂进 mods/；置空即“无运行时 mod”对照组。
- `MYTH_VM_DLL=<dll>` 换 VM（如 `builds/yutu_crash/lua51DS_nopatch.dll` 验“是不是 filter 补丁导致”）。
- 默认 VM = `Mod/deps/lua51DS.dll`；PUC 对照用 `stock` 模式（`DS_LUAJIT_FORCE_DISABLE_VM=1`）。
- 判定：出现 `World generated` 即成功；150 s 无日志增长判 STALL。

**坑**：两次运行**不能重叠**——同一 harness 端口 11998，重叠加会得到假失败（`RakNet UDP startup failed: SOCKET_PORT_ALREADY_IN_USE`）。跑前确认没有 `dontstarve_dedicated_server_nullrenderer.exe` 残留。

## 判读日志

- `MOD ERROR: <mod>: … modworldgenmain.lua:1: attempt to index local 'K' (a nil value)`：混淆 VM（DaxSg/风雪系）在 LuaJIT 下走坏路径。
- `PANIC: missing required prefab [xxx]! Expected 1, got 0` + `An error occured during world and we give up! [was 5 of 5]`：该 mod 的 worldgen prefab 没注册成功 ⇒ 世界生成放弃（客户端卡“创建世界”）。
- `worldgen success` 反复出现但 `World generated` 为 0 ⇒ 一直在重试。
- 每次重试都会重载 mod（MOD ERROR 计数 = 重试次数）。

## 诊断顺序

1. 先跑 **stock**：成功 ⇒ LuaJIT 专属问题。
2. 再跑 **带运行时 mod**：成功 ⇒ 对方是旧版运行时 mod / 未启用 / `HideGlobalJIT` 被关。
3. 仍失败 ⇒ 换 `MYTH_VM_DLL` 验 filter 补丁（nopatch DLL）；都失败说明是混淆 VM 本身与 LuaJIT 的语义差异（非我们的补丁）。
4. 需要更深的插桩时：`modworldgenmain` 里 `GLOBAL.io` 可能是 nil，探针输出走 `print`；`debug.sethook("c")` 会显著拖慢 worldgen 并触发 STALL 误判。

## 发布层面

`Mod/deps/lua51DS*.dll` 被 `.gitignore` 忽略；`Downloads/windows_Mod/` 与 `windows_Mod.zip` 是快照。修完 DLL 必须重新拷贝进包/重写 zip 条目（`zipfile.writestr(info, data)` 保留原 ZipInfo），否则对外分发仍复现。
