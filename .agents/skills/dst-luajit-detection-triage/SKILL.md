---
name: dst-luajit-detection-triage
description: 分析 DST 受保护/混淆 mod 是否有 LuaJIT 检测或对抗行为：解壳字符串表、在真实游戏环境（tests/harness 专用服务器，LuaJIT vs stock）跑 A/B、读引擎丢失的错误文本、必要时伪装检测点定位机制
---

# DST 受保护 Mod 的 LuaJIT 检测/对抗排查

适用：怀疑某加密/混淆 DST mod 检测或拒绝 LuaJIT（本仓 LuaJIT2 运行时）。产出：检测点清单、真实游戏环境下的加载行为、机制判定（检测驱动 vs 纯不兼容）与规避建议。

## 1. 定位代码
- 加密壳形态识别见技能 `decrypt-encrypted-mods`（frostxx / 自校验壳 / 纯混淆）。
- 纯 VM 混淆（hercules/MyxlHttps 家族）三要素：字符串表**区间反转三次** + **自定义 64 字符 base64**（`char->index` 表就在文件里，反演得 value->char）+ 状态机 VM（`while PC do if PC<C[k] …`，常量数组 `g`，取值器 `local function z(z)return g[z+OFFSET]end`，注意反转置换后索引要复算）。
- 快速全文搜索：解码全部字符串常量的 `\ddd`（**Lua 的 \ddd 是十进制**，不是八进制）与自定义 base64，再 grep `jit|ffi|LuaJit|upvalueid|string%.dump|builtin`。
- 典型向量（workshop-3014076942 实测 9 条，诊断串 `LuaJit detected via …`）：`require("ffi")`、`require("jit")`、`GLOBAL.jit`（`type(jit)=="table"`）、`debug.upvalueid|upvaluejoin`、`string.dump`（头部+长度双重判据：只改头部或只补长度都骗不过）、`tostring(<C 函数>)` 里的 `builtin#N`（base/debug/math/os 四族）。

## 2. 真实游戏环境 A/B（tests/harness）
```
python builds/<task>/game_env_test.py <mode>        # 模式示例：force / force2 / force3 / force4 / stock / stockmod2
```
- `force*`：`DedicatedProc.start(..., force_mods="workshop-A;workshop-B")`（分号分隔；注入器 Lua 侧 force-enable，仅 LuaJIT 路径有效）。
- stock 对照：`extra_env={"DS_LUAJIT_FORCE_DISABLE_VM": "1"}`；此后 force-enable 不生效，需写 `<game>/mods/modsettings.lua`：`ForceEnableMod("workshop-<id>")`（或无副作用地写 `<persist>/DoNotStarveTogether/<cluster>/modoverrides.lua`，键用 id 或 workshop-id）。
- 注入 mod 目录名要满足 modinfo 的 `folder_name:match` 分支（如 3014076942 含 "76942"，否则会塞入不存在的依赖 workshop-123456789203）。

## 3. 读错误（关键坑）
- 引擎 `moderror(message, level)` 只用**第一参**：`mods.lua` 传的 `"…Error loading mod!\n"..r` 被当 level 丢掉 → `MOD ERROR:` 行只有前缀。
- 真错误在：①stdout/watcher 里 `MOD ERROR` 之后的 `[string "…"]:1: …` 多行 traceback；②控制台 `print(ModManager.failedmods[i].error)`；③`data/unsafedata/luajit_crash.json`。
- 壳内异常常见伪装成 `[string "main_loader"]:1: Error in modimport: modmain.lua` + 内层 `main function has more than 67108864 bytecode instructions`（= LuaJIT 解析器上限 LJ_MAX_BCINS=2^26；PUC 5.1 上限是 MAX_INT）→ 同一 payload 在 stock 下能编过，jit 下失败。

## 4. 机制判定（检测驱动 vs 不兼容）
- 判定要点：把检测向量**全部伪装成非 LuaJIT**（探针 mod，priority 高于目标 mod、低于工具链）：`GLOBAL.require` 对 ffi/jit/luajit(/jit.*/ffi.*) 抛 stock 式 `module '<n>' not found:`、`jit` 全局 nil、`debug.upvalueid/upvaluejoin=nil`、`string.dump` 返 `"\27Lua\81\0"..d:sub(5)..string.rep("\0",#d)`。
- 伪装后失败不变 ⇒ 不是“检测到就拒绝”，多为壳 payload 生成在 LuaJIT 下走形（用 stock 侧同一阶段耗时对比可佐证：stock 秒内完成 ⇒ 两侧生成物不同）。
- 相关栈判定坑：注入器把 pcall/require 用 Lua 包过；`return f(x)` 尾调用会替换 mod 帧 → 单靠“第一个 Lua 帧”判归属会漏。

## 5. 输出/规避
- 结论要区分“有检测（静默记录）”与“实际加载失败”，并给出组合矩阵（client/server × stock/jit、有无垫片、有无伪装）。
- 规避：`LuaVmType`（Mod/modmain.lua 的 SwitchVm → GameInjector.DS_LUAJIT_set_vm_type）切 `lua51`/`game`；`LJ_DS_slowtailcall_mods`（encrypted-mod 垫片）对这类壳 payload 问题无效。
- 想抓壳动态加载的 chunk：`tests/sect/simulator_ingame.lua`（`load` 代理落盘 `bin64/unsafedata/`，需要 newproxy(fn) 可调用代理=jit VM）。
