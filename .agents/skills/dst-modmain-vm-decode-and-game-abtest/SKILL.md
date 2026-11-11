---
name: dst-modmain-vm-decode-and-game-abtest
description: "DST 受保护 modmain（VM/自定义 base64 混淆家族）的字符串解码，以及用 tests/harness 在真实游戏里做 jit vs 原版 A/B 探针测试的流程。Use when: 分析/解密受保护 DST mod、modmain VM 混淆、自定义 base64 字符串表、LuaJit 检测、游戏环境加载测试、ModManager.failedmods、force_enable_mods。"
---

# DST 受保护 modmain：解码 + 游戏环境 A/B 探针

适用：单行数万字节的 VM 混淆 modmain（`local g={...}` / `local e={...}` 常量表 + 状态机 + `bit` 位运算 + 字符串表）；以及需要用**真实引擎**验证「mod 在 LuaJIT 与原版下行为差异」的场景。
（frostxx/风讯加密文件、带自校验的 shell 见用户技能 `decrypt-encrypted-mods`，不要重复。）

## 0. 纪律
- 一切产物写到 `builds/<task>/`，保持 mod 本体原样。
- **Lua 的 `\ddd` 转义是十进制**（`\049`='1'、`\061`='='），不是八进制；手写正则解码时先用单样本自证（例：把 `\115\116\114\105\110\103` 解成 `string`）。

## 1. 先判型（30 秒）
- 文件是否单行、`local <名字>={` 开头、大量 `a=b+c` 数字表达式、字符串里全是 `\ddd` → VM 混淆家族。
- 常见特征串（可先用 `grep -a` 粗筛）：`bit.lshift`、`table.concat`、`string.char`、`%4`、`while <pc> do`。

## 2. 字符串表解码（可复现步骤）
1. 取字符索引表：找 `local <z>={o=...,j=...,["+"]=...}`，把它解析成 **char→value(0..63)**；同名 key 后出现的覆盖前面的（例如 `[")"]=50` 之后 `["\049"]=6`）。
2. 反转 value→char 得到 64 字符字母表；逐字符串用标准 4×6bit→3×8bit 解码，`=` 或脚本自带的 padding 分支残留 1~2 字节。
3. 自证：解出的应是可读标识符/中文（DM 是 `\149\...` 的十进制转义，先正确 unescape 再解码）。
4. 常量表本身会被「区间反转」重排（样例：先把 `{{1,90},{1,146},{147,390}}` 逐个按首尾向中间 swap）——`z(idx)` 的取值索引要把这段置换算进去，否则对不上。
5. 有运行时才能确定的东西（生成物、隐藏分支）就不要硬解：直接进第 3 步动态探。

## 3. 游戏环境 A/B（tests/harness）
- 起服：`DedicatedProc.start(game_dir, persist_root, cluster, shard, force_mods="<folder>")`；`injected_mod(game_dir, src, folder)` 复制到 `game/mods/<folder>` 并在退出时清理；离线集群用 `write_offline_cluster`；日志看 stdout + `server_log.txt` + `DontStarveInjector_server.log`。
- **A（LuaJIT）**：默认（`vm=jit`）；**B（原版）**：`extra_env={"DS_LUAJIT_FORCE_DISABLE_VM"="1"}`。
- 原版下 `force_enable_mods` 不生效（属 LuaJIT 侧框架）：写 `<game>/mods/modsettings.lua`（`ForceEnableMod("<folder>")`）或集群 `modoverrides.lua`，并记得回滚该文件。
- **探针 mod**（比 console 注入可靠，能跑到目标 mod 之前）：`priority=-1`，modmain 里只打印 `GLOBAL.*`（mod env 无 rawget/select/pcall/debug/package）：`rawget(GLOBAL,"jit")`、`pcall(require,…)`、`debug.upvalueid`、`string.dump(f):sub(1,4)` 与 `#`、`tostring(GLOBAL.print)`、`pcall(newproxy, function() end)`。
- 引擎错误文本：`moderror` 只打印第一个参数 → 用控制台 `ModManager.failedmods[i].error` 拿真实错误（同名 `KnownModIndex.savedata.known_mods[mod]` 可查 enabled/disabled_bad）。
- 结论证据要区分：`MOD ERROR` 行只给前缀；真正原因常在紧随的 traceback（如 LuaJIT 的 `main function has more than 67108864 bytecode instructions` = `LJ_MAX_BCINS` 2^26）。

## 4. 判断「检测」还是「不兼容」
- 先解出检测字符串清单（第 2 步），再在探针里逐项实测「当前运行时是否命中」。
- 要区分「检测驱动」与「生成物/不兼容」：用一个 **spoof 探针**（`priority=-1`，在目标 mod 之前）把检测项改成原版形态——`require` 对 `ffi`/`jit`/`jit.*` 抛 `module '<n>' not found:`、`debug.upvalueid/upvaluejoin=nil`、`string.dump` 返回 stock 头+非 LJ 长度、`_G.jit=nil`。若失败表现完全不变 ⇒ 与检测判定无关。
- 若要真的屏蔽（例如放进 `HideGlobalJIT`）：mod env 级前端（`env.require`/`env.string`/`env.newproxy`，尾调用也拦得住）＋全局兜底（栈判定要跳过 C 帧、自身帧与**游戏全局环境帧**；注入器把 pcall/require 用 Lua 包过）。探针面清单与源码锚点见 `docs/luajit-probe-surface.md`。

## 5. 收尾
- 产物：`builds/<task>/`（解码字符串、常量表、annotated 源码、`game_env_test.py`、`gameenv/<mode>/` 日志、探针 mod）。
- 结论里写清「验证到哪一格」：例如 客户端/服务器 × 原版/LuaJIT 的 2×2 覆盖情况。
