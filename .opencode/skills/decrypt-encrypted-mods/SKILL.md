---
name: decrypt-encrypted-mods
description: "DST 加密/受保护 mod 的解密与反混淆流程（frostxx/Fengxun 加密文件、自校验保护壳 shell）。Use when user says: 解密mod, 加密mod, 解密modmain, 反混淆, 保护壳, decrypt mod, encrypted mod, obfuscated modmain, protected mod, modmain0.lua, frostxx, 风讯."
---

# DST 加密 / 受保护 Mod 解密流程

## 0. 判型（先做这个，30 秒）

| 形态 | 识别特征 | 走哪条车道 |
|---|---|---|
| **frostxx/Fengxun 加密文件** | 文件高熵/二进制；mod 目录内有 `modmain0.lua`（或请求 `modmain.lua` 实际读到加密体）；modmain.lua 前 12 行内出现 `frostxx@qq.com` | **Lane 1** |
| **自校验保护壳（shell）** | `modmain.lua` 是**单行数十 KB** 的混淆体（`local a={...}` 开头、`end)(...,("3134…"))` 结尾）；旁边有伴生 `modmain_.lua`；业务层 `main.lua`/`config.lua`/`scripts/` | **Lane 2** |
| 普通混淆 | 字符串表 + 查表函数，无自校验 | 只用 Lane 2 的静态抽取（步骤 3/4） |

运行期判定已内置在本项目：`Mod/plugins/jit_tailcall.lua` 的 `EncryptedModManager.check_encrypted()` —— 行长 > 1024 判 "encrypted"（shell 类），行内 `frostxx@qq.com` 判 `frostxxMods`（走 Fengxun 解密），非法 UTF-8 也判 encrypted。

> 通用纪律：**一切产物写到独立目录**（如 `builds/<task>/`），保持 mod 本体原样——自校验/回退都依赖原始字节。

---

## Lane 1 — frostxx / Fengxun 加密文件

### 算法（离线复刻，已实测）
来源：`src/DontStarveInjector/plugins/plugin_core_vm/io/gameio.cpp:301`（`DS_LUAJIT_Fengxun_Decrypt`）

```
cipher -> plain:
  split = 7997
  part1 = data[0:7997]; part2 = data[7997:]      # len < 7997 时 part2 为空
  f(x)  = bytes((b + 7) & 0xFF for b in reversed(x))
  plain = f(part2) .. f(part1)                   # 注意：密文尾部解出的是明文头部
```
逆变换（`--encrypt`，用于 round-trip 验证）：`cipher = g(plain[-7997:]) .. g(plain[:-7997])`，`g(x)=reversed(x)-7`。

### 三种用法
1. **离线单文件**：`python .opencode/skills/decrypt-encrypted-mods/scripts/fengxun_decrypt.py <cipher> [out]`（`--selftest` 自测；已通过 CLI round-trip）。
2. **运行期自动解密**（游戏/服务器内）：本项目 `Mod/plugins/jit_runtime.lua` 的 `HookKleiloadlua` 已实现——把 `modmain.lua` 重定向到 `modmain0.lua` 并调用 `injector.DS_LUAJIT_Fengxun_Decrypt(filename)`。名单来自 `jit_tailcall.lua`（`ctx.frostxx_mods`），受编译期开关约束。
3. **运行期抓明文（spy mod）**：写一个自制 mod 包住 `kleiloadlua/require/loadstring` 记日志，并用 `GameInjector.DS_LUAJIT_Fengxun_Decrypt(MODROOT..f)` 把解密结果导出到文件/日志。参考实现：`builds/hang_repro/autorefuel_spy/modmain.lua`。

---

## Lane 2 — 自校验保护壳（VM + 逐字节哈希）

样例：`workshop-2130351510`（实测全解析，产物见 `builds/hang_repro/shell_analysis/`）。

### 实测运行链
```
engine → modmain.lua（保护器）
  → 反调试闸门（11812201：读 env._G；存在则 rawget(它,"ModManager")，缺失 ⇒
       print("Do not debug this file!") + 写 info.vbs + wscript 弹窗）
  → 4864660：组装 {require=env.require, modimport=env.modimport,
                   loadfile=GLOBAL.loadfile, kleiloadlua=GLOBAL.kleiloadlua}
             + rawget(GLOBAL,"jit")（仅探测 jit.flush，行为不因 jit 变化）
  → 9178904：池构建器（把 encrypt/decrypt/validateMainFile/isValidModFile/readAllContent/
             splitString(Optimized)/chunkParts/executeCode/loadName/fileType/shouldExecute/
             useGlobalEnv/checkAndCollectGarbage/isHookedFunction/kleiloadlua/loadFile/
             fallbackToOriginal/getSourceFileName/toHex/fromHex 以闭包注册；LCG 随机池键）
  → 自校验：io.open(MODROOT..<当前 chunk 源文件名>,"rb") → read("*all") → close
            → 剥离 16 字符 key 串（样例 "3134386332343937"）
            → 逐字节 h=(h*31+byte)%4294967295（注意是 2^32−1）
            → 与内嵌期望值比对（比较点原文 `_v=_p;_p=_v==__;_J={_p}`，全文唯一）
  → 通过：debug.getinfo(...).source → 去 "@"/".lua" → 拼 "<stem>_.lua" → modimport(伴生体)
         → 伴生体 modimport config.lua / main.lua
```

### 保护范围（实测矩阵）
| 文件 | 可否直接改 |
|---|---|
| `modmain.lua`（保护器本体） | ❌ 逐字节哈希；加 12B 惰性注释即静默终止 |
| `modmain_.lua`（伴生体）/ `config.lua` / `main.lua` / `scripts/*` | ✅ 随意修改，无任何校验 |

### 六步流程

**步骤 1 — 搭 harness**（引擎等价）：用 `harness/shell_harness.lua`
```bash
LJ=<可用的 luajit.exe>          # 任选一个构建产物；先 ` "$LJ" -v` 确认能跑
H=.opencode/skills/decrypt-encrypted-mods/harness/shell_harness.lua
# A: 原始文件 → 应看到 modimport modmain_.lua → config.lua → main.lua
"$LJ" "$H" builds/skill_test/A.log <mod-root>
# B: 改过的文件 → 应“静默终止”（日志里 0 条 modimport）
"$LJ" "$H" builds/skill_test/B.log <mod-root-modified>
# C: 改过的文件 + 对自校验喂原始字节（绕过 A）
"$LJ" "$H" builds/skill_test/C.log <mod-root-modified> 0 <modname> <pristine-modmain.lua>
```
harness 关键事实（对照 `data/scripts/mods.lua` `CreateEnvironment`）：
- env 是**无元表普通表**；`env.env=env`；`env.GLOBAL=游戏全局`；`env.modname/MODROOT`。
- **不要给 env 加 `_G`**——那会踩中反调试闸门（引擎 env 没有 `_G`，闸门天然跳过）。
- 用**真 debug**（`debug.load` 必须保持 C 函数，否则指纹 `what=="C"` 失败）。
- `io/os/loadfile/kleiloadlua` 由 `GLOBAL` 提供；`modimport` 桩要真的加载 `ROOT/<name>`。
- 判活口令：日志出现 `modimport modmain_.lua` = 校验通过；没有 = 校验失败（静默终止）。

**步骤 2 — 动态追踪**（定位真实路径）
- 在 `while <pc> do` 后插 `io.write("PC:",tostring(<pc>),";")` → PC 状态轨迹；
- 给片段名函数插桩（`f(g)` 打印 `F[i]=<值>`）→ 看每个用法读到的名字；
- 对照块列表（步骤 3）读代码；改文件/不改文件重跑，比 A/B 轨迹。

**步骤 3 — 静态抽取派发树**
```bash
python .opencode/skills/decrypt-encrypted-mods/scripts/extract_program.py \
  --src <去混淆后的文件.lua> --vm _p \
  --alphabet 2yfzShEe/ZCV0jQRG8cAXt1LUlHpJiT+augNrWmOYqI9PMvB5K7Fxobw6sk4Dn3d \
  --out blocks.txt
# → 177 块 + 每块状态区间 + (可选) 名字解码；与本会话 shell_program.txt 实测一致
```
前提：先把 `a[...]`/`f(...)` 解析成字面量（否则派发常量不是数字）。命名解码字母表可从文件自身 `char->index` 表反演。

**步骤 4 — 池函数映射**：线性扫 `_H=<H>((PC),{…})`（闭包创建）+ `TBL[VAR]=_H`（注册）⇒ name→PC 表；样例结果见 `shell_analysis/pool_functions.txt`。

**步骤 5 — 校验与绕过**
- 绕过 A（推荐、无需改代码）：磁盘留原始文件，让自校验的读请求返回原始内容（步骤 1 的 C 用法）。
- 绕过 B（自包含）：改文件 + 把唯一比较处 `_v=_p;_p=_v==__;_J={_p}` 改成 `_v=_p;_p=true;_J={_p}`。
- 其它闸门：`isHookedFunction`（`debug.getinfo(debug.load).what=="C"`）、`sethook` 拦截、`ModManager` 存在性、`jit` 存在性（仅信息）。

**步骤 6 — 验证**：跑步骤 1 的 A/B/C 三连；A 与 C 应到 `modimport main.lua`（其后错误只应是引擎模块缺失，如 `scheduler`/`GetTick`——需要真实引擎）。

---

## 通用坑

- **单行 Lua 文件**：切勿插入 `--` 行注释（会吞掉同一行后续全部代码）；文件**末尾追加**注释行安全。
- 引擎 mod env 没有 `io/select/loadfile`：保护器一律从 `GLOBAL` 拿；harness 的 GLOBAL 必须备齐 `io/os/debug/loadfile/kleiloadlua`。
- `require` 需要把 mod 的 `scripts/`（以及引擎 `data/scripts/`）加入 `package.path`。
- 更深层载荷（`coroutine_manager` → `scheduler` → `GetTick` 等 C API）只能在真实引擎里跑完。
- 选 luajit 二进制前先 `-v` 验证（构建目录里可能存在被截断/过期的 exe）。

## 参考（本仓）

- 全量报告与证据：`builds/hang_repro/shell_analysis/` —— `report.md`、`host_program_blocks.txt`（177 块）、`pool_functions.txt`、`coverage_t1..t4_*.log`、`run_bypass_proof.log`、`run_bypass_selfcontained.log`、`h13–h18.lua`。
- 运行期解密入口：`Mod/plugins/jit_runtime.lua`（`HookKleiloadlua`）；加密判定：`Mod/plugins/jit_tailcall.lua`（`EncryptedModManager.check_encrypted`）。
- C 实现：`src/DontStarveInjector/plugins/plugin_core_vm/io/gameio.cpp:301`。
- 引擎 mod env 事实：`Don't Starve Together/data/scripts/mods.lua` `CreateEnvironment`（约 302–337 行）。
