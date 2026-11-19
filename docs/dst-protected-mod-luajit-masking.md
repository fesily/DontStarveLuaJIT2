# DST 受保护 Mod 在 LuaJIT 下的 C API 掩码与 reader 语义

> 目标案例：`workshop-3014076942`（【璇儿】Xuaner 6.2.x，自校验保护壳）
>
> 2026-11-14 根因复核：**首调即 EOF 的 `load(reader)`，PUC 5.1 调用 reader 两次，LuaJIT 只调用一次。** 目标壳依赖这项副作用。
>
> 最终方案已把这次缺失的调用下沉到 VM：`lj_lex_setup` 在 `LJ_DS_PUC51_LOAD_EOF_RETRY` 下对首次 EOF 再读一次，reader 调用次数与 PUC 5.1 一致。C gate 的 peek/replay 已删除；只保留 `dump_lua_mods` 的 dump-only `lua_loadx` 包装。游戏内 bytecode 拒绝仍由编译期宏 `LJ_DS_REJECT_BINARY_CHUNKS`（默认 `LJ_DS`，无运行时开关）执行；另加按 state 的外侧开关 `lua_ds_allow_lj_bytecode(L, allow)`（原生 LuaJIT 字节码模式：既放行 `\x1bLJ` 的加载，也让 `string.dump` 保持原生），供 CLI / 工具 / 注入器私有 state 使用；游戏态与 mod 可见路径保持掩码行为，PUC 5.1 字节码依旧由 `LJ_DS_PUC51_DUMP` 拒绝。目标 mod 已进入 `Sim paused`。

## 1. 症状

- Stock PUC 5.1 下 mod 正常加载。
- 注入 LuaJIT 后，早期表现为：
  ```
  [string "../mods/workshop-3014076942/modmain.lua"]:1:
  attempt to index local 'PL' (a nil value)
  ```
  或直接：
  ```
  not enough memory
  ```
- 早期 C API 指纹问题与最后的 OOM 需要分开：本轮确认，去掉 gate 后的 OOM 来自外层 reader 反复返回同一段源码、编译无法结束；不能仅凭 OOM 就认定壳主动进入 anti-JIT 分支。

## 2. 最终最小方案

| 层 | 措施 |
|---|---|
| VM lexer | `lj_lex_setup`：`LJ_DS_PUC51_LOAD_EOF_RETRY` 在首次 EOF 再调一次 reader，匹配 PUC 5.1 的两次调用；`LJ_DS_REJECT_BINARY_CHUNKS` 编译期拒绝所有 `\x1b`（默认 `LJ_DS`）；`lua_ds_allow_lj_bytecode(L, 1)` 可按 state 关闭它，`LJ_DS_PUC51_DUMP` 仍拒绝 `\x1bLua` |
| injector `lua_loadx` | **仅 dump**：只有 `dump_lua_mods` 非空（`LuaModDumpEnabled()`）时才安装 hook，命中 mod 时用 `LuaModDumpReader`；不再 peek/回放/做 bytecode 检查；dump 关闭时加载路径无 hook |
| VM bytecode reader | `bcread_header` 恢复原始实现；`\x1bLJ` 仍可被独立 VM/CLI 加载 |
| `string.dump` | 有 injector bridge（`lj_ds_puc_dump`）时**无条件 PUC 5.1**；独立 CLI/VM 无 bridge 时保持原生 LuaJIT dump |
| `require` | stock require 的 package 表保留原 `loaded=registry._LOADED` 身份和真实 loader 链（游戏启动后插入的 custom loader 仍可见），只清除扩展 `loaded/preload` 并把 `loadlib` 换成拒绝 `luaopen_ffi/bit/jit/memprof/string_buffer/string/table/debug` 的 wrapper；`GLOBAL.package` 仍是这张处理后的真实表，`GLOBAL.require` 仍是 stock C require 原对象，扩展名自然报 stock `module '...' not found:`。声明了 `modinfo.luajit_compatible` 的 mod 拿到独立 `real_package` 视图（`loaded` overlay：扩展 raw + `__index=safe`，`preload/loaders/loadlib` 同安全面）和私有 loader；普通 mod 的 env.package 是独立 safe 视图。`GLOBAL.bit` 保留（DST 脚本使用） |
| `loadstring` | 不需要 Lua 侧 patch：VM 自己按 PUC 规则报文案与 chunk 名 |
| `jit` / `package` / registry | 注入器状态全部收进每个 state 的**私有 root**（LuaJIT：`global_State.registry2tv`，与公开 registry 同点初始化、`LUA_REGISTRYINDEX2`/`registry2(L)` 同一套 index2adr 路径；PUC：`registry[GameLuaContext*]` 是一个 C holder，root table 是它的 upvalue 1，5.1 debug 库拒绝 C 函数 upvalue，所以不需要过滤 `debug.getregistry`）。`LUA_REGISTRYINDEX2` 由编译期 `LJ_DS_REGISTRY2` 控制：默认 `0` 时等同 `LUA_REGISTRYINDEX`、不分配 `registry2tv`，CMake 选项默认 `ON` 保持本产品的独立 registry。`jit._private_registry` 已删除；宿主/测试通过 C API（`LUA_REGISTRYINDEX2` 或 `PrivateLuaRegistry`）读取 root。`GLOBAL.jit`、共享 `safe_package.loaded/preload`、`registry._LOADED/_PRELOAD` 清空扩展项；声明兼容的 mod 拿到真实 package（扩展 overlay）和自己的 jit/bit/ffi/debug/table/string 副本 |
| 删除 | `LuaLoadGate` 的 peek/replay/0x1b 检查、`LJ_DS_NEW_PROXY_PATCH`、旧 newproxy C proxy、旧 per-env `env.string` dump wrapper |

部署产物：

- `Mod/deps/liblua51DS.so`
- `Mod/plugins/plugin_core_vm/plugin_core_vm.so`
- `Mod/scripts/luajit_mod_blacklist.lua`（运行时读取）

## 3. 真正的差异：首次即 EOF 时，reader 调用一次还是两次

### 3.1 PUC 5.1 先探测格式，再初始化 lexer

源码链：

```
f_parser                         src/lua51/src/ldo.c
 -> luaZ_lookahead
    -> luaZ_fill -> reader()      第一次，返回 nil / 0 字节
 -> luaY_parser                  非字节码，仍进入源码 parser
    -> luaX_setinput
       -> next(ls) -> luaZ_fill
          -> reader()            第二次
```

`luaZ_lookahead` 遇到 EOF 不会保存一个永久 EOF 状态；随后 `luaX_setinput`
仍读取首字符。因此，即使第一次 reader 返回 nil 或空串，仍可能调用第二次。
两次调用都在 PUC 的 protected parser 中。

### 3.2 LuaJIT 一次读取同时完成格式探测和 lexer 初始化

```
lua_loadx -> cpparser -> lj_lex_setup
 -> lex_next -> lex_more -> reader()    第一次，返回 EOF
 -> lj_parse                           直接编译空 chunk，无第二次 reader 调用
```

VM 宏 `LJ_DS_PUC51_LOAD_EOF_RETRY` 的效果是：

```
lj_lex_setup
 -> lex_next -> lex_more -> reader()    第一次，返回 EOF
 -> if (ls->c == LEX_EOF) lex_next()    PUC 5.1 的第二次调用
    -> lex_more -> reader()             第二次；若返回数据则继续解析
```

这使空 reader 的调用次数恰好与 PUC 5.1 一样；C gate 的 peek/replay 已删除。
**决定目标壳能否继续的是这次额外调用的副作用，不是首调在 parser 外，也不是前 4 字节的切分。**

### 3.3 实测：三组 reader 的 Lua-visible 栈

探针 mod 在 reader 里打印 `debug.getinfo(level,"Sln")`：

**PUC 5.1**

```
1:C/pcall | 2:Lua/reader(modmain) | 3:C/load | 4:main(modmain)
| 5:C/xpcall | 6:Lua/RunInEnvironment | 7:InitializeModMain | 8:LoadMods
| 9:ModSafeStartup | 10:callback
```

**LuaJIT raw（无 C gate）**

```
1:C/pcall | 2:Lua/reader(modmain) | 3:C/load | 4:main(modmain)
| 5:C/nil | 6:tail/(tail call) | 7:InitializeModMain | 8:LoadMods
| 9:ModSafeStartup | 10:callback
```

**C gate**

与 raw **逐字一致**。

要点：

- `raw` 与 `gate` 的 Lua-visible 栈完全相同 → **C gate 对 Lua `debug` 是透明的**；
- PUC 与 LuaJIT 的差异在 5/6 层：`xpcall + Lua RunInEnvironment` vs `xpcall + tail pseudo-frame`。这是 **VM 指纹**，与 C gate 无关；
- C gate 确实改变了 reader 首调所在的 C 调用链；但第 5.5 节的 inside 对照证明，这不是本案例成败的原因。

### 3.4 直接 nil reader 的调用次数实测

独立探针 mod 的 reader 恒返回 nil（不依赖目标壳）：

```lua
local n = 0
local function reader()
    n = n + 1
    print("[reader]", n, "return nil")
    return nil
end
local f, e = load(reader)
print("[reader] load", f ~= nil, tostring(e))
if f then print("[reader] call", tostring(f())) end
```

三组结果（logs `/tmp/reader_nil_{puc,raw,gate}.log`）：

| 实现 | reader 调用 | `load` 结果 |
|---|---|---|
| PUC 5.1 | **2 次** | 空函数 |
| LuaJIT raw（无 C gate） | **1 次** | 空函数 |
| C gate | **2 次** | 空函数 |

```
PUC  : [reader] 1 return nil; [reader] 2 return nil; load true
raw  : [reader] 1 return nil                     ; load true
gate : [reader] 1 return nil; [reader] 2 return nil; load true
```

`load` 都成功（空函数），差异只在 **reader 的调用次数**：raw 少一次，C gate 的 peek 补回；这与第 5.5 节 `eof` 变体（禁止第二次调用）导致重复首块/OOM 的结论互相印证。

## 4. 最小复现：不用游戏、不用壳、不用字节码

```lua
for _, first in ipairs({"nil", "empty"}) do
    local calls = 0
    local f, err = load(function()
        calls = calls + 1
        if first == "empty" then return "" end
        -- nil 分支隐式返回 nil
    end)
    print(first, calls, type(f), err)
end
```

本机构建与系统 PUC 5.1 的结果一致：

| VM | 始终返回 nil | 始终返回空串 | 编译结果 |
|---|---:|---:|---|
| PUC 5.1 | 2 次 | 2 次 | 成功，空函数 |
| 当前 LuaJIT fork，无 gate | 1 次 | 1 次 | 成功，空函数 |

复现命令：

```bash
builds/ninja-multi-vcpkg/src/lua51original/RelWithDebInfo/lua /tmp/dst-mask-diagnosis/empty-reader.lua
builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/luajit /tmp/dst-mask-diagnosis/empty-reader.lua
```

普通非空 reader 的输出块切分，以及相同 `debug.getinfo` 栈，均无法证明空 reader
的调用次数相同。此前只用 `return 1+1` 做探针，漏掉了目标真正依赖的边界。

## 5. 已验证的“无字节码/reader”事实

### 5.1 目标 mod 本体没有预编译 Lua chunk

```
non-asset files with \x1bLJ : none
non-asset files with \x1bLua: none
modmain.lua 开头: "GLOBAL.setmetata..."
scripts/**：全部源码
```

`assets/*.dyn|*.tex` 中的 `0x1b` 是二进制资源随机字节，不会作为 `lua_load` 输入。

### 5.2 游戏内 `string.dump` 是 PUC，不是 LJ

```
[tgt] dump_head "\27Lua" len 151
[tgt] dump_load false  binary string: Disallowed functionality in precompiled chunk
```

CLI 里的 `lj function` 来自**没有 injector bridge 的独立 VM**（`lj_ds_puc_dump == NULL`），不是游戏路径。

### 5.3 游戏 `lua_loadx` 的全部 chunk 都是源码

临时 `[gate-head]` 诊断（44136 个 chunk）：

```
total chunks: 44136
chunks starting 0x1b: 0
heads: 6d 61 74 68 ("math"), 2d 2d 5b 5b ("--[["), 47 61 6d 65 ("Game"),
       6c 6f 63 61 ("loca"), 50 52 49 4e ("PRIN"), 72 65 71 75 ("requ"), ...
```

C gate 拒绝任何 `0x1b`；带 gate 时目标能加载，反推出这些 chunk 里没有可拒绝的 bytecode。

### 5.4 实际壳：嵌套空 reader 改变外层源码流的进度

原始 mod 保持不变，使用独立诊断 plugin，在 C reader 边界记录每次调用。
目标执行期间还编译了这个计数回调：

```lua
return function(...) _._ = _._ + 1; end
```

真正开始读取 `modmain.lua` 时，每次外层 reader 都会进入一个嵌套 `load(reader)`：

```
raw:
  内层 reader #1 -> nil；内层 load 成功返回空函数
  外层 reader #1 -> 8 字节，head = 47 4c 4f 42 ("GLOB")
  内层 reader #1 -> nil；内层 load 成功返回空函数
  外层 reader #2 -> 仍为 8 字节且前缀不变，head = 47 4c 4f 42
  ...一直重复

gate:
  内层 reader #1 -> nil；#2 -> nil；内层 load 成功返回空函数
  外层 reader #1 -> head = 47 4c 4f 42 ("GLOB")
  内层 reader #1 -> nil；#2 -> nil；内层 load 成功返回空函数
  外层 reader #2 -> head = 65 74 6d 65 ("etme")
  外层 reader #3 -> head = 62 6c 65 28 ("ble(")
  ...继续向后读取源码
```

这不是语法错误信息或 bytecode 的差异，而是壳把 reader 的调用副作用用于后续
读取状态。反复返回首块使 parser 持续积累输入，最终报 `LUA_ERRMEM`。

### 5.5 单变量确认

测试时间：2026-11-14；Linux 专用服 build 762172；相同 VM、相同原始目标 mod；
诊断插件和隔离存档位于 `/tmp/dst-mask-diagnosis/`。

| 变体 | 变化 | 实际结果 |
|---|---|---|
| raw | 原 reader 直接交给 VM，仅旁路记录输入 | 外层持续重复首个 8 字节；旧无 gate 运行报 OOM |
| **VM 宏（最终）** | `LJ_DS_PUC51_LOAD_EOF_RETRY`，无 gate | `World generated`，21 秒 `Sim paused`（本日复跑） |
| gate（历史） | 旧 peek + replay | `World generated`，22 秒 `Sim paused` |
| eof | 保留 gate，仅记忆 peek 遇到的 EOF，禁止随后再次调用原 reader | 同样重复首块；27 秒 OOM |
| inside | 相同 peek + replay 延迟到 VM 首次 reader 回调内执行；所有首调均在 protected parser 内；无额外 binary 拒绝 | `World generated`，24 秒 `Sim paused` |

最终方案删除了 gate 的 peek/replay：VM 宏直接完成第二次 reader 调用，raw 的 1 次变为 2 次，目标进入 `Sim paused`。`eof`/`inside` 保留为反证。

`eof` 变体中，外层同一 load 的 reader 被调用了 **17,681,764 次**，最终返回
`status=4`（`LUA_ERRMEM`）。仅改变“EOF 后是否再调用一次”就能恢复失败；
而把首调移回 parser 内仍成功，排除了此前的首调时机 / C 栈归因。

诊断产物：`gate.log`、`inside.log`、`eof.log`、`raw-first-divergence.log`、
`build_probe.py`、`run_case.py`。这些是临时取证文件，未替换仓库发布产物。

## 6. 其他被否定的假设（A/B 记录）

| 假设 | 结果 |
|---|---|
| `GLOBAL.TheSim:LoadPrefabs` 是 Lua chunk loader | 否。探针：源码 prefab 文件未执行、`Prefabs.*` 未注册；mod prefab 文件走 `LoadPrefabFile` → `loadfile`，`TheSim:LoadPrefabs` 只处理已注册 prefab 对象 |
| 旧 `newproxy(function)` C proxy 是关键 | 恢复 VM 补丁 + manager 的 newproxy 代理后仍 `not enough memory` |
| per-env `env.string` 拷贝 + dump wrapper 是关键 | 恢复后仍 `not enough memory` |
| 只靠 VM `bcread_header` 全拒绝即可 | 会连 LuaJIT 自己的 `\x1bLJ` 一起拒绝；而且 no-gate 的 reader 语义问题依旧 |
| injector C gate 可直接删 | 最终已删除；前提是 VM 的 `LJ_DS_PUC51_LOAD_EOF_RETRY` 补齐第二次 reader 调用（直连 nil reader 为 2/2，目标进入 `Sim paused`），bytecode 策略迁移到编译期宏 `LJ_DS_REJECT_BINARY_CHUNKS`，并按 state 提供 `lua_ds_allow_lj_bytecode` 外侧开关（CLI 默认开启放行） |
| gate 有效是因为 reader 首调在 parser 外 / C 栈深度改变 | 否；inside 变体将首调移回 parser 内仍成功，eof 变体保留 parser 外首调却失败 |
| `string.dump` 只对 mod 归因 PUC | 改为无条件 PUC 后，配合 C gate 目标正常；无 bridge 的独立 VM 保持原生 LJ |

## 7. 最终代码落点

- `luajit/src/lj_lex.c`：`lj_lex_setup` 的 `LJ_DS_PUC51_LOAD_EOF_RETRY` 第二次 reader 调用；`LJ_DS_REJECT_BINARY_CHUNKS` 编译期拒绝（受 `G(L)->dsallowljbc` 控制）；`LJ_DS_PUC51_DUMP` 的 `\x1bLua` 拒绝；
- `luajit/src/lj_arch.h`：`LJ_DS_PUC51_LOAD_EOF_RETRY`、`LJ_DS_REJECT_BINARY_CHUNKS`（默认均为 `LJ_DS`）；`luajit/src/lj_obj.h` 的 `global_State.dsallowljbc`；`luajit/src/lj_api.c` 的 `lua_ds_allow_lj_bytecode`；`luajit/src/luajit.c` 在 CLI state 上默认调用它；
- `luajit/src/lj_bcread.c`：原始 `bcread_header`；
- `luajit/src/lib_string.c`：bridge 存在时无条件 PUC 5.1；
- `luajit/src/lib_jit.c`：VM 不提供 `jit.new_c_function`/`jit.patch_cfunction`/`jit._private_registry`，也没有 Lua 侧私有 root 入口；
- `src/DontStarveInjector/plugins/plugin_core_vm/game/GameLuaContextJit.cpp`：
  `lua_loadx` **仅 dump**（`LuaModDumpShouldDump` / `LuaModDumpReader`），且只有 `LuaModDumpEnabled()` 时安装；gate 的 peek/replay 已删除；无运行时开关；
- `Mod/scripts/luajit_mod_blacklist.lua`：
  `safe_package`/真实 package 双面、stock require 保持不变、jit/package cache+scrub；
- `luajit/src/lib_base.c`、`lib_debug.c`、`lj_debug.c`、`lj_arch.h`：
  `LJ_DS_NEW_PROXY_PATCH` 已移除。

## 8. 复现

### 8.1 构建/部署

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target luajit-5.1 plugin_core_vm luajit --parallel "$(nproc)"
cmake --install builds/ninja-multi-vcpkg --config RelWithDebInfo --prefix Mod
```

独立 CLI 在 `builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/luajit`；`cmake --install` 同步
`Mod/deps/liblua51DS.so` 与 `Mod/plugins/plugin_core_vm/plugin_core_vm.so`。

### 8.2 目标 mod

```bash
# cluster overrides: workshop-3014076942 + workshop-3444078585 (LuaVmType=jit)
timeout -k 5 90 /tmp/run_xuaner_jit_nodump.sh
```

成功判据：服务端出现 `World generated` 后 `Sim paused`，且无 `MOD ERROR` / `PL nil` / `not enough memory`。

### 8.3 reader 对照

- PUC：`lua_vm_type=game`，probe mod 打印 reader 的 `debug.getinfo`；
- LuaJIT raw：用 `-DLJ_DS_PUC51_LOAD_EOF_RETRY=0` 构建 VM；
- VM 宏：当前默认构建（`LJ_DS_PUC51_LOAD_EOF_RETRY=1`）。

直连 nil reader 的实测（第 3.4 节）：PUC **2** 次、LuaJIT raw **1** 次、VM 宏 **2** 次；
三者 `load` 都返回空函数。Lua-visible 栈仍见第 3.3 节。

### 8.4 bytecode 策略

- CLI：默认调用 `lua_ds_allow_lj_bytecode(L, 1)`（原生字节码模式），`loadstring(string.dump(fn))` 成功；同一 `liblua51DS.so` 不调用该 API 时加载 `\x1bLJ` 报 stock 错误、`string.dump` 转 PUC（缺桥则报 `bridge unavailable`）；
- CLI：`loadstring("\27Lua")` → `binary string: Disallowed functionality in precompiled chunk`（`LJ_DS_PUC51_DUMP`）；
- 游戏/未调用开关的 state：`[bin] lj false <name>: Disallowed functionality in precompiled chunk`（VM 按 PUC 规则填名字，见下）、`[bin] puc false ...`、`[bin] gamedump 27 Lu false ...`（编译期宏默认 1）；
- `dump_lua_mods` 仍由 dump-only `lua_loadx` 包装落盘。

## 9. 后续修复方向与边界

- **已实现的兼容行为**：`LJ_DS_PUC51_LOAD_EOF_RETRY` 在源码格式探测首次 EOF 后让 lexer 再调一次 reader，保留 protected parser 的错误处理边界；C gate 的 peek/replay 已删除。
- **不要改成永久 EOF 标记**：`eof` 对照已证明禁止第二次调用会重新引入目标 OOM。
- **拒绝文案的 chunk 名由 VM 负责**：`lj_lex_setup` 的 `ds_reject_binary_chunk` 复刻 PUC 5.1 `luaU_undump` 的命名规则（去掉 `@`/`=`；名字即字节码时用 `binary string`；无名为 `?`），`\x1bLua` 与 `\x1bLJ` 一致。模组脚本不再 patch `loadstring`：那层只拦 `\x1bLua`、只对齐文案，且会在 `debug.getregistry()` 留下可枚举的 C 函数台账。
- **字节码拒绝是编译期宏 + 按 state 的外侧开关**：`LJ_DS_REJECT_BINARY_CHUNKS`（默认 `LJ_DS`）在 `lj_lex_setup` 拒绝所有 `\x1b`；`lua_ds_allow_lj_bytecode(L, allow)` 是唯一的外侧出口，含义是“该 state 走原生 LuaJIT 字节码语义”——同时放行 `\x1bLJ` 加载并让 `string.dump` 不做 PUC 转换（CLI 已默认开启；游戏态与 mod 视角保持掩码）。不要把开关暴露给 Lua/mod：那样等于把这条策略交回给被检测方。
- **tail 指纹属于独立问题**：`RunInEnvironment` 与 `tail` pseudo-frame 的差异仍存在，但不是本轮成败的解释。
- **普通非空 reader 的块切分**：reader 能观测回调次数和副作用；parser 内部把同一块分成 head/pending，本身不会增加对原 Lua reader 的调用。不能把这件事与 EOF 后第二次调用混为一谈。
- **`string.dump` 无条件 PUC**：巨大函数的 source 重编译仍可能有内存成本；应与这里的无限重复输入问题分别评估。
