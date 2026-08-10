# Core.vm 模块拆分设计（包内整理 + 纯 VM 外置库）

**Date:** 2026-08-10  
**Status:** Draft for user review  
**Plugin id:** `core.vm`（不变）  
**MODULE:** `plugin_core_vm`（不变）

Related:

- Optional core.vm ownership: `docs/superpowers/specs/2026-08-04-core-vm-plugin-design.md`
- Config key ownership: `docs/superpowers/specs/2026-08-05-config-ownership-boundaries-design.md`
- Plugin system inventory: `docs/plugin-system.md`
- Current sources: `src/DontStarveInjector/plugins/plugin_core_vm/**`

---

## 0. 问题

`plugin_core_vm` 已是可选 Host 插件，但包内仍是「大杂烩」：

| 现状 | 问题 |
|---|---|
| `GameLua.cpp` 巨型单文件 | game / jit / gen / lua51 上下文、Replace、switch 缠在一起 |
| signature 已是 STATIC，语义边界未在源码树体现为「模块」 | 与 Replace 头文件交叉 include |
| io / Steam / GameInjector / event 同 DLL 合理，但目录职责不清 | 后续再拆成本高 |
| 用户说的「lua51 \| jit \| gen 覆盖」易被误解成 Host 插件 | 实际只需 **纯 VM 动态库** 外置 |

目标：**拆清 `core.vm` 内部模块**；外置三件是 **零业务逻辑的 Lua 虚拟机库**；逻辑全部留在 `core.vm`。

---

## 1. 决策（本设计锁定）

| # | 选择 |
|---|---|
| M1 | 逻辑 id **仍为 `core.vm`**；不引入 `core.vm.game` / `core.vm.jit` 等新 Host 插件 id |
| M2 | **全部行为**在 `plugin_core_vm` 内：signature、选 type、Load 纯 VM 库、Replace、GameInjector、gameio/Steam、event、schema |
| M3 | **外置覆盖 = 纯 VM 动态库**：`lua51DS`（jit）、`lua51DS_gengc`（gen）、`lua51Original`（lua51）；**无** `ds_plugin_module_init`、无 vtable、无业务符号 |
| M4 | **`game` 模式**无外置库，使用游戏主模块内嵌 Lua（`GameLuaContextGame`） |
| M5 | **特征码**为包内一等模块（继续 STATIC `ds_signature`，可链 tools）；与 VM 同 DLL 部署 |
| M6 | **`game/` 内按 context 拆编译单元**（同 DLL）：Game / Jit(+Gen 共享实现) / Lua51 / Replace / Switch |
| M7 | **io + Steam** 本轮同 DLL，物理归 `io/`；**GameInjector** 物理归 `injector/`，**独立 DLL 后拆** |
| M8 | 所选纯 VM 库 **Load 失败** → **降级 `game` context**，仍尽量跑 signature + replace 到内嵌 Lua；**不是**整段 VM 路径 soft-skip（与「无库=无 inject」区分：缺的是库不是底座） |
| M9 | 无第二 Frida Gum；无 shim 双份；迁完删除旧巨型堆叠路径 |
| M10 | YAGNI：不做 overlay Host 插件、不做热切换多 VM 并存、不做 signature/io/GameInjector 本轮独立插件 |

**否决的路径（讨论中明确丢掉）：**

- 方案 A 原稿：`core.vm.jit` / `.gen` / `.lua51` 作为 Host 插件 + overlay vtable 注册  
- 方案 B：每个覆盖自带完整 `ReplaceLuaModule`  
- 外置 DLL 内塞 DS 业务逻辑  

---

## 2. 产物边界

| 产物 | 类型 | 职责 |
|---|---|---|
| `plugin_core_vm.dll` | Host 插件 MODULE，id `core.vm` | **全部** Injector 侧 VM 行为 |
| `lua51DS` | 纯共享库（`Mod/deps` / staging） | LuaJIT 运行时 |
| `lua51DS_gengc` | 纯共享库 | GenGC LuaJIT 运行时 |
| `lua51Original` | 纯共享库 | 原版 Lua 5.1 运行时 |
| 游戏主模块 | 进程已加载 | `game` 模式的 Lua 导出 |

L0 仍只通过 `CoreVmBootstrap` 解析底座 export（如 `ds_core_vm_run_signature_and_replace`、`ds_core_vm_get_game_lua_context`）。**不** Load 三个纯 VM 库——由 `core.vm` 内部 `LoadLuaModule` 按 type 装载。

---

## 3. 包内模块图

```
plugin_core_vm/                    # id: core.vm
├── plugin_core_vm.cpp             # entry: schema, services, IPlugin, bootstrap export
├── VmOptionKeys.hpp
├── VmConfig.hpp                   # get_lua_vm_type / EnabledGenGC 优先 → jit_gen
├── VmServices.hpp
│
├── signature/                     # 特征码模块（现 signature_load/，可保留旧目录名作别名）
│   └── → STATIC target ds_signature
│
├── game/                          # VM 底座：选库 + Replace + context + switch
│   ├── GameLuaType.hpp
│   ├── LuajitVariantNames.hpp     # type → 纯库 base name（仅名字表）
│   ├── LuaApi.hpp
│   ├── GameLuaContext.hpp/.cpp    # 基类 + 共享 Load/Replace 骨架
│   ├── GameLuaContextGame.cpp
│   ├── GameLuaContextJit.cpp      # jit 与 jit_gen 共享实现，双实例/双 soname
│   ├── GameLuaContextLua51.cpp
│   ├── ReplaceLuaModule.cpp       # signature 应用 + 选 type + 缺库降级 game
│   ├── VmSwitch.cpp               # RequestVmType / DS_LUAJIT_set/get_vm_type / reinit
│   └── GameLua.def                # MSVC reexport（若仍需要）
│
├── io/
│   ├── gameio.*
│   └── GameSteam.*
│
├── injector/                      # 后拆候选；本轮只归位
│   ├── GameLuaModule.cpp
│   ├── GameInjectorApply.*
│   └── GameLuaInjectFramework.lua (+ lua2c 产物)
│
├── event/
│   ├── LuaEvent.hpp
│   └── LuaEventBus.cpp
│
└── optional/
    ├── lua_debugger_helper.*
    └── lua_fake.cpp
```

### 3.1 模块职责一句话

| 模块 | 职责 |
|---|---|
| **signature** | 训练/更新/加载 `Signatures` 与 export 列表；不执行 Replace |
| **game** | 读 VM 配置 → 选 type → Load 纯 VM 库或降级 game → 应用 signature 做 API replace → VM 热切换协调 |
| **io** | workshop 路径、`lj_*` 安装、Steam UGC hook；由 JIT 路径在 Replace 后调用 |
| **injector** | `luaopen_GameInjector`、核心 `DS_LUAJIT_*` 绑定、Host 注册 export 的 trampoline apply |
| **event** | `new_state` / `close_state` / `call_lua_gc` 监听扇出 |
| **entry** | 插件 ABI、schema、service 发布、bootstrap 编排（Steam hook → signature → Replace） |
| **optional** | 调试器 / fake API，编译开关 |

### 3.2 允许的依赖方向

```
entry → signature, game, io (Steam hook), event (register service)
game  → signature (只读 Signatures/exports), io (init_luajit_io), event (notify)
injector → game (GetGameLuaContext/api), io (workshop/decrypt decls)
io → (无 game 头循环依赖；workshop 缓存由 Steam hook 写入)
signature → 不依赖 game/injector
纯 VM 三库 → 不依赖任何 DS 代码
```

禁止：

- `GameLua` 公共头过度 include signature 实现细节（Replace 参数用窄类型/前向声明）
- 纯 VM 库反向导入 Injector / core.vm 符号
- 在 `Mod/deps` 的 lua51* 内加入业务 hook

---

## 4. 运行时选择与降级

与现逻辑对齐，并写死缺库行为：

```
type = get_lua_vm_type(ResolvedConfig)
  // EnabledGenGC == true → GameLuaType::jit_gen（覆盖 LuaVmType）
  // 否则 LuaVmType 字符串 → jit | game | _51 | …

if type == game:
  ctx = GameLuaContextGame
else:
  name = GetLuajitVariantBaseName(type)
    // jit     → lua51DS
    // jit_gen → lua51DS_gengc
    // _51     → lua51Original
  if !LoadLuaModule(name):   // Mod/deps 优先，现有 loadlib 策略
    spdlog::warn("VM library '{}' missing — degrade to game context", name)
    ctx = GameLuaContextGame
  else:
    ctx = context for type

ReplaceLuaModule(mainPath, signatures, exports) using ctx
```

| 场景 | 行为 |
|---|---|
| 无 `plugin_core_vm` | L0 soft-skip VM 路径（既有 optional 语义；修正 bootstrap 硬 require 漂移见实现计划） |
| 有底座、无所选纯 VM 库 | **降级 game**，signature+replace 仍走内嵌 Lua |
| `DisableJITWhenServer` / force disable | 不跑 signature+replace（既有） |
| `EnabledGenGC` | 强制 `jit_gen` + `lua51DS_gengc` |

`game` 与「降级到 game」路径共用 `GameLuaContextGame`，不另开第四套降级实现。

---

## 5. 导出与对等依赖（不变原则）

底座继续提供（名称可保持）：

| 符号 / 服务 | 用途 |
|---|---|
| `ds_core_vm_run_signature_and_replace` | L0 bootstrap |
| `ds_core_vm_get_game_lua_context` | lagcomp / profiler 等 |
| `ds_register_lua_event_listener` | profiler 等 soft |
| `DS_LUAJIT_set_vm_type` / `get_vm_type_name` | Lua / modmain SwitchVm |
| gameio 相关 `DS_LUAJIT_get_workshop_dir` 等 | GameInjector 绑定 |

纯 VM 库 **不** 出现在 Host 插件表、不进 `PluginLocalInventory` 的 `plugin_*` 映射。

---

## 6. 构建与部署

- CMake：`plugin_core_vm` 仍一个 `ds_add_dynamic_plugin`；源列表按 `game/` `io/` `injector/` `event/` `optional/` 分组。
- `ds_signature` 继续 STATIC，链入 `plugin_core_vm`（及 tools）。
- `stage_core_vm_deps.cmake` / `LuajitVariants.cmake`：继续 stage **纯** `lua51*`；注释写明「非插件、无业务逻辑」。
- 部署：`plugins/plugin_core_vm/...` + `Mod/deps/lua51DS*`；用户可只缺某一变体库而不拆整包。

jit / gen **共享** `GameLuaContextJit.cpp` 一份实现（双静态实例或等价），禁止两份 class 体拷贝。

---

## 7. 迁移切片

| Slice | 内容 | 验收 |
|---|---|---|
| **S0** | 目录搬家 + CMake 源列表归组；**零行为变化** | RelWithDebInfo 链过；现有 ctest 绿 |
| **S1** | 拆 `GameLua.cpp` → `game/*` 多 TU；对外符号/export 表不变 | dumpbin/导出一致；L-G present PASS |
| **S2** | 收紧 signature↔game include；实现/确认 **缺库降级 game** | 故意移走 `lua51DS` 仍 inject + game 路径日志 |
| **S3** | `injector/` `event/` `optional/` 归位；更新 `plugin-system.md` 模块图 | 文档与树一致；无回归 |
| **非本轮** | GameInjector / io / signature 独立 Host 插件 | — |

每切片可独立 commit；禁止半迁移双路径残留。

---

## 8. 非目标

- Host 级 `core.vm.jit` / `.gen` / `.lua51` 插件  
- Overlay vtable / `register_overlay` ABI  
- 纯 VM 库内业务逻辑  
- 本轮拆 GameInjector / gameio / signature 为独立 DLL  
- 改变 modinfo 键名（`LuaVmType` / `EnabledGenGC` / `DisableJITWhenServer`）  
- 重新设计 GC / signature 算法  

---

## 9. 成功标准

1. 源码树可按 §3 指出 signature / game / io / injector / event，无「上帝 `GameLua.cpp`」。  
2. 外置仅三纯 VM 库 + 既有 signatures JSON；无额外覆盖插件 DLL。  
3. 缺所选 VM 库 → 日志明确 + **game 降级**；有库时行为与拆分前一致（L-G present）。  
4. L0 与 peer 仍只依赖底座 C export / services；无新反向依赖。  
5. `ds_signature` 仍可被 tools 复用。  

---

## 10. 与旧 spec 关系

- **不** 推翻 `2026-08-04-core-vm-plugin-design.md` 的 optional / Signature 随 VM / 功能插件独立加载。  
- **补充** 包内模块边界与「覆盖 = 纯 VM 库」产品语言。  
- 实现阶段若修正 `CoreVmBootstrap`「硬 require 底座」与文档 optional 漂移，以 2026-08-04 optional 语义为准（本设计 M8 只定义 **库** 缺失降级，不改变 **底座 DLL** 缺失策略）。

---

## 11. 开放实现细节（计划阶段钉死，不阻塞本设计）

- `signature_load/` 是否物理 rename 为 `signature/`（行为无关，S0 可选）。  
- `ReplaceLuaModule` 参数结构是否抽 `SignaturesView` 窄类型。  
- `GameLua.def` 是否随拆分缩减 reexport 集。  
- 缺库降级时是否仍执行完整 signature update（倾向：是，与 game 路径一致）。
