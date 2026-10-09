# 更新日志

## 未发布

- 注入可诊断化：壳（Winmm / InjectorStub）每次启动把解析来源/模块路径/加载与导出结果、壳的最终结果写到 `<游戏>/data/unsafedata/ds_luajit_boot.log`（stderr 保留）；`install_linux.sh` 结束时自检壳/真实模块/marker/`ldd` 并打印 `[CHECK]` 结论，新增 `install_linux.sh selftest`（一次性进程实测 stub→真实模块链路），且脚本在 `sh`（dash）下会 `exec bash` 重跑，不再因语法错误空跑。

- `plugin.manager`：新增跨进程插件树锁（`plugins/.ds_plugin_update.lock`，`LockFileEx`/`flock`），启动更新检查与安装都持锁串行——客户端 + Master/Caves 同一波启动只做一次检查、不会并发写插件树（锁不支持时回退旧的无锁行为并提示，锁文件记录持有者 pid/host 便于诊断）。启动检查并入 `plugin_manager`（独立 `plugin.autoupdate` 模块及其三个专属服务删除），检查/安装期间不再持 manager 锁，`status_json` 全程可响应；等待中的安装最多等 30 秒后在锁内重建计划，不重复下载别的进程刚装好的资产。

- 插件安装布局收紧为“仅包布局”：只接受 `plugins/<stem>/<stem>.<ext>`（清单槽位带 `package=<stem>`，`module` 必须为 `<package><ext>`，`files[]` 相对包根，`modinfo.lua`、`scripts/*.lua` 等嵌套成员现在会真正安装）；扁平模块不再作为候选（loader 忽略并告警，清单校验与解压同步收紧）；某成员被占用时整包一起进 `update_pending/<package>/`，避免“新 Lua 面 + 旧模块”。

- 清单平台槽位与包内 meta 新增 `build_config` 构建戳：不兼容类别（MSVC 的 Debug 与 Release 家族）的资产在下载前被拒绝。

- 工具/测试：新增跨平台 pre-push ctest 门禁（`.githooks/pre-push` + `tools/pre_push.py`，可用 `git push --no-verify` / `PRE_PUSH_SKIP` 跳过）；游戏类 ctest 共享 `RESOURCE_LOCK(dst_game_server)`，`ctest -j` 并行时不再因固定端口（10999/8766/27016）冲突；Injector 只按当前布局（mod 根）定位真实模块，移除 `bin64`/`lib64` 旧路径回退与 deps 搜索兜底。

## 3.2.0

- 修复加密模组（风雪/daxsg 家族，如《神话书说》workshop-1991746508）导致的服务器世界生成卡死/崩溃：其加载器探测 `require("jit")` 后会在 LuaJIT 下走坏路径（字节码 VM 报 `K nil` 或死循环），污染 worldgen 状态。新增 `Mod/modworldgenmain.lua`：只在真正的世界生成状态（`WORLDGEN_MAIN`，`scripts/worldgen_main.lua` 设置；客户端前端/普通加载路径无此标记）里 `rawset` 掉 `_G.jit` 并清 `package.loaded.jit`（`jit.runtime` 的 HideGlobalJIT 只覆盖 modmain 阶段，worldgen 不跑 modmain），受 `HideGlobalJIT` 选项控制（默认开）。

- 修复 VBPool 与显式 ANGLE 后端（如 `AngleBackend=vulkan`）同时开启时的画面错乱：GL 入口点改为从引擎自身的 `libGLESv2.dll` IAT 槽解析（即 `render.angle` 重绑后的活动渲染器），并声明 soft dep 让 `render.angle` 先加载（priority 36）；槽位不可用时 fail closed，不再回落到错误的模块。

- `render.shadow` 剪影批的 GL 入口点同样改走引擎 IAT 槽确定活动渲染器模块（新增共享头 `util/engine_gles.hpp`）。

- 修复 `render.shadow` 剪影阴影完全失效（游戏 2026-10 更新后）：`LoadShader` 从硬编码 RVA(0x3e9f00) 改为签名定位（新 RVA 0x12170，进程内只扫描一次）；`shaders/sil.ksh` 的两段 GLSL 源码补上引擎要求的尾部 NUL（此前编译报 `0:18: '?' : syntax error`）；shader 资产纳入插件包（CMake install + 调试部署脚本）。

- 引擎 5.1 对齐（以 macOS 客户端为准，配套 parity 审计与回归测试）：
  - 新增 Klei 兼容层（进程级执行错误槽、`luaD_pcall` 的 `LUA_YIELD` 覆盖、`lua_settimeslice` 兼容 stub），`db_errorfb` traceback 与引擎同形（`LUA ERROR stacktraceback:` 头、8 空格帧缩进、`(line,1)` 行号、chunk 名只剥前导 `@`）。
  - VM 切换时按签名定位引擎自身的执行错误槽（0x1000 消息块 + 存块指针的标志）并发布进换入的 VM，引擎错误显示与 `luaD_pcall` 读同一块存储；模式/解码/导出任一失败即不发布（fail closed）。
  - `debug.getsize` 改为接管实现（保留“取 debug 表并留在栈上”的可观察契约），替换原先的单向 ret patch，修掉换 VM 后第二次引导的 `lua_settable(L, 0)` → "attempt to index a string value"。
  - C/FF 被调者尾调用（`LUA_COMPAT_TAILCALL_CFRAME`）与 traceback 命名/`(tail call)` 行对齐，覆盖结果转发、调用者帧保留、KBASE 恢复与 dump 版本边界；新增 `tests/lua_vm_parity` 用例与 `luajit_parity_*` 守卫（含有意保留的 xpcall 调用者帧差异）。

- 修复 arena GC 通配 `L->base` 崩溃的根因：x64 barrierback 宏把保存寄存器放在 Win64 shadow space，被 `lj_gc_barrierback_arena` prologue 覆盖（luajit 子模块 `vm_x64.dasc`，56d05799）；同批修掉 3 个把 64 位地址按 32 位解析的 GC 白盒测试崩溃，崩溃分析文档移入 luajit 子模块。

- 引擎 `lua_load` 钩子现在也 dump lauxlib 路径（`luaL_loadbuffer` / `luaL_loadfile`）加载的 chunk 到 `dumped_lua_mods/`（此前只处理不带 reader 的调用）；LuaJIT 侧新增 `LJ_DS_LOADLOG` 分块源码 dump。

- ANGLE：显式 Vulkan 后端改用 `eglGetPlatformDisplay` + `EGL_FEATURE_OVERRIDES_DISABLED_ANGLE` 关闭 `enablePrecisionQualifiers`，避免 DST 的 mediump/lowp shader 被驱动降精度（实测 RelaxedPrecision 41→0，D3D11 输出不变；API 缺失时告警而非静默回退）。

- 签名与注入器修复：更新流程对失败项清零偏移并重新推断（再回退到该条目的存储模式、按模块地址+大小扫描），修掉陈旧 DB 让 `luaL_loadbuffer`/`luaL_loadstring` 低 0x20 导致所有 mod 报 "unexpected symbol near 'char(N)'" 的问题，重复 RVA 守卫只看本轮结果；`signature_updater` 拆成 `create` / `update_signatures` 两个构建目标（此前 update 目标实际多走 create 路径）；启动钩子在 frida-gum 17.17 上改回 `replace`（`replace_fast` 不再有 on_enter trampoline，返回 `GUM_REPLACE_WRONG_SIGNATURE` 导致钩子装不上）。

- 修复 `alloc_rpc_channel` 在 `namespace_or_code` 为 nil 时报错。

- Steam 接入迁入宿主 `sdk/steam/`，客户端在配置解析前采集 AccountID，服务端创意工坊钩子不再依赖 VM 启用状态。

- 创意工坊目录缓存和查询接口统一由宿主管理，VM 文件读取复用该缓存；移除旧 Steam 工具层和测试库目标。

- 新增风雪（frostxx/Fengxun）保护壳 mod 的解密/加密脚本与处置流程（`.opencode/skills/decrypt-encrypted-mods/`：离线 CLI 支持 `--selftest` 与 round-trip 验证，配套保护壳抽取与反混淆步骤，产物写独立目录、不动 mod 本体）。

- `BufferNamePool` 单测期望改用类内上限常量（128/桶、1024、64MiB），跟上现容量设置。

- 测试基础设施：游戏测试 harness（按 `GAME_DIR`/`DST_GAME_DIR` 发现游戏、注入 mod 并保证清理、离线 cluster 写入、专用服务器启动、ctest skip 映射）+ 首个游戏夹具（modmain 索引 nil → 断言引擎 MOD ERROR 与启动 abort）+ LuaJIT traceback parity 守卫。

## 3.0.0

- V3 架构更新——插件包化：插件统一为 DST mini-mod 包布局，loader 支持包子目录发现与 `package_load`（带 DST modinfo 沙箱）；`save.fork` 等双面插件全部迁移。

- 外部插件包：枚举已启用的 DST mod，经 modinfo 信任门加载第三方 luajit 插件包（路径 jail + 包内模块清单），启用前弹确认。

- 插件配置项烘焙进父 modinfo：`configuration_options`、`host_gate`（`all_of`+`any_of` 全部满足）、AddSection 分隔，配置读取绑定到属主 modname。

- 安装布局：shell 与核心 Injector 分离（shell 进游戏目录，真实 Injector 放 mod `bin64`），mod/deps 搜索路径加载；全平台 vcpkg 动态链接，共享运行时随 `mod/deps` 分发。

- 函数定位与签名栈：vendored Nucleus + frida-gum 17.17.0 共享 shell；Windows `.pdata` / Linux `.eh_frame_hdr` 函数起点种子（剥离的 DST 没有 lua 动态符号）；soft-match（微窗口 unique-const、短函数体、匹配策略）；图搜索反向种子 + 传递导出恢复，并按首次调用去重避免 `luaL_loadbuffer`/`luaL_loadstring` 并列；740477 客户端/服务端签名 102/102。

- ANGLE 共享库化：`libGLESv2`/`libEGL` 以 DLL 随包分发，运行时 `LoadLibrary` 并把引擎 IAT 重绑到导出（不再静态链接 ANGLE）。

- `core.vm` 拆分：GameLua 上下文拆成 `game/` 多编译单元，公开类型在原处重导出；新增 Frida Gum 新 API 拦截封装。

- `render.shadow` 插件上线（双面包：EarlyNative 注册 + AfterModMain 读配置并调用导出 API）：太阳驱动的 `GenerateVB` 钩子 + Lua 状态喂入、SunModel 数学与单测、360° 周期 / 半球切换 / 整数 Lua ABI；配置项含 `ShadowSunDrive`、`ShadowSilhouetteBatch`（与太阳椭圆互斥，以剪影为准）、`ShadowLengthBoost`、`ShadowHemisphere`。

- 修复 LuaJIT `debug.getlocal` 在尾调用层级上的崩溃。

- 调试：存在 `Debug.config` 时自动分配控制台。

- 工具与 CI：新增 debug+ASAN 套件与游戏冒烟运行器；发布工作流停用 macOS 构建。

## 2.9.1

- fork_save 补齐 Windows：win32 后端、启动即可用、子进程网络 no-op（快照管理）、子进程状态轮询、超时自动结束进程、退出服务器时走 master，并补 Lua 测试。

- LuaJIT Gen GC 继续打磨：fullgc 的 O(live) 校验开销门控（ASAN 构建跳过）、ClearMarks 分块与 arena-slice yield、T3b 头精简、P4 标记量子排空（单步预算 128 对象/4KB）、pause assert step(1) 修复、gengc 测试与 LuaJIT 变体注册表/构建桥。

- 新增 `HideGlobalJIT` 选项：全局 `jit` 只对声明 `luajit_compatible` 的 mod 注入，其余 mod 环境隐藏；GameLua 清理 IO 库引用与未使用的 JIT 选项。

- ANGLE 从主 vcpkg 清单解耦（`tools/angle` + 预构建 `3rd/angle`），缓存目录自动创建，CI 缓存重置不再重建 ANGLE。

- 修复 `initialize_all_so` 静态初始化顺序导致的 ASAN SEGV（构造函数早于库名 `std::string` 构造，loadlib 收到 nullptr）。

- 修复 TheWorld 周期任务潜在 nil 引用。

- 修复 Windows 构建/发布与游戏 VM 相关错误，更新客户端/服务端签名与 CI。

## 2.8.0

- LuaJIT Gen GC 支持（分代 GC、帧 GC，禁用 Full GC）
- 游戏存档 Fork Save 支持
- 新增顶点缓冲池（VB Pool）
- 缓冲池统计追踪（EMA 命中率）
- 更新 Linux 签名
- 修复 Linux 递归崩溃
- 修复 lua-debug 模式
- 重命名本地服务器配置目录
- 修复 profiler_push 签名

## 2.7.3

- SlowTaICall 检查器迁移到 C 端

## 2.7.2

- 修复网络模拟器（netsim）bug

## 2.7.1

- 修复 GameLuaModule 相关 bug

## 2.7.0

- 客户端渲染顶点缓存
- 服务器延迟补偿功能
- 网络丢包模拟器
- 压力测试机器人框架
- mod 配置选项可视化禁用
- modinfo 注入平台环境
- 修复网络优化 bug
- 修复读取错误配置文件
