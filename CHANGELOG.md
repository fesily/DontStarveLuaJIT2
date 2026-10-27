# 更新日志

## 未发布

- 修复**替换 `<名>.pkg` 后对应的 DLL 不更新**（两个独立根因）。一、`ds::packaged::exists_or_materialize` 在规范名文件已存在时直接返回 true、**从不比较孪生**，而壳解析 `Injector.dll`、`DynamicPluginLoader` 的包内候选、`CoreVmBootstrap` 的 `plugin_core_vm` 全走这个入口——只有 `deps/` 的 `materialize_directory` 会按构建戳刷新，于是手工/Steam 换掉的 `.pkg` 必须先删掉同名 `.dll` 才生效。现在入口一律调用 `materialize`（无孪生即无操作，有孪生只做一次 size + PE 戳比较；被别的进程映射时仍是保留旧文件并打日志）。二、`image_stamp` 读 `TimeDateStamp` 时漏了定位：读完 `PE\0\0` 紧接着读 4 字节，实际拿到的是 COFF 文件头的 `Machine|NumberOfSections<<16`（同一布局恒定），**同尺寸重建被判成同一构建**，`.pkg` 换了也不刷新；现改为按 `lfanew + 8` 读取真正的构建时间戳（`SizeOfImage` 偏移不变）。回归测试均为「旧实现必失败」：`packaged_module` 新增 `exists_or_materialize_refreshes_stale_canonical` 与 `pe_time_stamp_detects_same_size_rebuild`（用测试自身的真实 PE、只改时间戳、尺寸不变），`plugin_dynamic_loader` / `injector_bootstrap` 各新增「陈旧规范名 + 已替换孪生」用例。

- 新增**进程级日志级别开关** `log_level`（`InjectorConfig::log_level`，走既有的 `ENV_OR_CMD_OPT_VALUE` 机制）：环境变量 `log_level=info` 或启动参数 `-log_level=info` / `--log_level info` 均可，取值 `trace|debug|info|warn|err|critical|off`（另接受 `warning`/`error` 两个别名）。默认仍是 release=`err`、Debug=`trace`、挂了调试器=`debug`，**显式值优先**；`spdlog::set_level` 对已注册 logger 全部生效，因此 `FunctionRelocation.log` 里的签名扫描明细也会一起放开。`spdlog::level::from_str` 会把无法识别的名字映射成 `off`，所以这里显式校验：未知值记一条 `[error] unknown log_level=...` 并保持默认级别，不会把日志“静默静音”。同时把 `DontStarveInjector_{client,server}.log` 的 sink 从 truncate 改为**追加**——原来 `basic_file_sink(filename, true)` 每次启动都会先清空，用户上一次失败的证据会被下一次（可能成功的）启动擦掉。实测：真实客户端注入（`plugin_client_inject_smoke`）带 `log_level=info` 跑两次，`bin64/DontStarveInjector_client.log` 累积 464 行、183 条 info/次，首两行分别是 `[warning] log level set to 'info' by log_level=info` 与 `[info] Inject start: isClient=true debuggerAttached=0`，两次运行的标记行（16:42 / 16:44）同时保留，证明追加生效。

- 构建目标 `create` 更名为 **`create_signatures`**，与既有的 `update_signatures` 成对命名，避免这个只做全量特征码生成的裸动词目标与目录/自定义命令名混淆。三个平台分支（macOS / Linux / Windows）的 `add_custom_target` 全部改名，命令内容不变（仍是 `signature_updater create` 工具模式，`SIGNATURE_TOOL_MODE=create` 与 CLI 参数 `create` 都不受影响）；仓内没有脚本、CI 或 pre-push 钩子以 `--target create` 调用它。

- **特征码库改为 `format_version` + 按 `<system>-<arch>` 分节**：`Mod/signatures_{client,server}.json` 顶层现在是 `{"format_version": 2, "platforms": {"windows-x64": {"version": …, "funcs": {…}}, "linux-x64": {…}}}`，同一文件可并存 Windows/Linux/macOS（含不同架构）的特征码且互不覆盖——写入只替换本机那一节，其余平台分节原样保留。读取时校验 `format_version`、`platforms` 结构与本机分节：格式版本不符（含没有该字段的旧扁平 `{version, funcs}`）、缺本机分节、节内缺 `version`/`funcs`、`funcs` 为空、条目缺 `offset`/`pattern`、`offset` 为 0、非法 JSON 一律判为不可用，`update` 模式下校验失败不再报错退出而是**从头重新生成**（只有库文件完全不存在时 `update` 才报错）。写入统一走 `SignatureJson`（`tools/Creater/verify_linux_signatures.cpp` 不再自拼 JSON），`tests/signatures/run.py` 新增"旧 `format_version` 重刷"与"缺本机分节重刷"两条闸门用例，并要求重写时保留 `linux-x64` 分节；新单测 `signature_json_format` 覆盖读取校验、跨平台合并与幂等写回；`tests/performance/analyze.py`、`tools/Signature.py` 同步按 `<system>-<arch>` 选节。

- 修复**重新生成特征码时进度窗消失、进程直接退出且没有 dump** 的静默失败：此前生成协程里抛出的既有 `update_signatures_exception` 走 `showError` → `MessageBoxA(NULL, …, 0)`（无 owner、非 TOPMOST，藏在游戏窗口后面）+ `std::exit(1)`，而 `showError` 在 Windows 分支**一条日志都不写**（发行包日志级别是 err，phase 日志全是 info）——用户只能看到"进度条 0% → 窗口消失 → 进程退出"，既没有错误文本也没有崩溃转储；非 `update_signatures_exception` 的异常（`std::bad_alloc` 等：`signature_updater create` 生成单个目标实测峰值工作集 ≈954 MB）则会直接穿过窗口定时器回调 → `std::terminate` → `abort`，同样无日志无 dump。改动：`showError`（注入器与 `plugin_core_vm` 两份）先把消息以 `spdlog::error("fatal: …")` 落盘并 flush，再用 `MB_SETFOREGROUND | MB_TOPMOST | MB_ICONERROR` 弹窗；`update_signatures_from_disasm` 追加 `catch (const std::exception&)` / `catch (...)`，把意外异常转成同一条失败路径而不是终止进程；`ShowProgressWindow` 改用 RAII guard 销毁窗口并复位 `progress_ctx`（异常展开时不再留下僵尸进度窗）；`SignatureJson::update_signatures` 检查流状态，写盘失败记 error（此前目录不可写会"生成成功"但每次启动都重生成）；进度窗在 phase 1–3（`init_module_signature`／20 MB 主 exe 的 nucleus 分析／特征扫描，本机约 11 s）开始前先显示 `Analyze lua51.dll and game module...` / `Analyze game module (nucleus)...` / `Scan function features...`，并用 `UpdateWindow` 立即重绘，避免用户误判卡死。`windows_signatures` + `windows_signatures_cache` 闸门复跑通过（client/server 各 104 条，create→update 208 个 offset 全部不变）。

- 修复**所有 Lua 插件静默失效**（典型症状：改了 `TargetRenderFPS` 仍是 60fps，日志只有 `plugin system disabled: package discovery failed: userdata: 0x…`）。两处根因都在包发现：一、`GameInjector.DS_LUAJIT_list_plugin_packages` 直接返回 `std::vector<std::string>`，sol2 把它压成容器 **userdata**，`Mod/plugins/init.lua` 的 `type(...) ~= "table"` 判定失败后返回空注册表——现在用 `sol::as_table` 返回真正的 1-based 序列表；二、`MODROOT` 是引擎路径而非磁盘路径（工坊项实际从 `steamapps/workshop/content/322330/<id>` 加载，`MODROOT` 仍是 `../mods/workshop-<id>/`），按它列目录得到 0 个包——新增 `ds::plugin::list_installed_plugin_packages`：传入目录存在时照旧列出，否则回落到 `default_plugin_search_dirs()`（native loader 扫描的同一批根，含 `luajit_config.json` 的 `modmain_path` 与工坊发现）。实测（离线客户端 + 工坊项）：`discovered 8 package(s)`、`plugin=fps.render status=Loaded`、`Reset fps by SetNetbookMode 60`；`test_plugin_path` 增加引擎相对路径的回落用例。

- **删除 `ForceDisableTailCall` 选项**并移除它在 VM 侧的支撑：LuaJIT 删掉 `jit.disabletailcall` 绑定与 `LUA_COMPAT_DYNAMIC_DISABLE_TAILCALL` 宏、`global_State::parser_disable_tailcall` 字段及 parser 里的运行时分支（源树 `jit/vmdef.lua` 同步重新生成）。5.1 尾调用帧语义由编译期 `LUA_COMPAT_TAILCALL_CFRAME` 无条件提供，该开关已无意义；`jit.tailcall` 现在只剩加密模组检测，`jit.runtime` 也去掉对应的 `jit_force_off` 守卫。残留配置键（若有）按未知键忽略。

- 加密模组检测**强制开启**并改为直接禁用 JIT：删除 `AutoDetectEncryptedMod` 选项，`jit.tailcall` 改为 `options = { always = true }`（仅 `has_luajit` 门控），检测结果始终发布到 `ctx.encrypted_mod_manager`。`jit.runtime` 的 `kleiloadlua` 钩子现在把命中的加密模组当作黑名单处理——该模组加载出的每个 chunk 都 `jit.off(chunk, true)`（`PROTO_NOJIT`），与 `ModBlackList` 走同一条路径；声明 `luajit_compatible` 的模组从该集合里剔除，不受影响。顺带修掉钩子里对全局 `jit` 的依赖（`HideGlobalJIT` 之后全局为 nil），改为加载时捕获 `ctx.jit`；`kleiloadlua` 钩子也不再要求 `injector` 存在（解密路径才需要）。缓存文件版本升到 `/1.1.0` 以重建缺失 `EncryptedMods` 的旧缓存。

- 删除**已失效的慢速尾调用回调链**：`lua_ds_set_slowtailcall_cb` 早在 LuaJIT 侧 `0188ec4f`（"Remove load-time tailcall wrapper injection"）随 `ParserTailWrapper` 一起移除，但注入器仍在 `gum_module_find_export_by_name` 里找它（结果恒为 NULL），`luajit_ds_check_slowtailcall` 与 `registry["LJ_DS_slowtailcall_mods"]` 因此成了无人读取的死代码——用户看到的 `SlowTailCall` / `AnyModDisableTailCall` 两个选项只是把名字写进一张没人查的表。现在连同注入器侧的导出查找、检查函数、`jit.tailcall` 插件里的 `ApplySlowTailCall`、两个 modinfo 选项、两份断言旧包装器行为的孤儿测试（`tests/backtrace.lua`、`tests/tailcall_helper_recursion.lua`）一并删除。5.1 尾调用帧语义本就由编译期 `LUA_COMPAT_TAILCALL_CFRAME`（`LJ_DS` + x64/GC64 默认开）无条件提供。

- 修复插件被两个搜索根**重复初始化**导致的启动崩溃：`DynamicPluginLoader` 现在按插件 stem 只处理一份（先到先得），后一个根打印 `skipped duplicate module (stem already handled from an earlier root)` 并跳过。此前 `default_plugin_search_dirs()` 的顺序是 env → mod 本地 `plugins/` → `injector_module_dir()/plugins`（migration fallback），当两处都有同一套包时（开发态 `DS_LUAJIT_INJECTOR=<repo>/Mod/Injector.dll`、游戏却加载工坊项），`plugin_core_vm` 会被 `LoadLibrary` 两次：第二次 `init` 被 host 拒绝（`service conflict ds_core_vm_get_game_lua_context`），随后该副本被 `close_library`，进程以 `0xC0000374`（堆损坏）退出——`plugin_client_inject_smoke`/`plugin_client_host_smoke`/`plugin_dedicated_sim_pause`/`game_mod_throw_abort` 四个闸门因此全灭。单测 `plugin_dynamic_loader` 新增跨根去重用例。

- 开发部署改为**复制**，不再依赖手工软连接：`cmake --install` 结束时调用新工具 `tools/deploy_mod.py`，把装好的包一次性写进游戏实际加载的 mod 目录（`-DDS_DEPLOY_AFTER_INSTALL=OFF` 关闭；`-DDS_DEPLOY_MOD_DIR` 指定目标；默认工坊项 `…\workshop\content\322330\3444078585`，不存在则 `<游戏>/mods/DontStarveLuaJit2`），并把 `bin64/windows/Winmm.dll` 复制进游戏 `bin64`。原因：软连接让 Steam 更新 / `--push-content` 暂存 / 运行时 materializer 直接写进源码树。目标目录是打包树（含 `<名>.dll.pkg`）时，每个部署的模块同时写成同名 `.pkg` 孪生——只写规范名会被 `materialize` 用旧孪生覆盖，没有孪生的模块会被 `prune_unpackaged_module` 删除。`tools/pre_push.py` 在测试通过后跑同一条 `cmake --install`（`--no-deploy` 跳过；部署失败只告警，不拦截推送），新增 `tools/deploy_mod.py` 单测并注册为 ctest `plugin_deploy_mod`。钩子的配置优先级同时改为 **RelWithDebInfo → Release → Debug → MinSizeRel**（原来 Debug 优先：既跑的不是日常运行的那套二进制，又会把 Debug-CRT 产物装进 staging 目录/游戏目录），只在首选配置没有已构建测试时才回退；`--config` 仍可显式覆盖。

- 测试与 pre-push 钩子：补上 Windows 侧的特征码**全量生成 + 增量生成**闸门（`windows_signatures` / `windows_signatures_cache`）。此前只有 Linux 有等价覆盖（`linux_signatures_*` 用 `verify_linux_signatures` 映射 ELF 后 `resolve_lua_signatures_from_modules`，`--check-cache` 验缓存增量），Windows 侧只有 `unique_signature`／`memory_signature_abi`／`xref_pattern`／`graph_seed` 这类纯算法片段测试，而 `create`／`update_signatures` 只是手动 custom target——签名库格式、create↔update 串线、缓存修复的回归都能直接穿过钩子。新闸门驱动**真实工具** `signature_updater`：`create` 从零重建 client/server 两个库（759671 实测各 104 条），随后 `update` 重解析并要求每条 offset 逐一不变；`--check-cache` 先把 `lua_gettop` 的缓存 pattern 改成 1 个 nibble（必然歧义），要求 update 原地换掉 pattern 且 offset 不动。库文件写到新增的 `SIGNATURE_TOOL_OUTPUT_DIR`（临时目录），绝不碰 `Mod/signatures_*.json`（runner 前后比对 mtime/size 兜底）。顺带修掉一个 Debug 专属崩溃：`pe-parse` 是 DLL 而其头文件的 `std::string` 跨 ABI 布局不同，Debug 消费者一旦在 PATH 上先命中 `Mod/deps/pe-parse.dll`（Release 构建）就会在 `IterSec` 里把 section 名读成空/错位并 0xC0000005——现在 `signature_updater` 与 `signature_checker` 的 POST_BUILD 统一按配置复制 `$<TARGET_RUNTIME_DLLS>`（原 frida-gum 单独复制规则随之删除）。实测单条 Debug ~6 分 16 秒／RelWithDebInfo ~26 秒；与 Linux 相同，仅在拿到游戏二进制（`GAME_DIR` 下两个 exe + `version.txt` + `Mod/deps/lua51.dll`）时才注册，CI 天然跳过。

- 测试与 pre-push 钩子：`plugin_client_inject_smoke` / `plugin_client_host_smoke` / `plugin_dedicated_sim_pause` 不再写死集群端口 10999，启动前用 `tests/harness/ports.py::free_udp_port()` 取一个空闲 UDP 端口（遗留专服或用户自己的服务器占着端口时，游戏会 `RakNet UDP startup failed: SOCKET_PORT_ALREADY_IN_USE`，随后在退出路径触发引擎断言 `Illegal termination of worker thread`（0xC0000409），看起来就是“push 钩子的测试脚本直接崩溃”）；`test_nucleus_adapter` 去掉写死的 `lua_getstack` span `< 0x120` 预算——那只是某一次 `lua51.dll` 构建的布局，重建参考库就会失败——改为结构性断言“span 不得越过下一个导出 RVA”，并打印参考 DLL 路径与大小便于定位。

- 签名库重建（`signature_updater create`）提速 341 s → ~11 s，输出与优化前**逐条一致**（client/server 各 104 条，pattern/offset 无变化）：`scan_by_short_body` 的中段 needle 搜索对每个候选都全量扫 train+target `.text`（`lua_setupvalue`/`lua_resume`/`luaL_ref` 三个函数独占 192 s），现在每个模块各构建一次 8 字节窗口哈希（唯一/多重命中）与 4 字节 postings 索引，needle 先查索引再只做定长 `memcmp`；`FunctionTable::span_containing` 原实现会从 `upper_bound` 一路回扫到表头（≈4e5 个 span），改为命中第一个仍覆盖目标的 span 即返回（层叠区间语义不变，pdata 交叉校验的 `compared/mismatches` 数值完全一致）；`FunctionTable::add` 的逐条有序插入改为批量 `assign`（Nucleus 的 CFG 与 remap 都是 4e5 量级）；`find_function` 先查 `address_functions`；pdata 交叉校验从 O(spans×ranges) 改为按 start 排序 + 前缀最大 end 的反向查找。另：该工具需用 **Release** 构建（Debug 下 `nucleus_disasm` 26.8 s，Release 3.3 s，是剩余时间的主体）。工具启动时关闭 CRT assert / WER 弹窗并把 assert 写到 stderr、stdout/stderr 改为不缓冲，避免批处理被模态框挂死（`init_ctx` 已创建 `FunctionRelocation` 日志器，`DS_FR_LOG=1` 时再镜像到控制台）。Linux 侧顺带修掉一个被这次结构变更暴露的未定义行为：`ModuleSections` 的 `GumMemoryRange` 成员（`text/pdata/rodata/plt/got_plt/bss/ehframe`）此前未初始化，`in_plt()/in_got_plt()` 在“段不存在”时读到栈垃圾；现在一律值初始化（0..0），`tests/function_relocation/test_xref_pattern` 在 Ubuntu 24.04 Release 下恢复通过。

- 修复开启 LuaJIT 后无法拆解/编织皮肤：客户端的物品服务器调用栈校验会把 `BarterLoseItem`/`BarterGainItem` 等的整条 Lua 调用栈逐帧格式化成字符串，与写死的期望栈逐字节比较；不一致时客户端本地伪造 `{"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}`（UI 只会显示 “Failed to contact Klei Servers”）。取 chunkname 的引擎私有 helper（Windows `0x140483B20` / Linux `0x4AC6D0`，Ghidra 命名 `lua51::luaGetFuncChunkName`）按内嵌 Lua 5.1 的 `TValue`/`Closure`/`Proto` 偏移硬解析（tag@+8=6、isC@+0xA=0、Proto@+0x20、chunkname@+0x78+0x18）；LuaJIT 下这些布局不存在，helper 对所有 Lua 帧返回 NULL，栈串变成 `[**untrusted** ...]`，校验必然失败。两者按定制 Lua API 纳入既有替换管线：`src/lua51` 参考实现导出 `lua_setchunkname` / `lua_getfuncchunkname`（后者按引擎 helper 的语义读 `Proto.chunkname`，C 闭包/未标记返回 NULL），`LuaApi.hpp` 的 API 表新增这两项（`ctx->api._lua_setchunkname` / `_lua_getfuncchunkname`），`ReplaceApis` 用同名 LuaJIT 导出替换游戏内的 `lua_setchunkname` 与 chunkname helper；特征码随参考实现进入 Lua 侧签名集（`signatures_client/server.json`：offset 6304/6416 + pattern）。Windows 与 Linux 同构，macOS 无此校验故不适用。顺带修掉 `lua_getinfo_game` 的死代码：`ar->source` 的 `@` 剥离写在了 `memcpy(ar,&iar,...)` 之前、随即被覆盖（`luajit/src/lj_debug.c`），现改为写 `iar.source` 并加 NULL/未请求保护。

- Linux/macOS 包不再因 `render.shadow` 报错，插件 Lua 注册表改为**按盘上内容发现**：`Mod/plugins/init.lua` 不再手写包清单，而是调用新导出 `GameInjector.DS_LUAJIT_list_plugin_packages(plugins_dir)`（`core/PluginPath.cpp::list_plugin_packages`；与 native loader 扫描同一文件系统，返回含 `modinfo.lua` 的 `plugin_*` 目录名，排序，路径按 UTF-8 解码）。因此非 Windows 包里不存在的 Windows 专用 `plugin_render_shadow` 根本不会被引用——此前 `load_package` 打不开 `modinfo.lua` 即 `error`，而 `modmain` 执行 `plugins/init.lua` 未包 `pcall`，整个 AfterModMain 注册表随之中断（所有插件丢失）。每个包独立 `pcall` 加载（单个坏包只记日志，不拖垮其余）；无 `GameInjector`（未注入 / 缺 `core.vm` / 单测）时插件系统整体禁用——`init.lua` 直接返回空注册表并打印原因，不保留静态兜底清单。`test_plugin_path` 新增发现语义用例。

- 所有安装入口（`install.ps1`、`install.sh`、`Mod/install.bat`、`Mod/install_linux.sh`）新增清理步骤：在包校验通过之后、部署壳之前删除 `<游戏>\data\unsafedata`（旧的 Injector marker、启动日志、插件配置），避免 marker 指向上一次安装残留的路径导致“装了没效果”；删除失败只警告不中断（`Mod/install.bat` 走 `rd /S /Q`，替代脚本里的 `rm -rf`）。由于 Lua 侧 `luajit_*.json` 已随沙箱改造迁到存档目录，该目录只剩注入器自己的状态，但插件管理器的配置/固定项也随之重置。同时自检不再把“marker 缺失”算作失败——marker 一直由壳在首次启动时写入，清理之后它必然是缺失的（由 `[CHECK] ... absent` 提示），只有“marker 存在但指向已消失的模块”仍算问题。

- 创意工坊改为“发布名 ≠ 加载名”：`tools/update_workshop_tags.py --push-content` 现在把游戏会映射的模块按 `<名>.pkg` 上传（`Injector.dll.pkg`、`deps/*.dll.pkg`、`plugins/<stem>/<stem>.dll.pkg`），运行时在 `LoadLibrary` 之前从 `.pkg` 生成规范名（`core/PackagedModule.hpp`；入口是壳的 `InjectorBootstrap`（解析模块 + `deps/`）、`DynamicPluginLoader`（包内候选）、`CoreVmBootstrap`（`plugin_core_vm`））。原因是 Steam 按文件差异更新工坊项：被映射的 DLL 既不能覆盖也不能删除（`ERROR 5`），只要规范名出现在清单里，游戏运行时那一次更新就永远完不成，整个 mod 停在旧版本。`.pkg` 从不被映射，Steam 随时可以替换；规范名只在启动时按 PE 构建戳（`TimeDateStamp` + `SizeOfImage`）刷新，若被另一个进程映射则保留现状（与此前相同的版本偏斜）。某个包成员被下架后留下的规范名残留，只在“打包树”内清理（规范名没有 `.pkg` 双胞胎即视为残留），源码树没有 `.pkg`，绝不会删掉开发者的构建。发布侧同步改布局：`.github/workflows/release.yaml`（Windows 腿）在打包前调用 `tools/pack_payload.py Mod`，`windows_Mod.zip` 同样只带 `<名>.pkg`（`install.ps1` 自检接受两种名字；**`cmake --install` 本身不改名**，改名只由打包工具 `tools/pack_payload.py`（与工坊推送共用同一规则）在打包时完成，开发树 `cmake --install Mod/` 仍是规范名，materializer 在那里是空操作）。Linux/macOS 不需要这套布局：POSIX 允许 `rename()` 直接替换被映射的文件（实测：持锁进程仍读到旧版本、新进程读到新版本），而**原地截断写**才是致命的（实测映射页被清零、进程 `SIGILL`）——本仓库的写入路径一律先 rename。多进程同时启动也安全：每个进程用自己的 `*.ds_materialize_tmp_<pid>_<n>` 暂存，只做一次原子发布（Windows `MoveFileEx(REPLACE_EXISTING)`、POSIX `rename`），抢输的一方干净退出、已被别人映射的规范名保持不动；抓到正在被 Steam 重写的 `.pkg` 会重读一次并校验 PE 段表完整性，绝不会把半个文件放上去。`update_pending` 落位与 `plugin.manager` 安装同样改成原子替换，不再有原地截断的兜底（实测 6 进程 × 400 次并发 materialize + `LoadLibrary` 无一次失败）。

- 崩溃哨兵与 `luajit_config.json` 对齐 Klei 的 mod io 沙箱：759671 起 Lua 侧只认相对 `unsafedata/...`，且解析到**存档目录**（`…/<steamid>/client_save/unsafedata`），绝对路径与 `../` 一律 `invalid filepath`；注入器此前却按 `<游戏>/data/unsafedata` 读写，同一个逻辑文件被拆成两份——mod 的清理永远清不到哨兵，于是 `skip inject, find crash content` 长期命中：注入被永久跳过、`GameInjector` 为 nil，用户只看到“模组未安装”。现在两侧同根：native 取 `GetClientSaveDir()`（`util/Unsafedata.hpp`；steamid 缺失时退回最近写入的 `*/client_save`）下的 `unsafedata/`，mod 继续用相对 `unsafedata/...`；`check_crash` 移到 `sdk::steam::Initialize` 之后（哨兵需要 steamid），注入开始时顺带创建该目录。壳自己的 marker 与 `ds_luajit_boot.log` 仍在 `<游戏>/data/unsafedata`（游戏 main 之前就要写，与沙箱无关）。不做旧路径兼容：老安装残留的 `<游戏>/data/unsafedata/luajit_config.json` 会被忽略。哨兵同时改为“只跳过一跳”（`{1}` → `{2}`，下一次启动照常注入），stock 启动不再抹掉记录，`is_crash()` 恒 false 的笔误一并修正，崩溃后的重试弹窗恢复。

- Linux 专服启动：修复 `nucleus_analyze_file(lua51) failed: nucleus load_binary failed: …/deps/liblua51.so` 后进程直接退出的问题。根因是 CI 镜像没有 `binutils-dev`，`3rd/nucleus` 把 `NUCLEUS_LOADER_NO_BFD` 编进了 `libfunction_relocation.so`（发布包里既无 `libbfd-2.42-system.so`，也没有任何 BFD 符号），Linux 上 `load_binary()` 只走到 "no binary loader available for non-raw type" 桩。现在 Linux 不再依赖 libbfd：`loader.cc` 内置 ELF64 加载器（段按 `SHF_EXECINSTR` / `SHF_ALLOC` 且非 `SHT_NOBITS` 映射，`STT_FUNC` 符号取自 `.symtab`/`.dynsym`，`.eh_frame_hdr` FDE 起点照旧）。对 `liblua51.so`、`liblua51DS.so`、`liblua51Original.so`、`dontstarve_dedicated_server_nullrenderer_x64`、`dontstarve_steam_x64` 生成的 FunctionTable 与原 BFD 路径逐条一致（服务端 25324、客户端 27236 条 span 完全相同）。macOS 仍走 BFD。

- Linux 启动：`libfrida-gum.so` 改为 `-Wl,-z,noexecstack` 链接（`tools/setup_frida_gum.py`）。glibc ≥ 2.41 拒绝 `dlopen` 需要可执行栈的 DSO（`cannot enable executable stack as shared object requires`），而壳正是用 `dlopen` 加载真实 Injector，Ubuntu 25.04+/WSL2 上表现为启动即失败（#45/#47）。

- 注入诊断：`nucleus_analyze_file` 的失败信息带上加载器自身原因（`nucleus load_binary failed: <path> (<loader reason>)`，disasm/CFG 失败同样），不再只给无细节的包装串。

- Windows 下 `lua51DS`/`lua51DS_gengc` 可发布 LuaJIT trace 符号到 Microsoft-JScript ETW provider（`57277741-3638-4a4b-bdba-0ac6e45da56c`，不安装 manifest、不生成 JIT PDB）：**运行时默认关闭**，用 `require("jit.profile").etw(true|false)`（`etw()` 查询）进程级开关；`etw(true)` 会顺带对该 VM 执行等价 `jit.flush` 的全量 trace flush（确保此后每条活 trace 都有记录、不残留旧身份），`etw(false)` 立即上报 MethodUnload/SourceUnload/ScriptContextUnload 并停发（记录由属主 VM 释放，绝不被别的线程解引用）。因此**游戏/宿主必须在被注入的 VM 里显式调用一次 `etw(true)`**（集成测试与 `--hold-for-profile` 已自行调用），否则 ETL 里不会有 JIT 名字。开启后：每个提交的 trace 发布一条 source 与一条 method 记录，WPA/PerfView 的 `CPU Usage (Sampled)` 能把落在 `[T->mcode, T->mcode+T->szmcode)` 的采样 PC 解析成 `LuaJIT::TRACE_<traceno>::<chunk>:<起始行>`；`tests/performance/cpu.wprp` 以 `0x3` 订阅（运行时 load/unload + start rundown），因此对已运行的进程中途附加也能解析此前编译的 trace，并把事件收集器缓冲调大（该 GUID 与机器上所有 Chakra 宿主如 Edge/WebView2 共用，它们会刷出上万条 JIT 事件）。符号名只表示 trace 起始行，不覆盖 exit stub／解释器 dispatch，也不注册 `RtlAddFunctionTable`（`lj_err.c` 靠缺少 `RUNTIME_FUNCTION` 识别 JIT 帧，原生 unwind 行为不变）；chunk 名取自 Lua 侧：`@`/`=` 前缀去掉，裸路径（DST 引擎传 `scripts/xxx.lua`，不带 `@`）原样保留，形如源码文本的名字（含换行或超过 512 字节）折叠成 `(string)`，避免把整段源码塞进符号；发布路径不在符号缓存锁内写 ETW（锁内只做链表/标志更新，实测 ~0.2 µs/条提交、~15 ns/记录），worker join 移出 lifecycle 锁（5 秒超时诊断），会话背压不会卡住 trace 编译或 VM 创建/关闭；`--jit-diagnostics`/`analyze.py` 仍是独立的 stdout/`jit.attach` 路径，不是 ETW 符号消费者。该功能**默认不编译**，需显式开启构建：`-DLUAJIT_ENABLE_ETW=ON`（CMake）/ `XCFLAGS+=-DLUAJIT_ENABLE_ETW`（Makefile）；`-DLUAJIT_TEST_ETW=ON`（需同时 `LUAJIT_ENABLE_ETW=ON`）构建两个 GC 变体的真实 ETW 集成测试（`luajit_<variant>_etw_symbols`，无采样权限时返回 77 即 CTest SKIP，事件缺失即失败；`--hold-for-profile` 模式供 WPR 中途附加验收）。

- `render.angle`：修复 Vulkan 后端下 Steam 覆盖层不可用/卡死的问题，并移除旧的覆盖层禁用 workaround。旧实现无条件把 `VK_LAYER_VALVE_steam_overlay` 写进 `VK_LOADER_LAYERS_DISABLE`（禁用覆盖层 layer），但真实根因是 ANGLE 在驱动支持时默认启用 `supportsSwapchainMaintenance1`（`VK_EXT_swapchain_maintenance1`：present fence、信号量回收、延迟释放交换链），Steam 覆盖层的 Vulkan layer 重建呈现信息链时不支持这些结构——覆盖层激活后呈现报错，渲染线程在 ANGLE 错误日志路径（`std::ostringstream` 构造 → LFH 堆锁）上无限阻塞，游戏表现为 `framebuffer not complete (0x0)` 刷屏后无响应（实测：RTX 3050 / 610.88 / Vulkan 1.4.341，ANGLE d9fc4a37，挂起转储 RenderThread 卡在 `RtlpLowFragHeapAllocFromContext`）。现在 `EGL_FEATURE_OVERRIDES_DISABLED_ANGLE` 直接禁用该特性、回到经典呈现路径，Steam 覆盖层可正常打开；`EnsureVulkanLayerDisableEnvironment` 与 `VK_LOADER_LAYERS_DISABLE` 相关代码整段删除，不再触碰用户的 Vulkan loader 环境变量。

- `dev_init.sh`/`dev_init.bat`（`tools/update_steam_paths.py`）初始化补齐一步：定位到游戏目录后，向 `<游戏>/bin64/steam_appid.txt` 写入 appid（默认 `322330`），不再需要按调试文档手工创建。

- `install.bat` / `install_linux.sh` 收敛为“只装壳”：Windows 只把包内 `bin64\windows\Winmm.dll` 复制进游戏 `bin64`（内容一致直接跳过，重复运行结果不变），Linux 只把包内 `bin64/linux/lib64/libInjector.so` 放进游戏 `bin64/lib64` 并改写 `LD_PRELOAD` 启动器（原二进制保留为 `*_1`，重复运行跳过）；两者都不再迁移/删除任何 mod 文件、不再写 marker、不再清理游戏目录里的旧 DLL。旧脚本在原地更新时不收敛——`if exist Injector.dll`/`[ -f libInjector.so ]` 会把上一版的 Injector 留在 mod 根、robocopy 无 `/MIR`（Linux `cp -a`）会留下新版已删的 deps/插件，结果就是新壳配旧 Injector（启动崩溃的来源）。源/目标改为按脚本自身位置推导（与调用者 cwd 无关），Windows 侧错误提示不再因绝对路径里的 `(`/`)` 打断 cmd 解析，`uninstall` 只删壳与遗留 marker（Linux 另把 `*_1` 原二进制改回）。

- 新增一行式安装：`install.ps1`（Windows，`irm … | iex`）与 `install.sh`（Linux，`curl … | sh`）——自动挑最新 release/preview（`DSJ_CHANNEL`/`--channel`）、按 `tools/steam_env.py` 的规则从注册表 / `libraryfolders.vdf` / `appmanifest_322330.acf` 定位游戏根目录（可用 `DSJ_GAME_DIR`/`--game-dir` 覆盖），把包解到目标目录后调用包内安装脚本（装壳；Linux 另写 marker 与自检）。

- `install.ps1` 目标目录改为工坊优先：游戏所在库存在 `steamapps\workshop\content\322330` 时，包解到 `…\322330\3444078585`（订阅者实际加载的目录；`install.bat` 的 `workshop\content\322330` 分支据此把壳装回同库的 `common\Don't Starve Together\bin64`），只有该目录不存在时才退回 `<游戏>/mods/<目录>`；`DSJ_MOD_FOLDER`/`-ModFolder` 只在回退路径生效。目标目录已存在却不是本 mod（无 `modinfo.lua`）时仍拒绝覆盖。

- `install.ps1` 覆盖文件前先过“强杀授权”：检测到 `dontstarve_steam_x64` / `dontstarve_dedicated_server_nullrenderer_x64` 仍在运行（这些进程映射着 mod 里的 DLL，`Remove-Item`/`Copy-Item` 会 sharing violation）时，先打印进程名与 pid 并询问，只有输入 `y`/`yes` 才强制结束（随后等进程真正消失再继续）；其它输入或非交互环境（`Read-Host` 失败）整体中止。授权发生在解压/删目录/复制之前，中止时磁盘无任何改动，也不再浪费一次下载。原来“先删改 mod、再由 `install.bat` 无条件 kill”的顺序漏洞就此消除。免交互场景可用 `-AllowKill`（或 `$env:DSJ_ALLOW_KILL=1`）跳过询问直接强杀。

- `install.ps1` 输出本地化：按 Windows 显示语言（`CultureInfo.CurrentUICulture`）自动选中文 / 英文，全部提示与错误都走同一张消息表（`Msg '<key>'`），未命中的 key 原样打印便于发现漏翻。中文词条放在仓库根新增的 `install.zh.json`（UTF-8 JSON，键与英文表一一对应）；脚本本身保持**纯 ASCII、无 BOM**——PS 5.1 会把无 BOM 的 `.ps1` 按 ANSI 解析（中文变乱码并触发语法错误），而 `irm | iex` 执行带 BOM 的文本会直接报 `无法将“Windows”项识别为…`，两种编码互斥，所以 CJK 文本不能写在脚本里。取不到（离线 / 未发布）或词条不全时静默回退英文。

- 注入可诊断化：壳（Winmm / InjectorStub）每次启动把解析来源/模块路径/加载与导出结果、壳的最终结果写到 `<游戏>/data/unsafedata/ds_luajit_boot.log`（stderr 保留）；`install_linux.sh` 结束时自检壳/真实模块/`ldd` 并打印 `[CHECK]` 结论，新增 `install_linux.sh selftest`（一次性进程实测 stub→真实模块链路），且脚本在 `sh`（dash）下会 `exec bash` 重跑，不再因语法错误空跑。

- `plugin.manager`：新增跨进程插件树锁（`plugins/.ds_plugin_update.lock`，`LockFileEx`/`flock`），启动更新检查与安装都持锁串行——客户端 + Master/Caves 同一波启动只做一次检查、不会并发写插件树（锁不支持时回退旧的无锁行为并提示，锁文件记录持有者 pid/host 便于诊断）。启动检查并入 `plugin_manager`（独立 `plugin.autoupdate` 模块及其三个专属服务删除），检查/安装期间不再持 manager 锁，`status_json` 全程可响应；等待中的安装最多等 30 秒后在锁内重建计划，不重复下载别的进程刚装好的资产。

- 插件安装布局收紧为“仅包布局”：只接受 `plugins/<stem>/<stem>.<ext>`（清单槽位带 `package=<stem>`，`module` 必须为 `<package><ext>`，`files[]` 相对包根，`modinfo.lua`、`scripts/*.lua` 等嵌套成员现在会真正安装）；扁平模块不再作为候选（loader 忽略并告警，清单校验与解压同步收紧）；某成员被占用时整包一起进 `update_pending/<package>/`，避免“新 Lua 面 + 旧模块”。

- 清单平台槽位与包内 meta 新增 `build_config` 构建戳：不兼容类别（MSVC 的 Debug 与 Release 家族）的资产在下载前被拒绝。

- 工具/测试：新增跨平台 pre-push ctest 门禁（`.githooks/pre-push` + `tools/pre_push.py`，可用 `git push --no-verify` / `PRE_PUSH_SKIP` 跳过）；游戏类 ctest 共享 `RESOURCE_LOCK(dst_game_server)`，`ctest -j` 并行时不再因固定端口（10999/8766/27016）冲突；Injector 只按当前布局（mod 根）定位真实模块，移除 `bin64`/`lib64` 旧路径回退与 deps 搜索兜底。

- 工具/测试：修复 Windows 中文代码页下游戏类 ctest 的假超时（`plugin_dedicated_sim_pause` / `plugin_client_inject_smoke` / `plugin_client_host_smoke` / `game_mod_throw_abort`）。harness 用 UTF-8 `errors="replace"` 读取子进程 stdout，得到的 U+FFFD 在 GBK 控制台无法编码，读线程抛 `UnicodeEncodeError` 退出后不再排空管道，游戏继续写 stdout 时阻塞，测试只能等到超时。`harness.logs.safe_print` 现在对编码失败降级输出，三个入口脚本把 stdout/stderr 设为 `errors="replace"`，读线程不会再因打印失败退出。

- 工具/测试：修复 Windows 上 `plugin_hash_zip` / `plugin_apply_offline` 两个 ctest 的加载失败（`0xc0000135` 找不到 `jvm.dll`、`0xc0000139` 找不到入口点 `zip_file_add`）。两者静态导入 vcpkg 的 `zip.dll`，但测试目录里没有这个 DLL，loader 会沿 PATH 命中 JDK 的 `bin\zip.dll`（JNI 库，自身导入 `jvm.dll` 且不导出 libzip 符号）。现在构建后把 `zip.dll` 连同 `bz2d/zlibd1`（Release 为 `bz2/zlib1`）复制到测试 exe 旁，与 PATH 内容无关。

- CI 修复：Windows 发布包此前实际是 Debug 构建。`Build` / `CMake install` 两步没有声明 `shell:`，Windows runner 默认的 pwsh 把 `"$PLUGIN_BUILD_CONFIG"` 当同名 PowerShell 变量展开成空串（环境变量要写 `$env:…`），`cmake --config ""` 不报错、静默回退默认配置（`CMAKE_CONFIGURATION_TYPES` 第一项 Debug）；Linux 默认 bash 展开正常，所以只有 Windows 侧出未优化的 Debug 产物和 vcpkg debug 运行时（`spdlogd/fmtd/zlibd1`），而清单/meta 仍盖着 `build_config: RelWithDebInfo`（同一步骤显式 `shell: bash`，展开正确）。现改用 `${{ env.PLUGIN_BUILD_CONFIG }}`（与 shell 无关）并新增校验步骤：安装产物必须与目标配置的构建产物逐字节一致，且非 Debug 包不得出现 vcpkg debug 专属运行时，否则 fail。

- CI 新增独立调试符号包 `windows_symbols.zip`（Release/Preview 资产，仅 Windows）：PDB 仍然**不**进 `*_Mod.zip`、也不进创意工坊（工坊那条路径本来就排除 `*.pdb`）。符号从 build tree 里按“本次实际发布的模块”逐个配齐——Injector / Winmm / 全部 `plugin_*` / function_relocation / lua51DS 系列 / lua51Original / 仓库自带的 stock lua51，配置取同一个 `PLUGIN_BUILD_CONFIG`，与发布二进制严格对应；Injector / Winmm / plugin_core_vm / plugin_manager 任一符号缺失即 fail。用法：解压后把该目录加入调试器符号路径（WinDbg `.sympath+`，VS「调试 → 符号」），Linux 不需要符号包——`Mod/*.so` 是 RelWithDebInfo 且未 strip，DWARF 就在包里（实测发布版 `libInjector.so` 21 MB、含 `.debug_info/.debug_line/.debug_str`）。

- 修复 `dump_lua_mods`（引擎 `lua_load` 钩子）的 chunk 落盘路由：chunkname 不一定是文件路径——`loadstring`/buffer 加载把代码本身当 chunkname（modoverrides 表、存档 savedata 包装、`GameLuaInjector.forceEnableLuaMod(...)` 注入块都走这条路）。此前这类 chunkname 会先做 `find("../mods/")` 的 `npos + strlen` 越界切片（代码短于 8 字节直接抛 `std::out_of_range`），又被 `!exists()` 误判，而 thunk 回退因内层 `auto output_path` 遮蔽从未生效，结果是 dump 静默失败或落到非法文件名。现在 `ChunkDumpPath()` 只把 `../mods/<mod>/<file>`（可带 `@` 前缀，剔除非法路径字符，总长 ≤255）映射到 `dumped_lua_mods/<file>`，其余一律写 `dumped_lua_mods/thunk.lua`（落盘策略见下一条，打不开时告警）。实测（专用服 `lua_vm_type=game`）：`plugin_lg_probe/modmain.lua` 正常成文件，modoverrides / savedata 代码块落 `thunk.lua`。

- 修复 `dump_lua_mods` 对加密 mod 只能 dump 出源码尾部的问题（hercules / MyxlHttps 家族，如 workshop-3014076942）：这类 loader 会在**同一个 `lua_load` 内**把解密后的源码按 ~8 字节切片喂给 reader（如 `myxl_date.lua` 245 片 = 1960 字节、`speech_moyuxuanli.lua` 4.3 万片 = 344112 字节），并在 reader 排空期间**重入 `lua_load`**；原来共用的 `thread_local LuaReaderWrapper` 会被重入调用 `buffers.clear()`，外层已累积的切片整批丢失、只剩最后一片，dump 出来自然就是文件尾那几个字符。现在每次 `lua_load` 用各自独立的 wrapper（重入调用各建各的、各 dump 各的 chunk），整文件一次组装落盘：上述文件 dump 后为完整明文源码（344112 / 70920 / 36360 / 1960 …）。落盘策略同时收敛为三态：切片流期间**追加**、负载不小于已落盘内容时**整体覆盖**（完整 chunk）、完整 dump 之后的零散小负载**跳过**（不再被 8 字节探测清零，例如 modmain 的 80154 字节完整源码不会被随后的 652 片重流覆盖）；写文件改用二进制模式（此前文本模式把 `\n` 写成 `\r\n`，dump 与真实源码不符）。

- 工具/测试：`game_mod_throw_abort` 对齐当前游戏的 mod 加载失败行为——modmain 报错后引擎不再退出进程，而是禁用该 mod（`Disabling <mod> because it had an error.`）并继续启动/重试游戏。测试仍要求三件事：`[ds_harness] THROW_ABORT`（force-enable 生效）、nil 索引错误文本、错误被处理（禁用日志或引擎 VM 的 `Error loading main.lua`），但不再要求进程退出；随之删除 `DedicatedProc.wait_exit`。

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
