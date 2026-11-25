# mimalloc 全局分配（Windows / Linux / macOS）

状态：**已实现并落地（Windows：单测 + 实进程 + DST 专用服负载通过；Linux ELF：WSL 实进程冒烟通过；macOS：未构建/未运行）**
日期：2026-11-24
源码位置：`src/DontStarveInjector/core/alloc/`

## 目标

在三个桌面平台的游戏进程里，把 CRT 全局分配（`malloc/free/calloc/realloc` + 平台 dup）
替换为 mimalloc，由注入器底座在**加载器阶段**安装、常驻、可一键回退（`DS_ALLOC_SHIM=off`）。

## 关键决策（实施后确认）

| ID | 决策 |
|---|---|
| D1 | 分配器属于注入器底座，不做插件；安装后不可运行时开关。 |
| D2 | mimalloc **静态**链入 `Injector`，`MI_OVERRIDE=OFF`、`MI_SECURE=OFF`，只用 `mi_*`。 |
| D3 | **全动态 CRT 域原子覆盖**：Windows 钩已加载 `msvcr90.dll` + `ucrtbase.dll` 的导出入口；POSIX 按模块全有或全无改写非系统模块的 GOT / `__got`+`__la_symbol_ptr`。**实测修正**：Debug CRT（`msvcr90d.dll` / `ucrtbased.dll`）不覆盖——debug 层在自己的 `malloc/free` 里维护块头，只换分配器入口会让它的 `free` 校验失败（`debug_heap.cpp` `_CrtIsValidHeapPointer` / `is_block_type_valid`，另有 `mimalloc: buffer overflow`），因此加载了 debug CRT 镜像即整进程跳过并记录 `skipped (debug CRT image loaded)`；发行版游戏链的是 release CRT。 |
| D4 | phase 0 零日志、零文件 IO、不触碰 `InjectorCtx`/`InjectorConfig`；Windows 在 `HookStartupEntry()` 首部完成栈缓冲 exe guard 与 env 读取后，用已有的 `gum_init_embedded()` + `gum_interceptor_obtain()` + `ds::FastHook` 完成 CRT 入口钩挂。 |
| D5 | 归属判定统一 `mi_is_in_heap_region`；外来指针按所属 CRT provider 回退各自 `orig_*`（`_aligned_free` 外来块只回退 `orig_aligned_free`）；`Injector.dll` 被 `GET_MODULE_HANDLE_EX_FLAG_PIN` 固定，`DLL_PROCESS_DETACH` 置 `g_shutting_down`。 |
| D6 | 唯一开关是启动期只读 env `DS_ALLOC_SHIM=mimalloc\|off`；`DS_ALLOC_SHIM_STATS=1` 开启计数与统计输出。禁用 `mi_option_show_stats`（退出期 `LoadLibrary("psapi.dll")`）。 |
| D7 | 不改 vcpkg triplet，用 overlay port 固化 mimalloc 构建形态。 |
| D8 | 不做 Windows CRT 代理 DLL，不重链游戏。 |

## 落地文件

| 路径 | 内容 |
|---|---|
| `cmake/ports/mimalloc/{vcpkg.json,portfile.cmake,vcpkg-cmake-wrapper.cmake,usage,pkgconfig-cxx.diff}` | overlay port：`vcpkg_check_linkage(ONLY_STATIC_LIBRARY)`、`MI_OVERRIDE=OFF`、`MI_SECURE=OFF`、POSIX `MI_LOCAL_DYNAMIC_TLS=ON`；port-version 2 |
| `src/DontStarveInjector/core/alloc/AllocTargets.hpp` | Windows CRT 导出表（消费/查询组 + 生产组、`_*_base` 别名）与 POSIX 导入符号表 |
| `src/DontStarveInjector/core/alloc/AllocShim.{hpp,cpp}` | provider 原函数表、按 provider 模板化的 wrapper、统计、`install_early`、env 读取、退出保护 |
| `src/DontStarveInjector/core/alloc/backend_win.cpp` | `msvcr90`/`ucrtbase` 导出入口两阶段 `FastHook` 安装 + 失败整组 `Revert` |
| `src/DontStarveInjector/core/alloc/backend_elf.cpp` | `dl_iterate_phdr` + `PT_DYNAMIC` 解析 + `JUMP_SLOT`/`GLOB_DAT` 改写 + 页权限恢复 |
| `src/DontStarveInjector/core/alloc/backend_macho.cpp` | dyld add-image 回调 + indirect symbol table 定位槽 + `vm_region_64` 权限 |
| `src/DontStarveInjector/DontStarveInjector.cpp` | Windows `HookStartupEntry()` / POSIX `init()` 安装点、phase 1 日志、`DllMain` 退出保护、POSIX `dlopen`/`dlmopen` 补扫钩、`Inject()` 起始与插件加载后补扫 |
| `src/DontStarveInjector/CMakeLists.txt` | `SOURCES` + `mimalloc-static` 静态目标校验与链接 + Linux x86_64 `-fcf-protection=branch` |
| `tests/plugin/test_alloc_shim.cpp` | wrapper 语义（10 cases / 96 assertions） |
| `tests/plugin/test_alloc_shim_install.cpp` | 实进程安装验证（1 case / 25 assertions） |

## 实施检查表

- [x] **Task 1 overlay port**：`vcpkg.json` 2.2.3 port-version 2；`portfile.cmake` 先 `vcpkg_check_linkage(ONLY_STATIC_LIBRARY)`，显式 `MI_OVERRIDE=OFF`/`MI_SECURE=OFF`/`MI_BUILD_STATIC=ON`/`MI_BUILD_SHARED=OFF`，非 Windows 追加 `MI_LOCAL_DYNAMIC_TLS=ON`；删除 dynamic 分支的 `mimalloc.h` 改写。
      验证：`vcpkg_installed/x64-windows-custom/lib/mimalloc.lib`（仅静态），`share/mimalloc/mimalloc-release.cmake` 为 `mimalloc-static ... STATIC IMPORTED`，无 `*mimalloc*.dll`，`include/mimalloc.h` 未被改写；`dumpbin /symbols` 无 `malloc/free/calloc/realloc` 外部定义且含 `mi_malloc`。
- [x] **Task 2 AllocShim 内核**：provider 分桶表 `ProviderOrig[kMaxProviders=4]`、`ShimSet<K>` 模板、`shim_entry(provider, kind)`、`orig_slot(prov, kind)`、计数（`memory_order_relaxed`）、`install_early`、`read_env_switch`/`read_env_stats`、`set_shutting_down`。
      零长语义：own `realloc(p,0)`/`_recalloc`/`_expand`/`reallocarray` 一律 free + `nullptr`；外来指针走 provider 原函数。
- [x] **Task 3 Windows backend**：`GetModuleHandleExW(..._FROM_ADDRESS|_PIN)` 固定 `Injector.dll`；只用 `GetModuleHandleW` 探测已映射 CRT（不 `LoadLibraryW`，不碰 `System32\msvcrt.dll`）；debug CRT 镜像存在时整进程跳过；两阶段事务；`InstallOutcome{Absent,Installed,Failed}` 区分“该 CRT 没有这个导出”和“钩挂被拒”；`ALREADY_REPLACED` 时恢复被 `FastHook::Install` 清空的原函数槽；失败按已装目标 `Revert`（事务外重试一次）；提交后分阶段校验必选跳板非空。
- [x] **Task 4 POSIX backend**：ELF 解析 `DT_SYMTAB/STRTAB/JMPREL/PLTRELSZ/PLTREL/RELA(SZ)/REL(SZ)`，`d_ptr` 归一化按 `PT_DYNAMIC` 是否 `PF_W` 判断；按 `PT_LOAD` + `PT_GNU_RELRO` 推导页权限并恢复；x86_64/aarch64 常量。Mach-O 用 indirect symbol table 定位 `S_LAZY_SYMBOL_POINTERS`/`S_NON_LAZY_SYMBOL_POINTERS` 槽，名称无法解析时按已绑定指针比对；`vm_region_64` + `mprotect`/`mach_vm_protect`（必要时 `VM_PROT_COPY`），写后按查询到的原权限恢复；回调内不调 `dlsym`/`dlopen`，主程序按“无 `LC_ID_DYLIB`”识别。
- [x] **Task 5 安装点与日志**：Windows `HookStartupEntry()` = 栈缓冲 exe guard → `gum_init_embedded()` → `install_early()` → `gum_interceptor_obtain()`（不经过 `InjectorCtx`）；POSIX `init()` = guard → `install_early()` → 原 `install_posix_startup_hook()`；`Inject()` 起始打印 `alloc shim: backend=... primary=... slots=... failures=...` 并镜像 `stderr`，主目标未命中升为 `error`。
- [x] **Task 6 POSIX 补扫**：Linux 钩 `dlopen`/`dlmopen`（失败只写 `stderr`），`Inject()` 起始与 `PluginHost.load_phase(EarlyNative)` 之后各补扫一次（幂等，按当前值判断是否已改写）；macOS 由 dyld 回调覆盖，`rescan_modules()` 为空实现。
- [x] **Task 7 统计与文档**：`DS_ALLOC_SHIM_STATS=1` 时 phase 1 与 `Inject()` 结束各输出 own/foreign 计数 + `mi_stats_print_out`（经 spdlog，避免 GUI 无 stderr 时静默）；POSIX `fini` 在 `_exit(0)` 前输出计数；CHANGELOG 双语条目。
- [ ] **Task 8（条件）MemoryManager 启用时的引擎层覆盖**：发行版使能字节恒为 0（Windows 只有 `Shutdown` 写 0、mac 唯一写 1 的 `Initialize` 零引用），CRT 入口/GOT 已覆盖 `Allocate→malloc`、`Free→free` 薄壳，故本任务不落地。
- [x] **Task 9 验收矩阵与回滚**（见下）。

## 验证结果

| 项 | 结果 |
|---|---|
| `ctest -C RelWithDebInfo -R "^(alloc_shim|alloc_shim_install|fast_hook)$"` | 3/3 通过 |
| `alloc_shim`（RelWithDebInfo / Debug） | 10 cases / 96 assertions 通过（Debug 下 `mi_expand` 因 `MI_PADDING` 恒返回空，断言改为与分配器自身答案比对） |
| `alloc_shim_install`（RelWithDebInfo） | 1 case / 25 assertions 通过（真实进程） |
| `alloc_shim_install`（Debug） | 按设计跳过（debug CRT）并有 `MESSAGE`，进程不崩 |
| `Injector` RelWithDebInfo/Debug 构建 | 通过；`dumpbin /dependents` 无 `mimalloc.dll`，导出表无 `malloc/free/calloc/realloc` |
| overlay port 产物 | 仅 `lib/mimalloc.lib`（+ `debug/lib/mimalloc-debug.lib`），`mimalloc-static … STATIC IMPORTED`，`mimalloc.h` 未被改写，`dumpbin /symbols` 无 `malloc/free/calloc/realloc` 外部定义且含 `mi_malloc` |
| **Windows 实进程**（`alloc_shim_install`） | `ucrtbase`：`realloc` 是跳进 `_realloc_base` 的 5B 桩（`ALREADY_REPLACED` 时保留已取得的跳板），`free` 与 `_free_base` 各自装钩，`_recalloc_base`/`_msize_base`/`_expand_base` 缺失记为 `Absent`；`malloc/calloc/realloc/free/_recalloc/_msize/_aligned_malloc/_aligned_free/_strdup` 与 `std::string` 全部落 `mi_is_in_heap_region == true` |
| **DST 专用服真机**（`tests/plugin_server/run_dedicated_sim_pause.py`，两次运行：20:45 与 20:53） | `LG_INJECT_OK` → `LG_WORLD_READY` → `LG_SIM_PAUSED` → 干净关闭、`server exit code=0`、`PASS`；注入器日志 `alloc shim: backend=win-crt-hook primary=1 slots=31 failures=0`（`msvcr90.dll` 命中，31 个入口，0 失败）；无 `Access violation` / 无 mimalloc 报错 |
| **Linux ELF**（WSL Ubuntu 24.04，g++ 13.3，源码目录内 mimalloc 静态构建） | `installed=1 backend=elf-got slots=6 primary=1 failures=0`；`malloc/calloc/realloc/free/strdup/posix_memalign/realloc(NULL,0)` 全部 `mi_is_in_heap_region == true`，`stats malloc=5 free_own=5 free_foreign=0` |
| macOS Mach-O | **未构建/未运行**（无 macOS 机器）；调用链内部无 `dlsym`/`dlopen`、无分配，槽身份取 indirect symbol table，绑定值扫描作兜底 |
| DST 客户端真机负载 / 性能 A/B（Task 9 Step 2） | **未执行**（需 Steam 客户端与同存档 A/B） |
| `tools/pre_push.py` 全量门禁 | **未执行**（本次只跑改动相关目标；全量套件含需要 Steam 的客户端 smoke 与 1800s 游戏用例） |

## 回滚

1. 用户侧：`DS_ALLOC_SHIM=off`（完全跳过 CRT 钩挂/改槽与模块扫描）。
2. 仓库侧：还原 `Injector` 链接与 `SOURCES`、删除 `core/alloc/*`、删除 `cmake/ports/mimalloc`（回到 vcpkg 基线的动态 mimalloc，注入器不再使用它）、还原 `DontStarveInjector.cpp` 的安装点与日志。
3. 崩溃取证：`DS_ALLOC_SHIM_STATS=1` + `MIMALLOC_VERBOSE=1 MIMALLOC_SHOW_ERRORS=1`，看 `free_foreign` 来源模块再决定补哪个 dup/API。
