# doctest 迁移与 CTest 并发调度重整计划

## Context

重整 `docs/superpowers/plans/2026-11-11-doctest-test-suite-migration.md`。交付目标：把 `tests/` C++ 测试迁移到 doctest，**隔离测试并发，共享资源组内互斥，真实游戏测试不阻塞无关单测**。

当前为 plan mode：本文件是完整的新计划；仓库原文未修改。获准实施后先用本计划替换原计划，再落实代码。以下验证均为未来验收要求，不代表已通过。

## 1. Scope 与已核对事实

- 保留可执行目标、CTest 名字、命令参数、工作目录、超时；只追加分类标签和必要资源锁。
- 保留一个测试文件一个可执行文件。doctest 进程内串行执行，CTest `-j N` 并发进程。不合并 exe，不用 `doctest_discover_tests`，不引入自制调度器。
- 48 个测试源：plugin 31、function_relocation 15、根目录 2；`tests/CMakeLists.txt` 声明 48 个测试可执行目标，其中 46 个可用共享 main，2 个保留协议 main。平台条件影响实际目标数，不再把“46”或“77”当全平台测试总数。
- `config_view_build/plugin_config_bridge` 是同一纯内存 exe 的两个既有 CTest 注册，均保留，可并发，不加锁（`tests/CMakeLists.txt:220-221`）。不能写“一目标严格等于一条 CTest”。
- doctest 已在 `vcpkg.json:50-52`，安装版本 2.4.12；不新增依赖。`tools/pre_push.py:239-240,288-312` 已传 `-j N`，不改默认 jobs。
- 不迁移 Python/Lua、`luajit/` 和 `src/DontStarveInjector/util/tests`；允许在 CMake 中给现有测试追加标签/锁。不修改游戏 skip 逻辑，不新增生产 reset/log-path API。
- `run_match_suite.sh` 必须同步改造：它直接编译迁移源，现有 g++ 与临时 CMake 路径都没有 doctest/main（`:16-69`），原计划“无需改”不成立。

## 2. CTest 并发策略

### 标签

保留既有标签，使用 `set_property(TEST ... APPEND PROPERTY ...)` 等追加形式，仅操作已注册测试：

- `game`：真正启动游戏的测试。补到 `plugin_dedicated_sim_pause`、`plugin_client_inject_smoke`、`plugin_client_host_smoke`；`game_mod_throw_abort`、可选 `game_performance_*` 已有。
- `game_signatures`：`windows_signatures/windows_signatures_cache` 及四个 `linux_signatures_*`，保留原平台签名标签。
- `harness_unit`、`game_performance_unit`、`game_info_arguments` 不加 `game`，它们不启动游戏。

证据：`tests/CMakeLists.txt:579-672,914-954`。旧快速过滤漏掉 `game_mod_throw_abort`、可选性能和 Linux 签名测试，不能继续按名字排除。

### 资源矩阵

| CTest 集合 | 资源 / 证据 | 策略 |
|---|---|---|
| 其余隔离 C++、Python/Lua 静态门禁、离线 harness 单测 | 各自内存、不同临时前缀、只读构建产物 | `ctest -j N`，无锁 |
| `plugin_dedicated_sim_pause`、`plugin_client_inject_smoke`、`plugin_client_host_smoke`、`game_mod_throw_abort`，启用时含 `game_performance_worldgen/startup` | 同一游戏安装、注入文件/mod、保存环境、端口和运行时缓存 | 复用 `dst_game_server`，组内串行，与无关测试可重叠 |
| `xref_pattern`、`graph_seed`、`unique_signature`，Windows 的 `net_stats_decode`，UNIX 的 `eh_frame_starts/elf_plt_symbols` | exe 目录中的 `tests/<Config>/FunctionRelocation.log` | 新增 `ds_relocation_log`，只串行该组 |
| Windows 两个签名测试，或 Linux 四个签名测试 | DB 使用私有 scratch/只读，但共用签名工具 exe 目录下的旋转日志 | 独立 `ds_signature_tool_log`，同工具组内互斥，不占游戏锁或单测日志锁 |

游戏锁已存在（`tests/CMakeLists.txt:643-645,667-672`），不是新发明。修正“全是固定端口”的旧注释：动态选端口也不能隔离共享安装/保存环境。

日志路径依据：`src/FunctionRelocation/ctx.cpp:28-29`、`config.hpp:2-3`。路径由主模块位置决定，只改 cwd 无效。签名工具初始化依据：`tools/Creater/verify_linux_signatures.cpp:210-212` 与 Windows updater ctx 路径；输出目标见 `tools/Creater/CMakeLists.txt:104-105,150-165`。

日志锁是保守选择：确认共享文件和轮转，不声称已经观察到崩溃。代价是签名慢测同组不并发；本次不通过修改生产日志接口/复制运行目录优化它。

`memory_signature_abi/fast_hook` 只有 gum，`nucleus_adapter` 不初始化 relocation ctx，均不加 `ds_relocation_log`。锁按 CTest 名在对应平台分支注册后追加，不覆盖已有锁；不使用阻塞全体测试的 `RUN_SERIAL`。

### 保证边界

- CTest 资源锁仅在同一个调度进程内生效。不同构建目录、不同配置、两个 `ctest` 不共享锁。
- 临时 fixture 有固定 `%TEMP%` 名字；已核对同次调度不同测试前缀不冲突，不承诺跨 CTest 隔离。本次不重写临时目录系统。
- 验收顺序运行配置，不同时启动多个 CTest，不在测试时构建/部署。
- 游戏缺环境可能打印 SKIP 并 exit 0；签名可能 configure 时不注册。报告区分真实通过、跳过、未注册，不把绿色汇总当游戏验收。

## 3. doctest 入口与迁移契约

### 3.1 共享 runner

新增 `tests/support/doctest_main.cpp`：定义 `DOCTEST_CONFIG_IMPLEMENT`，手写普通 main，创建 Context，设置默认 `no-breaks=true`，再 `applyCommandLine(argc, argv)`，返回 `run()`。避免附加调试器时断言触发调试中断；命令行可覆盖默认。

```cmake
find_package(doctest CONFIG REQUIRED)
add_library(ds_test_doctest STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/support/doctest_main.cpp)
target_link_libraries(ds_test_doctest PUBLIC doctest::doctest)
target_compile_features(ds_test_doctest PRIVATE cxx_std_17)
```

显式列全部 46 个普通目标，`if(TARGET ...)` 后链接共享 STATIC main。两个自定义 main 只链接 `doctest::doctest`，各自定义实现，不链接共享 main。测试直接 include `<doctest/doctest.h>`，不增加只转发 include 的包装头。

### 3.2 普通场景

- 独立无参场景转 `TEST_CASE("<文件主干>/<场景>")`，删除旧 main 的调用；转换后不能仍由别的用例重复调用。
- `DS_REQUIRE` 默认转 `REQUIRE`，删除局部宏；`test_net_stats_decode.cpp:37-59` 的 `REQUIRE_EQ/fail()` 一并移除，使用 doctest 对应断言。
- 保留非致命收集语义：如 signature JSON 的 `expect()` 转 `CHECK`，不强制改成首错退出。
- `test_fast_hook` 整个原 main 为一个用例，保留 helper 调用和 hook 生命周期；`require(cond,msg)` 转 `REQUIRE_MESSAGE`。
- main-only 文件保留一个完整场景；`function_table_refinement` 保留全部检查和顺序，不为数量拆分。
- main 同时含初始化、内联检查和函数调用时：初始化按 §3.4；内联检查独立保留，函数转用例后删除调用。带参 helper 由用例准备参数后调用。确保每个原场景只执行一次。
- 删除四个选择器 `micro_windows/soft_score/virtual_flatten/orchestration` 的 `argv[1]` 分支，改用 doctest 过滤；仓库无旧协议消费者，不保留兼容分支。

### 3.3 失败隔离与状态依赖

旧 `DS_REQUIRE` 是 `exit(3)`（`test_assert.hpp:22-30`）；doctest `REQUIRE` 抛异常，仅终止当前用例。不能再依赖断言后的尾部清理，也不能依赖默认源码排序。

- `plugin_services/lua_event_bus` 各自合为一个按旧顺序执行的生命周期用例；注册、重复注册、通知依赖历史状态且无 reset API。不制造可单独过滤却缺前置条件的用例，不新增生产 reset。
- `plugin_path/injector_bootstrap/enabled_dst_mods/external_discover_gate/plugin_pin_config`：环境、根目录、搜索路径用局部 RAII 恢复，失败也执行；环境变量恢复进入用例前值，不无条件清空用户配置。
- `plugin_apply_offline`：fixture 成对设置/清理 HTTP override、mock map 与计数器。
- `signature_json_format`：全局 `SignatureJson::version_path` 指向局部字符串时，使用期有效，字符串销毁前恢复原指针。
- `plugin_process_lock.cpp:141-164` 有 join 前断言。改 `std::jthread` 或 join guard，失败展开也 join；被捕获对象生命周期覆盖 join。
- 动态库句柄、gum interceptor/事务、页映射等补齐必要局部 RAII；析构不得断言或抛异常。
- C 回调、`noexcept`、线程入口不使用会抛异常的 `REQUIRE`；记录结果，在 C++ 用例侧/线程 join 后断言。不把 `CHECK` 当所有异常边界的通用补丁。

### 3.4 gum / ctx 生命周期

`init_ctx` 只有 hcs 存活时可重复引用；deinit 不移除 logger，关闭后重开会同名注册失败（`ctx.cpp:15-45`；`tools/Creater/main.cpp:369-372`）。

新增最小 `tests/support/fr_context_env.hpp`，仅供六个 ctx 测试使用：

- 用例首次执行时，函数局部 static 进程级 guard 初始化 gum/ctx，返回就绪状态。每个相关用例首部 `REQUIRE(ensure_reloc_context())`。
- 无全局提前初始化、无逐用例 init/deinit；枚举不执行测试体，不创建 gum/ctx/临时资源。
- 正常进程退出时对成功初始化的 ctx 只 deinit 一次，再清理 gum；失败路径按实际完成阶段平衡清理。
- 不通过修改生产 `ctx.cpp` 或插入 `spdlog::drop` 掩盖错误。
- gum-only 的 `fast_hook/memory_signature_abi` 保持各自单一用例的局部 gum guard，不引入 ctx。

### 3.5 两个协议 main

| 目标 | 保留的协议 |
|---|---|
| `test_plugin_process_lock` | `--hold-lock <dir> <ms>` 在 Context 创建前直接走子进程模式；普通模式保存 argv[0] 供自我派生 |
| `test_elf_plt_symbols` | 前四个位置参数仍为 collision/external/provider/training 库；缺参先报 usage 并非零退出；允许在后面追加 doctest 选项。库加载/符号检查保留为完整用例，句柄自动释放 |

两个 main 均设相同 `no-breaks` 默认值，再传完整 `argc/argv`。原 `applyCommandLine(1, argv)` 会废掉过滤/枚举，禁止沿用。

### 3.6 独立 match 构建

`run_match_suite.sh` 两条路径都保留：g++ 添加共享 main 与 doctest include；临时 CMake 添加同一 main、`find_package(doctest CONFIG REQUIRED)`、链接头文件库。

直接编译接受 `DOCTEST_INCLUDE`，CMake 接受 `CMAKE_PREFIX_PATH/doctest_DIR`，复用已安装依赖；不下载另一份框架，不硬编码 Windows triplet 为 Linux 默认。缺依赖清楚失败，不能跳过后宣称兼容。

## 4. 实施路线与并行文件所有权

### Phase 0：基线与试点，先完成

- 导出当前 `ctest --show-only=json-v1`，记录名字、命令、标签、cwd、超时、锁；列出 48 源的目标及平台条件。
- 接入 runner，仅迁移 `test_buffer_name_pool`；Debug/Release 验证 9 个场景、精确过滤、失败退出，以及既有 CTest 名 `BufferNamePool`。
- 固定上述命名、异常安全、ctx、协议 main 契约。

### Phase 1：三片可并行，集成文件单 owner

| 切片 | 文件所有权 | 重点 |
|---|---|---|
| A | plugin 源中除 B/C 外的文件 | 普通转换、services/event_bus 整体生命周期、signature JSON |
| B | `test_plugin_path/injector_bootstrap/enabled_dst_mods/external_discover_gate/plugin_pin_config/plugin_apply_offline/plugin_process_lock.cpp` | 状态 RAII、线程 join、自定义 main |
| C | `tests/function_relocation/*.cpp`、plugin 的 `test_net_stats_decode.cpp`、根目录 `test_fast_hook.cpp`、ctx 支持头与 match 脚本 | ctx、内联检查、Linux 参数、独立构建 |
| 集成 owner | `tests/CMakeLists.txt`、共享 main、计划与最终文档 | 目标链接、分类/锁、统一验证 |

各片提供原场景→新用例映射，不用函数计数充当行为覆盖。并发编辑时不在共享构建目录各自 configure/build/ctest；统一集成后检查。

### Phase 2：集成调度

完整链接普通/协议目标；落地 §2 标签与锁；只操作已注册条件目标。与基线 JSON 对比，CTest 名字、命令、cwd、超时不变，属性差异只允许计划内新增标签/锁。

### Phase 3：行为与并发验收

按 §5 顺序执行；失败定位到测试/资源，不用全局 `-j 1`、删断言或排除失败用例规避。

## 5. Verification

仓库根目录执行，cmake/ctest 使用 PATH 或本机已配置完整路径。先构建对应配置，再运行；各配置顺序执行。

```bash
cmake --preset ninja-multi-vcpkg
cmake --build --preset ninja-vcpkg-debug
ctest --test-dir builds/ninja-multi-vcpkg -C Debug --show-only=json-v1
ctest --test-dir builds/ninja-multi-vcpkg -C Debug -j 8 \
  -LE '^(game|game_signatures)$' --no-tests=error --output-on-failure

cmake --build --preset ninja-vcpkg-release
ctest --test-dir builds/ninja-multi-vcpkg -C Release -j 8 \
  -LE '^(game|game_signatures)$' --no-tests=error --output-on-failure

cmake --build --preset ninja-vcpkg-release-dbg
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -j 8 \
  -LE '^(game|game_signatures)$' --no-tests=error --output-on-failure

# LG_REQUIRE_GAME 为现有游戏 harness 共用的严格开关
# 正常游戏使用 RelWithDebInfo，避免 Debug CRT 注入边界
LG_REQUIRE_GAME=1 ctest --test-dir builds/ninja-multi-vcpkg \
  -C RelWithDebInfo -j 8 --no-tests=error --output-on-failure \
  --output-junit doctest-migration.xml
```

| 验证 | 可判定结果 |
|---|---|
| 分类选择 | 快速集合排除四个游戏 smoke、可选游戏性能与任何已注册平台签名；保留离线 game/harness 单测 |
| 完整性/过滤 | 枚举所有已构建 exe，与场景映射核对；多用例 exe 用精确 `--test-case` 只执行一个。services/event_bus 按整体场景计数 |
| 失败隔离 | 临时探针：首例中途 REQUIRE 失败，RAII 清理执行，第二例仍执行，进程非零；验证后移除，不新增永久框架自测 |
| 产品回归牙 | 临时移除 `PluginPath.cpp` 的 `g_dll_roots.push_back`，只重建 `test_plugin_path`，Release 必须行为断言失败；恢复后重建绿。不以写 false 断言代替牙 |
| 子进程协议 | 跑完整父子锁用例，直接执行 `--hold-lock <隔离临时目录> 100` 保持退出语义；普通模式过滤有效 |
| ctx | `xref_pattern/graph_seed/unique_signature` 完整多例运行，无重复 logger 注册；过滤单例也能初始化 |
| 真实并发 | 完整 `-j 8` 的 JUnit 时间戳/耗时或等价起止事件中，至少两个无共享资源测试区间重叠，不是只看到命令含 -j |
| 真实互斥 | 同一次运行中每个锁组内区间不重叠；JSON 中锁成员准确。游戏条目须实际启动，SKIP/未注册不算通过 |
| 游戏/签名 | 核对注册清单与严格模式结果，缺安装记录未验收；Debug 只验离线集合 |
| Linux | 构建迁移目标，运行离线集合、eh_frame 与 elf_plt；后者用四个实际库参数且追加枚举/过滤有效；match 脚本两条编译路径都通过 |

Linux match 脚本示例，路径须用实际安装包：

```bash
DOCTEST_INCLUDE=/path/to/include \
CMAKE_PREFIX_PATH=/path/to/doctest-prefix \
  bash tests/function_relocation/run_match_suite.sh
```

不存在 Linux/游戏环境时，完成可达验证并列出未验收项，不能宣称全平台/完整游戏通过。可选性能测试未启用则不冒充执行。无需永久新增“测试 CTest 调度器”的测试。

## 6. Completion 与收尾

- 48 个原测试源完成迁移，仅两个协议目标和共享 runner 保留 main；原场景无遗漏/重复，无局部断言宏、DS_REQUIRE、旧头引用。
- 删除 `tests/support/test_assert.hpp`、旧 main 选择器与 fail/abort 包装，不留兼容路径。
- CTest 外观与基线一致，只有约定标签/锁变化；条件注册、别名、旧标签保留。
- 交付准确配置、命令、真实通过/跳过/未注册集合，以及并发/互斥证据，只声明已执行验证。
- 验证后更新现有测试使用文档与 CHANGELOG，说明断言、过滤、快速标签门禁和跨 CTest 锁边界；历史计划不批量改写。同步可维护的旧 DS_REQUIRE 指导，不修改用户维护技能文件。

本次规划仅静态源码核对与本地计划交付；未构建、未运行测试、未启动游戏、未修改仓库实现。
