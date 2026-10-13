# Linux 特征码适配：756039

本次以 GCC 9.4 的客户端、服务器和 Lua 5.1 训练库为目标。训练库从
`Mod/bin64/linux/lib64/liblua51.so` 同步到签名工具及 Mod 使用的
`Mod/deps/liblua51.so`。CMake 的 `DS_LUA51_TRAINING_LIBRARY` 可指定其他训练库。

`lua_setexecutionerror`、`lua_getexecutionerror`、`lua_clearexecutionerror`、
`lua_settimeslice` 位于 `src/missfunc.txt` 排除列表，不定位或注入。execution-error
helper 的专用定位仍用于将引擎的存储槽连接到替换 VM。

带符号语义参考为早期 macOS DST 的 `dontstarve_steam_12527201`（x86_64）及
`dontstarve_steam`（i386）。先检查符号函数，再用注册字符串、调用关系、采样
事件与 TLS 访问交叉验证当前 Linux 二进制。以下地址都是未加装载偏移的 ELF RVA。

| 目标 | macOS x86_64 符号 | Linux 客户端入口 | Linux 服务器入口 |
|---|---|---|---|
| Lua 锚点 | `index2adr`，Lua 索引到 TValue 的转换 | `0x50f840` | `0x487700` |
| getsize 注册 | `luaopen_getsize`，`0x100195be8` | `0x1e6590` | `0x1c4a40` |
| execution-error helper | Lua 训练库 `lua_setexecutionerror` 与引擎对应 helper | `0x513480` | `0x48b340` |
| profiler push | `FrameProfiler::Push`，`0x100224a9e` | `0x43db10` | `0x3b67d0` |
| profiler push singleton 变体 | 同一方法的常量传播 wrapper | `0x43db30` | `0x3b67f0` |
| profiler pop | `FrameProfiler::Pop`，`0x100224cd4` | `0x43d690` | `0x3b6350` |

getsize 注册函数访问旧 Lua GC closure 布局，然后设置 `debug.getsize`。替换函数
保留其 Lua 栈合同。Linux 特征码命中函数中部后，从精确 `.eh_frame` FDE 范围
取得入口，并确认命中处是指令边界，不再使用固定 `-0x1f`。

新的 profiler 采样结构计数偏移为 `0x240`，旧版本为 `0x180`。
Push 被拆成检查 enabled 的公开 wrapper、singleton 变体和 `.part.0` 主体。
两个 wrapper 的 zone/source/line 仍位于 RSI/RDX/ECX，替换函数不使用 `this`。
两者一起替换，保留 stock profiler 关闭时也可采样的行为；部分安装失败时撤回。
Pop 的旧 `-0x15` 会落入 `ENDBR64` 内部；FDE 入口解析同时解决这个偏移问题。

游戏目录信息来自 `-persistent_storage_root`、`-config_dir`/`-conf_dir`、
`-cluster`、`-shard` 启动参数及引擎默认值。早期 macOS 有符号版本的参数解析
和 `PersistentStorage` 初始化提供语义依据。移除对旧 std::string 布局、固定
`mov esi,imm32`/`mov edi,imm32` 序列及 32 位绝对地址的依赖。

特征生成使用 Capstone 的 displacement/immediate 编码字段。零位移、REX、
额外前缀及 imm64 都保留正确的操作码，CALL/JMP 和地址引用按指令边界处理。
GCC 9 的 `.plt.sec`/`.plt.got` 以及 PLT 开头的 ENDBR/NOP 必须解析。GraphSeed
的模块接口和 ScanCtx 共用 PLT/GOT 目标规约，函数体检查、候选交集和首调用
筛选使用实际 callee；未绑定的 PLT 桩不进入注入候选。ELF 映射基址来自 PT_LOAD，而非
根据 `.text` 地址大小猜测 PIE。

CFG 发现和特征扫描曾将一些类型检查函数截断在第一个 RET（37 字节），遗漏
后续错误分支。特征扫描保留权威函数长度并包含后续分支；ELF 适配器用精确
FDE 范围确定已覆盖代码的边界，Nucleus 范围扣除 FDE 后的所有剩余区间
（包括跨边界尾部）继续保留；精确重复的区间去重，再按真实 FUNC 符号拆分；
匹配优先使用完整短函数体，调用图候选还必须排除训练图中不存在的额外 Lua API。

签名缓存即使版本一致，也须在当前地址验证存储字节。重新定位失败会报错，
不再恢复旧偏移后写入当前游戏版本。删除无效果的 luaG_errormsg 扫描；Windows
专用 FPS/RPC/VBPool 特征码不在 Linux 路径创建或扫描。

验证工具只把 ELF 数据映射为可读内存，应用内部 GOT 重定位以复现训练调用图，
不执行游戏代码、构造器或 Steam。它使用运行时同一套函数匹配及调用图补全，
并验证每个结果的字节特征、偏移和 FDE 入口。

```sh
cmake --build --preset ninja-vcpkg-debug --target verify_linux_signatures
ctest --test-dir builds/ninja-multi-vcpkg -C Debug -L linux_game_signatures --output-on-failure
```

也可调用 `verify_linux_signatures <lua51.so> <游戏二进制> [输出.json]`，
在全部条目通过验证后生成数据库。此检查不替代游戏内 VM 切换与 profiler 的
运行测试。

本次 Debug 构建通过，13 项相关回归测试通过；客户端和服务器数据库均为
756039、102 个 API，四个 Klei 扩展已排除。两个 Push 入口及其余 Linux 入口
均唯一命中并通过 FDE/指令边界检查。

完整 CTest 为 55/60：现有 `plugin_apply_offline` 的配置戳矩阵在 Linux 上断言
Debug/Release 必须拒绝，但生产兼容规则在非 Windows 下允许此组合；相关源码
和测试没有在本次修改。四项游戏烟测在沙箱外重试后仍受 Steam 初始化、服务器
认证及测试 Mod 强制启用条件影响，未获得完整的游戏内验证。

## Review 修复：缓存更新与共享库 ABI

偏移未变化的成功匹配也必须登记到 `known_functions` 和本次占用集合。
否则调用图排除额外 Lua API 的检查无法识别这些调用；同一二进制更新缓存时，
`luaL_loadstring` 曾从正确的 `0x51ef80` 被错改为 `0x5251d0`。
`verify_linux_signatures ... --check-cache` 先生成数据库，再清空并重建模块表，
更新该数据库并检查所有入口偏移保持一致。客户端、服务器都有此回归测试。

`MemorySignature` 恢复原来的数据成员布局（Linux x64 为 56 字节）。入口解析
改由新方法 `scan_function()` 显式选择，旧 `scan()` 符号及行为保持兼容。
`memory_signature_abi` 使用冻结的旧头文件编译消费者，链接当前共享库，并将
旧对象放在保护页之前，验证两个旧扫描方法不会读取对象之外。实际加载 Lua
库的测试同时覆盖新入口方法及 `pattern_offset` 行为。

后续 Debug 完整构建和 14 项相关测试通过，包含客户端、服务器的缓存更新
一致性检查，以及旧消费者对新共享库的保护页检查。
