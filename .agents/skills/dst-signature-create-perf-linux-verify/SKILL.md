---
name: dst-signature-create-perf-linux-verify
description: "Diagnose/accelerate DST signature_updater create and verify the result on WSL/Linux against the real game (LD_PRELOAD, A/B with pristine sources)."
---

# 何时用

需要加速或验证 `signature_updater create`(DST 签名库生成),或要在 WSL/Linux 上复核签名相关改动时。

# 1. 先定位耗时(不要猜)

- 工具是 Debug 还是 Release?`builds/<preset>/tools/Creater/<cfg>/signature_updater.*`;**必须 Release**(Debug capstone `nucleus_disasm` ≈26.8 s/模块 vs Release 3.3 s)。
- 策略日志不在 stdout:由 `init_ctx()` 创建的 `"FunctionRelocation"` logger 写到 `<主模块目录>/FunctionRelocation.log`。工具里**不要**再 `spdlog::create` 同名 logger(抛异常 → Debug CRT 模态断言框 → 进程挂死,表现为 RC=3 且日志为空)。需要控制台时给已存在 logger 追加 stdout sink。
- 加 `PhaseClock`/阶段计时的位置:`Signature.cpp` 的 `scan_by_short_body`/`scan_by_micro_windows`/`scan_by_unique_const`,`DontStarveSignature.cpp` 的 init/nucleus/apply/scan_features/pdata 各阶段。

# 2. 已知的二次方热点(优化前先看这里)

| 热点 | 症状 | 修法 |
|---|---|---|
| `FunctionTable::span_containing` 全表回扫 | 单函数几十秒,候选数 × 4e5 | 层叠(laminar)判定 + 首个覆盖目标即返回;非层叠保留原 tightest-wins |
| `FunctionTable::add` 逐条有序插入 | 4e5 span 装载慢 | 批量 `assign()` 一次排序 |
| `find_function` 线性遍历 `std::list` | 每候选 ms 级 | 先查 `address_functions` |
| pdata 交叉校验 spans×ranges | 每模块 ~23 s | 按 start 排序 + 前缀最大 end 反向查找 |
| needle 搜索每候选扫 train+target | 每个候选两次 `gum_memory_scan` | 8 字节窗口哈希 + 4 字节 postings,保留字节扫描回退 |

改完必须证明输出不变:同一游戏二进制重跑 `create`,与旧 JSON 逐条 diff(应为 0),并保持 `pdata compared/mismatches` 数值一致。

# 3. Linux/WSL 交叉验证流程

```bash
# 复制(排除重物;约 4 GB / 8 GB 目标)
rsync -a --exclude .git --exclude builds --exclude vcpkg_installed --exclude .venv \
  --exclude tools/angle --exclude tools/frida --exclude 3rd/angle \
  --exclude 3rd/frida-gum-build --exclude vcpkg/buildtrees --exclude vcpkg/packages \
  --exclude vcpkg/installed --exclude vcpkg/.git /mnt/c/<repo>/ ~/dst/

cd ~/dst/vcpkg && ./bootstrap-vcpkg.sh -disableMetrics
cd ~/dst && cmake --preset ninja-multi-vcpkg
```

- `cmake/GameDir.cmake` 是 `tools/update_steam_paths.py` 生成的机器相关文件;WSL 里手写指向 `~/.steam/.../Don't Starve Together`(路径含单引号,用 heredoc 写,别用 printf 拼)。**不要提交**该文件。
- 铺训练库:`cp Mod/bin64/linux/lib64/{liblua51.so,lua51} Mod/deps/`。
- 端到端:`cmake --build builds/ninja-multi-vcpkg --config Release --target create`(内部 `LD_PRELOAD=libsignature_updater.so` 注入游戏客户端与专服两个二进制)。无显示器也能跑,构造函数里起线程做完就 `exit()`。
- 独立校验:解析 ELF 段头取 `.text`,对每条 pattern 在 `[Lua base, .text end]` 内做通配扫描,要求唯一且 `hit + pattern_offset - offset` 全库等于同一 base(WSL 副本实测 client base 0x4aad50 / server 0x41ef90)。
- **A/B 等价性**:`git show HEAD:<file>` 取回改动前的 `FunctionRelocation/{FunctionTable.hpp,ModuleSections.hpp/.cpp,Signature.cpp,NucleusAdapter.cpp}` 覆盖 → 重编 → 跑 create → 与优化版 JSON 对比(应 0 diff)。

# 4. 陷阱

- 全仓 rsync 比对时,唯一“差异”通常是**被跟踪的** `__pycache__/*.pyc`(Python 版本不同),不是源码漂移。
- `src/missfunc.h`、`src/modinfo.hpp`、`src/DontStarveInjector/GameLuaInjectFramework.c` 是构建生成物(未跟踪),两平台只差行尾。
- Linux 训练库只有 102 个导出(缺 Klei 的 `lua_setfuncchunkname/getfuncchunkname`),Linux DB 因此是 102 条,不是 Windows 的 104;这是既有差异,不是回归。
- `Mod/deps/lua51.dll` 需要 `/Ob2`(内联与游戏一致),否则 `luaL_pushresult`/`lua_getupvalue`/`lua_isstring` 无法字节匹配,会退化到 graph-seed 并把 `luaL_prepbuffer` 误判成 `lua_isstring`。
