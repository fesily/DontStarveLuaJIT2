---
name: dst-game-perf-etw-jit-symbols-round
description: 跑一轮 DST 专用服务器 perf 并验收 LuaJIT JIT 符号进 native ETW 报表：重建 Release VM、run.py --sample-native、定位 ETL/pid、xperf tracestats、离线 IP-in-range 归因、WPA 人工步骤与实测坑（裸路径 chunk 名/占比低/共享 GUID）。
---

# When
在 `C:/Users/fesil/DontStarveLuaJIT2` 需要**真跑一轮游戏 perf**(专用服务器 worldgen/startup)并且要 native ETW 栈 + LuaJIT JIT 符号(WPA/PerfView/TraceEvent 消费),或要核对某轮 ETL 里到底有没有 JIT 符号时。

不适用:只跑 LuaJIT 侧的 ETW 集成测试(`luajit/test/etw_symbols.c` / `verify_jit_symbols.py`),见 `tests/performance/README.md` 的 *JIT symbols in WPA / PerfView*。

# 0. 前置(顺序不能错)

- **改了 `luajit/src/lj_*.c` 就必须先重建 Release VM**,否则游戏里跑的还是旧 DLL:
  `python tests/performance/build_release.py`(约 15 s,同时重写 `builds/game-performance-vm-release/luajit/lua51DS.dll.performance.json` 的 hash 证据;runner 会校验它)。
- Release Injector 用现成的 `builds/game-performance-runtime-release/src/DontStarveInjector/Release/Injector.dll`(改 VM 源码不影响它)。
- `--sample-native` 需要管理员:runner 内部经 Windows `sudo` 起 WPR(弹 UAC);非管理员 `wpr -start` 失败签名 `0xc5585011`。
- 命令要在 `vcvars64.bat` 环境里跑(CMake/Ninja 在 VS 包内,不在 PATH)。

# 1. 跑一轮

```cmd
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d C:\Users\fesil\DontStarveLuaJIT2
python tests\performance\run.py --profile worldgen --worldgen-jit on --sample-native ^
  --warmup 0 --repeat 1 ^
  --vm luajit=builds/game-performance-vm-release/luajit/lua51DS.dll ^
  --injector builds/game-performance-runtime-release/src/DontStarveInjector/Release/Injector.dll ^
  --output builds/game-performance/<name>
```

- `--vm LABEL=<dll>` 会**同时**跑 baseline `game` 轮(game 自带 Lua,无我们的 provider)⇒ 一轮 ≈2 min,这本身就是"改前/改后"的自然对照。
- `--worldgen-jit on` 只作用于 vm group(基线轮是 off);单轮计时**不是**加速结论,按 README 要成对多轮。
- gameplay 阶段用 `--profile startup`;`--sample-lua`/`--jit-diagnostics` 会扰动时序,别用于符号验收(它们不是 ETW 符号消费者)。
- 长跑放 bat 里重定向日志,再 `grep -E "perf\] (RUN|SUMMARY|PASS|FAIL)"`;`[perf] PASS: <output>/results.json` 才算成功。

# 2. 产物定位

| 文件(在 `<output>/`) | 用途 |
|---|---|
| `round-0-<label>-native.etl` | label = `game`/`luajit`;WPA 打开的输入 |
| `round-0-<label>-native-samples.json` | **含 `pid`**、`session`、`boundaries`(MAP_BEGIN/END、phase) |
| `round-0-<label>-native-start.json` / `-stop.json` | WPR receipts(returncode=0、ETL 已保存) |
| `results.json` / `results.csv` | 计时 + 与 baseline 的对比 |

再 `python tests/performance/analyze.py <output>` → `hotspots.json`、`round-0-<label>-native.csv`、`-native.stats.txt`、`.images.csv`、`.export.json`。

# 3. 验收:符号有没有进 trace

```cmd
xperf -i <output>\round-0-luajit-native.etl -a tracestats        :: Lost Buffers/Events 必须 0
python tests\performance\verify_jit_symbols.py ^
  --exe builds\game-performance-vm-release\luajit\luajit.exe ^
  --out builds\_jitcap\<name> ^
  --etl <output>\round-0-luajit-native.etl --pid <samples.json 的 pid>
```

离线模式免提权:该脚本用 `xperf -a dumper -stacktimeshifting` 出 CSV,解 CSV 里 `Microsoft-JScript/…` 行的 `MethodStartAddress/MethodSize/MethodName`(WPT 已按 OS manifest 展开字段名),再把该 PID 的 SampledProfile PC 落进 `[addr, addr+size)` 的样本归到 trace 名;`summary.json` 有 `event_counts`/`jit_ranges`/`resolved_trace_names`/`verdict`。

判据:luajit 轮有大量 `9/41`,且 `samples_in_trace_range > 0`、`resolved_trace_names` 出现 `LuaJIT::TRACE_<n>::<chunk>:<line>`;**baseline `game` 轮同 provider 行数应为 0**(最干净的对照)。

WPA 人工验收(无 CLI):打开 luajit 轮 ETL → *CPU Usage (Sampled)* → `Process` 列过滤 `dontstarve_dedicated_server_nullrenderer_x64.exe (pid)` → Stack/符号列看 `LuaJIT::TRACE_…::scripts/…lua:<line>`;*Generic Events* 里 provider `Microsoft-JScript` 核对记录。

# 4. 实测坑

- **DST 传的 Lua chunk 名是裸路径**(`scripts/util.lua`,无 `@`)⇒ chunk→符号名映射必须保留裸路径,否则游戏侧名字全部退化成 `(string):<行>`(只剩行号);只有源码文本/超长名才折叠成 `(string)`。
- worldgen 的 trace 内样本占比极低(≈0.8%,11143 里 93):窗口含整个服务器启动,map generation 只有 ~1.7 s 是 JIT 热区;占比低 ≠ 符号化失败。
- `Microsoft-JScript` 是**共享 GUID**,同机所有 Chakra 宿主(Edge/WebView2)也往里写;按 PID 过滤,别拿总行数当结论。
- 残留的启用中会话会让后续 run 丢事件:先 `logman query -ets | findstr /i <prefix>` 清自己名下的会话再重跑。
- `<output>` 里的 CSV 可能几百 MB(215 MB ETL → ~500 MB CSV);分析完可删 CSV,ETL 与 receipts 留作证据。
