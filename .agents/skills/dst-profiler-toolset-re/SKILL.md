---
name: dst-profiler-toolset-re
description: Reverse-engineer DST TheSim:Profiler* / FrameProfiler toolset across platforms with Ghidra MCP; not for LuaJIT jit.profile or unrelated profiling.
---

# DST profiler 工具集逆向 (Ghidra MCP)

目标: 说清 `TheSim:ProfilerPush/ProfilerPop`（及 ProfilerLoad*, Toggle*Profiler, Profile, SendProfileStats, GetProfilerData）在某个平台构建里到底做什么、底层工具集是什么、怎么用。

## 入口清单（luaL_Reg 表定位法）

不要按 RVA 找；先在 Ghidra 里搜字符串/函数名定位**注册表**，再从表项读函数指针。

1. `search_strings` term = `Profiler` → 拿到名字字符串地址与 mangled 符号（`_ZN11SimLuaProxy12ProfilerPushEP9lua_State`）。
2. `get_xrefs_to` 名字字符串地址 → 命中 `[DATA]` 表项地址（Android 上为 `.data.rel.ro`）。
3. `read_memory` 读表项附近 0x100 字节: 表结构 = `{const char* name; void* func; ...}` 步长 0x20（Android），name/func 相邻两个指针。
4. `decompile_function`/`disassemble_function` 验证 func。

要覆盖的名字: `ProfilerPush`, `ProfilerPop`, `ProfilerLoadPush`, `ProfilerLoadPop`, `ToggleFrameProfiler`, `ToggleDataProfiler`, `Profile`, `SendProfileStats`, `GetProfilerMetaData`, `ViewNetProfile`。

注意 `|` 交替正则不被支持，`search_functions` 是字面子串匹配 —— 一次只搜一个名字。

## 判定「是否被裁掉」

- `disassemble_function` 出来是 `mov w0,wzr; ret`（AArch64）/ `return 0`（C, `ret`）→ 空壳。
- 必须找**旁证**排除 Ghidra 误判: 同表里取一个功能函数（如 `SimLuaProxy::SpawnPrefab`）确认是完整实现; 并 `search_strings` 搜 `profile_%03d` / `ProfileIndex:%.2f` / `Profiler started.` / `FlushToDisk` / `StartRecording`，全空即整族被裁。
- 下游驱动也要查: `cSimulation::Profile`、`cSimulation::HandleProfiler`、`cSimulation::SendProfileStats`。

## 真实工具集形状（PC 构建）

- `FrameProfiler` 单例 + `FrameProfilerSection` (RAII: ctor→Push, dtor→Pop) + `cSimulation` 计时驱动。
- `FrameProfiler`: `Push(name,__FILE__,__LINE__)`, `Pop`, `StartRecording(bool bumpIndex)`, `ToggleRecording`, `FlushToDisk`, `WriteHeader`, `GetSpinTime`。
- 每线程 TLS `SampleStack`；样本 0x1c 字节 `{name, tid, ts_us, ph('B'=0x42/'E'=0x45), src_file, src_line}`；全局 `sThreadIDs` + `sProfileLock`。
- 分块: `dwProfileCount > 0x3c00`(15360) 且发起线程深度归零 → 停录 + `FlushToDisk` + `StartRecording(true)`。
- 输出: `<donotstaredir>/profile.json`（`nFileIndex==0`），否则 `profile_%03d.json`；Chrome Trace Event JSON `{"traceEvents":[...]}`，`cat:"dont_starve"`，`B` 事件带 `args.src_file/src_line`；首文件写 `metadata` 伪事件，args 来自 `mDataFunc` = `LuaIntegration::GetProfilerData`（含 Lua 全局 `GetProfilerMetaData()` 键值）。
- 起停: `TheSim:ToggleFrameProfiler()` → `ToggleRecording`；`TheSim:Profile(secs)` 打印 `Profiler started.`，`HandleProfiler(dt)` 倒计时归零后停录并 `print("Profiler stopped - profile located at <dir>/profile.json")`。

用 `get_xrefs_to` 对 `FrameProfiler::Push` 列出引擎自动插桩点（渲染/世界更新/网络解析等主循环段），这比逐个翻函数快。

## 三平台基线（DST 1.1.28 一代，作对照锚点）

| 项 | Android libDontStarve.so | Windows x64 发布 | mac dev 32-bit |
|---|---|---|---|
| ProfilerPush/Pop | 空壳 `0x008a06d0/0x008a06e0` | 真 `0x140129080`→`FUN_14042b0d0` | 真 `0x000ed488`/`0x000ed4de` |
| ProfilerLoadPush/Pop | 空壳 `0x008a06d8/0x008a06e8` + WorldSimActual `0x00896988/0x00896990` | 有 | ‑ |
| ToggleFrameProfiler | 空壳 `0x008a9eb0` | 空壳 `FUN_140007700` | 真 `0x000f29b2` |
| ToggleDataProfiler | 空壳 `0x008a9eb8` | 空壳 `FUN_140007700` | 空壳 `0x000f29d2` |
| cSimulation::Profile/HandleProfiler/SendProfileStats | 全 `ret` `0x008895fc/0x00889600/0x0088dc60` | 真 `FUN_140101a40` | 真 `0x000fbb16` |
| GetProfilerData | 真 `0x00885734`（索引值为空串） | 真 | 真 `0x000f64cc` |

结论表述要点: 移动端保留 Lua API 面与「元数据上报」通道（`GetProfilerData` 导出符号 + `GetProfilerMetaData`），采样器整体裁掉 —— 调用 `TheSim:ProfilerPush/Pop` 在 Android 上无任何副作用。

## 陷阱

- 程序有 overlay space（`has_overlay_spaces=true`）时地址可能重复出现在 `.plt` 区间；确认地址落在 `.text` 再下结论。
- `.plt`/`eh_frame`/`.gcc_except_table` 的 `[DATA]` xref 不是调用点，别当调用者。
- 不要把「Toggle 是空壳」等同于「整个采样器被裁」：Windows 发布版 Toggle 空壳但 Push 真实存在。
