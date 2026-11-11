---
name: dst-signature-updater-create-perf
description: "Diagnose and speed up DST signature_updater create (slow exports, Debug tool, needle scans, luaL_Reg/xref anchors)"
---

# DST signature_updater `create` 性能定位与加速

适用:`signature_updater create` 全量重建慢(数分钟)、少数函数吃掉绝大部分时间,需要定位并加速。
不适用:签名解析失败 / 偏移错误(见 `dst-signature-updater-triage`)。

## 1. 先拿基线,不要猜

```bash
# 计时 + 保存完整日志(工具日志默认被重定向到文件)
time builds/ninja-multi-vcpkg/tools/Creater/Debug/signature_updater.exe create > $TEMP/sigtool.log 2>&1
```

从日志按函数算耗时(每条 `try create signature [X]` → 下一条 `update signatures [X:...]` 的时间差),排序取 top5。
参考基线(2026-10,104 导出 × client+server):总计 341 s;`lua_setupvalue` 63+34 s、`lua_resume` 32+30 s、`luaL_ref` 17+16 s,三者占 192 s,其余 101 个 <3 s。

## 2. 关键陷阱:策略日志默认丢失

`src/FunctionRelocation/*.cpp` 里所有诊断日志走 `spdlog::get("FunctionRelocation")`,但 `tools/Creater/main.cpp` **没有注册这个 logger**,返回 null → `scan_by_short_body` / `scan_by_micro_windows` / `scan_by_unique_const` / `fix_func_address_by_signature` 全部无输出。
现象:日志里两个时间戳之间没有任何行,却耗时几十秒 → 不要臆测策略,先补观测:

- `main.cpp` 里 `spdlog::create<spdlog::sinks::stdout_color_sink_mt>("FunctionRelocation")`;
- 在三个策略函数入口/出口加 scope timer,输出 `strategy=... ms=... scans=... candidates=... votes=...`。

## 3. 已定位的结构性成本

`scan_by_short_body`(Signature.cpp):
- `leaf = original->size <= 256 ? size : effective_leaf_size()`;leaf>256 直接跳过;
- 先试 exact leaf + `create_signature` 的 32/24/16/12 窗口 + 固定 prologue;
- 再进“mid-body needle”循环:`len = 12..6` × 每个 `off`(off<8 跳过),每个候选做**一次 train 扫描 + 一次 target 扫描**;
- 训练体越小候选越少,但 train 只有 ~130 KB,几乎所有 needle 都“train 唯一”,于是大量候选都进 target 扫描 —— 该唯一性判据基本失效。

体量参考(参考 DLL `.pdata`):`lua_setupvalue` 37 B、`lua_resume` 190 B、`luaL_ref` 198 B。
另外工具是 **Debug** 构建(frida-gum `/Od`),扫描吞吐远低于 Release。

## 4. 加速顺序(收益/成本)

1. **Release 重编工具**(零代码改动,先做)
   `cmake --build builds/ninja-multi-vcpkg --config Release --target signature_updater`
   运行时把 PATH 指向 `vcpkg_installed/x64-windows-custom/bin`(Release deps,已存在)。
2. **索引化 needle 判定**(1–2 h)
   每次 run 对 target `.text` 建一次 8 字节窗口哈希 `{first_hit,count}`(~5 M 项);
   needle ≥8 字节时查其中央 8 字节:`count!=1` 直接淘汰,`==1` 只在该位置校验整条 needle + 现有几何约束。len<8 或跨通配时保留扫描兜底。
3. **luaL_Reg/xref 锚点前置**(2–4 h)
   现在的顺序是「逐函数盲扫 → 全部扫完才跑 call-graph seed」,应反过来。
   - 训练侧解析 `lua51.dll` 的 `.rdata` luaL_Reg 行 `{name_ptr, func_ptr}`;
   - 目标侧同行扫描(游戏已重定位,`name_ptr`→`.rdata` 字符串,`func_ptr` 落在 `[luaBase, text_end]`);
   - 目标 wrapper 的 E8 目标(深度 ≤2,未 claimed)∩ 训练 wrapper 的调用名 → 直接得导出地址。
   已验证链:`{"setupvalue",0x140495570}` → `db_setupvalue` 0x1404955d1 `E8` → `lua_setupvalue` 0x140483940(全 exe 唯一直接调用者);`getupvalue` 同理;`{"resume",0x14049b7e0}` → `luaB_coresume` → `auxresume 0x14049b761` → `lua_resume 0x1404892a0`。
   `luaL_ref` 有 61 个直接调用者 → 该通道不适用,走索引或“唯一常量”通道。
4. **策略重排**:`scan_by_unique_const` 提到 `scan_by_micro_windows` 之前(小函数 micro-window vote 集合可能极大)。
5. **并行**:client/server 本来就是串行两遍,先跑两个进程即可砍半;函数级并行需先拆开 `set_known_function`/`claimed_this_pass` 共享写。
6. **剩余地板**:三函数解决后约 150 s 花在 nucleus 分析 + pdata 交叉校验(后者是 O(spans×ranges),可改排序+二分)。

## 5. 验收

- 新 `signatures_client.json` / `signatures_server.json` 与优化前 **104 条逐条一致**(offset / pattern / pattern_offset);
- 单函数解析 <100 ms;总时长目标 <45 s;
- 独立复核:`[Lua base, .text end]` 内每条 pattern 唯一且 `hit + pattern_offset == base + offset`。
  客户端 Lua base RVA `0x482210`,服务端 `0x41B110`(同一游戏版本内可从任一已知函数反推:`base = target - offset`;注意 1312/5792/7648 是相对该 base 的偏移,不是模块基址)。

## 6. 常见误判

- 用 `Mod/deps/lua51.dll` 的导出 RVA 直接对比游戏地址会差一个 0x30:签名库 offset 相对 **Lua 模块基址**,不是 exe 基址。
- 二进制字符串搜索 `"msvcr90.dll"` 区分 /MD、/MT 要用导入表解析,大小写敏感。
