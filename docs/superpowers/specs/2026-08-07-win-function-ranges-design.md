# Design: Windows-first 权威函数区间（`.pdata` / `RUNTIME_FUNCTION`）

**Date:** 2026-08-07  
**Status:** Implemented (Win-first enumerator + ScanCtx seed + signature snap)
**Scope:** 改进 `FunctionRelocation` 在 **Windows x64** 上的函数起点/长度获取策略：以 `.pdata` 的 `RUNTIME_FUNCTION` 为权威区间源，降低启发式 `guess_function_size` / call-graph 误把 **stub / 函数中部** 当起点的概率；为后续修正 `signatures_*.json` 生成与删除 `ReplaceApis` 内 getstack/getinfo 特判打地基。

**User-locked choices (review):**

| Decision | Choice |
|----------|--------|
| 范围 | **2 — A-win-first**：只做 Windows 权威区间；Linux/macOS 二期 |
| 权威源 | **`.pdata` 的 `RUNTIME_FUNCTION` 表**（`BeginAddress`/`EndAddress`）；`UNWIND_INFO` 仅用于 **chained** 合并 |
| 启发式 | **补洞 only**：不得覆盖已有权威 `size` |
| ReplaceApis 特判 | **本切片不删**（`lua_getstack +0x20` / `lua_getinfo` 探针先留；签名模块修好后再删） |

**Amends / related:**

| Prior | Relation |
|-------|----------|
| `src/FunctionRelocation/ScanCtx.cpp` `scan_pre_text_range` / `pre_function` / `guess_function_size` | 本设计改造的主路径 |
| `src/FunctionRelocation/ModuleSections.{hpp,cpp}` 已有 `pdata` 字段 | 复用，不新造 section 探测 |
| `plugin_core_vm` `ReplaceApis` 运行时特判 | 消费者；本切片不改业务，只改善上游区间质量 |

---

## 1. Goals / Non-goals

### Goals

1. Windows x64 上，对每个有 `.pdata` 条目的函数，得到可靠的 **`[start, end)`**（`start = image_base + BeginAddress`，`end = image_base + EndAddress`，chained 见 §3）。
2. `ScanCtx::pre_function` / `init_module_signature` 产出的 `Function.address` / `Function.size`：**有权威条目时优先用权威 size**，不再被 `guess_function_size` 覆盖。
3. 提供可单测的解析层（合成或真实 `.pdata` fixture）：chain 合并、Begin/End、空表降级。
4. 签名更新路径具备 **snap-to-range-start** 能力（pattern 命中落在区间内时，canonical start = 区间 start，重算 `pattern_offset`）——至少 API + 一条调用点接好；全量重生成 signatures 可放同切片或紧随 plan 的验证步。
5. 无 `.pdata` 或解析失败时：**fail-soft 回退旧启发式**，打明确日志，不中断注入。

### Non-goals

- Linux `.eh_frame` 权威 size、macOS `LC_FUNCTION_STARTS` / `gum_darwin_module_enumerate_function_starts`（二期；接口预留即可）。
- 删除 `GameLua.cpp` `ReplaceApis` 内 getstack/getinfo 特判（等签名生成验证通过后再单独清理）。
- 重写 Karta / `fix_func_address_by_signature` 整套匹配算法。
- ARM / WoA；本切片仅 **x64 PE**。
- 依赖 PDB / 私有符号服务器。
- 把 `UNWIND_INFO` 当「函数目录」主表（它不是）。

---

## 2. 问题陈述（现状）

### 2.1 权威源事实

| 结构 | 作用 |
|------|------|
| **`.pdata` → `RUNTIME_FUNCTION`** | PE x64 **主** 运行时函数表：`BeginAddress`、`EndAddress`、`UnwindData`（均为 image-relative RVA） |
| **`UNWIND_INFO`（`UnwindData` 指向）** | 展开码、flags、**chained unwind** 信息；**不是**全量函数起止目录 |

结论：用户方向正确——应用 **`.pdata` 表** 建区间；`UNWIND_INFO` 只服务 **chain 合并**，不是「UNWIND_INFO 内嵌全部函数表」。

### 2.2 当前实现缺口

`ScanCtx.cpp` 已遍历 `.pdata`，但：

1. 只把 `BeginAddress` 写入 `sureFunctions`（权重 0），**未把 `EndAddress - BeginAddress` 写成权威 `Function.size`**。
2. 相邻 `EndAddress == next.BeginAddress` 时做了 vector 拼接容器，**未建成「逻辑函数」的合并 `[first.Begin, last.End)`** 并下发 size。
3. 后续仍大量依赖：
   - text 内 `E8/E9` 扫描
   - 反汇编挖 call/jmp
   - `guess_function_size`（遇 ret/jmp 启发式截断）
4. 结果：签名 pattern 可能落在 **5 字节 stub**（如 `movzx; ret` + INT3）上，offset 钉死错误入口 → `ReplaceApis` 只能运行时 `+0x20` 补丁。

### 2.3 目标因果链

```text
错误: pattern/offset → stub → Hook(stub) → 真 body 未替换
正确: 权威 [start,end) → offset 对齐 start → Hook(真入口)
```

---

## 3. 设计

### 3.1 模块边界

在 `FunctionRelocation` 内新增（命名可微调，职责固定）：

```text
FunctionRanges.hpp / FunctionRanges.cpp   # 或并入 ModuleSections，但须可单测

struct FuncRange {
  uintptr_t start;   // VA
  uintptr_t end;     // VA exclusive-ish: EndAddress 语义与 PE 一致（通常为函数末尾下一字节 RVA）
  enum class Source { Pdata, HeuristicFallback };
  Source source;
};

// Windows: 从 ModuleSections.pdata 解析；非 Win 返回空 + 调用方可走旧路径
bool enumerate_function_ranges_win(const ModuleSections& m, std::vector<FuncRange>& out);
```

**约束：**

- **不**让 `ScanCtx` 再直接手写 12 字节步进逻辑（现有循环迁入 `enumerate_function_ranges_win`）。
- `ModuleSections.pdata` 继续由 `get_module_sections` 填充（已有）。

### 3.2 Windows 解析规则

对 `pdata` 内存按 **12 字节** 步进读 `RUNTIME_FUNCTION`：

1. `BeginAddress == 0` → 视为表结束（与现逻辑一致）。
2. 校验 `image_base + Begin/End` 落在 `text`（或至少 module range）；失败条目 skip + count，不整表失败。
3. **Chain 合并：**
   - 若下一条 `BeginAddress == 当前逻辑函数累计 EndAddress`，并入同一逻辑函数（与现 `runtime_functions` 相邻拼接意图一致）。
   - 可选加强：读 `UNWIND_INFO` 的 `UNW_FLAG_CHAININFO` 确认 chain（实现若成本低则做；v1 允许「仅相邻 End==Begin 合并」，文档标明与 MSVC 常见布局一致）。
4. 输出：`start = base + first.Begin`，`end = base + last.End`，`source = Pdata`。
5. 排序、去重 start；同 start 取更长 end。

### 3.3 接入 `pre_function` / `scan`

**新顺序（Windows）：**

```text
1. ranges = enumerate_function_ranges_win(m)
2. 若 ranges 非空:
     对每个 range:
       sureFunctions[start] = max(existing, kPdataWeight)  // 例如 2，高于裸 call 的 1
       建立/更新 Function{ address=start, size=end-start } 到 address_functions / 扫描上下文
     权威 size 标记：禁止 guess_function_size 覆盖
3. 保留 E8/E9 + 反汇编启发式:
     仅当候选地址 **不落在任何已有 range 的 [start,end)** 内，才考虑新增 sureFunctions
4. 对 **无权威 size** 的起点，才调用 guess_function_size
5. 无 pdata / ranges 空:
     log: "function_ranges: fallback heuristic (no pdata)"
     完整走现有 pre_function 路径
```

**Linux/macOS：** 本切片不改行为；可在头文件留 `enumerate_function_ranges` 分发桩（非 Win 返回 false）。

### 3.4 签名路径：snap-to-start

在 `DontStarveSignature` 更新/扫描（`update_signatures` / pattern 命中后）增加：

```text
hit = scan_address
if (range = find_range_containing(hit)):
  canonical = range.start
  signature.pattern_offset = hit - canonical   // 或按现有约定符号
  target = canonical
else:
  保持现有逻辑（export known / try_fix_func_address）
```

**目的：** 即使 pattern 落在函数中部或 stub 邻近，只要区间正确，JSON 里的 **offset 钉在真入口**。

本切片要求：

- `find_range_containing` API 可用；
- **至少一处**签名更新路径调用（与现 `refix signature pattern offset` 同级日志）。

全量重刷 `Mod/deps/signatures_client.json` 可作为验证步骤，不强制在同一 commit 手改 100+ 符号。

### 3.5 与 `ReplaceApis` 的关系

| 组件 | 本切片 |
|------|--------|
| `lua_getstack` stub +0x20 | **保留** |
| `lua_getinfo` `80 3a 3e` 探针 | **保留** |
| null export / trampoline 校验 | **保留** |

删除条件（后续切片，不在本 spec 实现）：

1. 用新逻辑重生成 client signatures；
2. 对照：`lua_getstack` offset 的入口字节 **不是** `0F B6 ?? ?? C3` stub，或 stub 的 range.start 已是真 body；
3. 游戏烟测 LOADING LUA 无 AV；
4. 再删特判。

---

## 4. 数据流

```text
get_module_sections(path)
  → ModuleSections.pdata {base,size}

enumerate_function_ranges_win(m)
  → vector<FuncRange>  // Pdata

init_module_signature / ScanCtx::pre_function
  → Function.address/size 权威填充
  → sureFunctions 高权重 seed
  → 启发式仅补洞

signature update (pattern hit)
  → find_range_containing(hit)
  → snap start + 重算 pattern_offset
  → signatures_*.json offset 更接近真入口

(未来) ReplaceApis
  → 去掉 per-symbol 启发式
```

---

## 5. 错误处理 / 降级

| 情况 | 行为 |
|------|------|
| `pdata.size == 0` | fallback 启发式 + `spdlog::warn` |
| 单条 RVA 越界 text | skip 该条，累计 `skipped`；其余继续 |
| 整表解析异常 | fallback 启发式，不抛到 Inject 顶层 |
| chain 无法判定 | 按相邻 End==Begin 合并；无法合并则每条独立 range |
| 非 Windows | 不调用 win 解析；行为与现网一致 |

**Fail-fast 不适用**于此可选增强：签名/扫描失败不应比现状更脆。

---

## 6. 测试门禁

### 6.1 单元（CTest，无游戏）

| 用例 | 期望 |
|------|------|
| 合成 2 条独立 `RUNTIME_FUNCTION` | 2 个 range，start/end 正确 |
| 合成 chain（`r1.End == r2.Begin`） | **1** 个逻辑 range，`start=r1.Begin`，`end=r2.End` |
| `BeginAddress==0` 终止 | 不读垃圾后续 |
| 空 pdata | `enumerate` 返回 false/空，调用方 fallback 路径可测 |
| `find_range_containing` | 命中中部 → 返回该 range；区间外 → 空 |

Fixture：手写字节数组或最小 PE 切片进测试资源；避免依赖本机游戏路径。

### 6.2 手工 / 半自动（有游戏或有 `dontstarve_steam_x64.exe`）

| 检查 | 期望 |
|------|------|
| 对游戏主模块或已加载 lua51 模块枚举 | `ranges.size() > 0` |
| 已知 export（若有）或先前错误的 `lua_getstack` 地址 | 落在某 `range.start` 或 range 内且 snap 后为 start |
| 重跑签名更新后日志 | 出现 snap/refix；getstack 不再依赖盲扫 |

### 6.3 回归

- 现有 `FunctionRelocation` / signature 相关 CTest 全绿。
- `plugin_core_vm` RelWithDebInfo 可链（接口变更若暴露到头文件，注意 export）。

---

## 7. 实现切片建议（供后续 plan，本 spec 不实施）

| 序 | 内容 | 验收 |
|----|------|------|
| W1 | `FuncRange` + `enumerate_function_ranges_win` + 单测 fixture | 6.1 绿 |
| W2 | `pre_function` 接入权威 size；guess 不覆盖 | 日志 + 单测/调试打印 size 一致 |
| W3 | `find_range_containing` + 签名更新 snap 一点接入 | 一次真实模块更新日志可见 snap |
| W4 | 文档：`docs` 短注或本 spec Implemented；**不**删 ReplaceApis 特判 | review 清单勾选 |

---

## 8. 风险

| 风险 | 缓解 |
|------|------|
| 部分函数无 pdata（极端手工汇编） | 启发式补洞保留 |
| Chain 规则过简误合并 | v1 相邻 End==Begin；单测 + 可选 UNW_FLAG |
| `EndAddress` 与「最后一条指令后」语义和 disasm limit 差 1 | 统一按 PE 文档；scan 上限用 end，与现 `functions[i+1]` 对齐 |
| 签名 snap 改变大量 offset | 需版本 bump / 重生成；本切片可不强制提交新 JSON |
| 运行时模块 rebase | 全程用 VA = base + RVA；base 来自 `ModuleSections.details.range` |

---

## 9. 决策摘要

1. **权威：** Windows = `.pdata` `RUNTIME_FUNCTION` 区间；不是「只读 UNWIND_INFO」。  
2. **范围：** Win-first；Linux/mac 二期。  
3. **启发式：** 补洞；不覆盖权威 size。  
4. **签名：** snap-to-range-start 接入更新路径。  
5. **ReplaceApis 特判：** 先留，签名验证后再删。  
6. **降级：** 无 pdata → 旧路径 + warn。

---

## 10. Spec self-review

| Check | Result |
|-------|--------|
| Placeholder / TBD | 无开放 TBD；chain 的 UNW_FLAG 为可选加强并写明 v1 默认 |
| 与代码矛盾 | 承认现有已读 pdata 但未用 End；设计是加强而非虚构新源 |
| 范围 | 仅 Win + FunctionRelocation/签名 snap；不碰插件 ABI |
| 歧义 | `End` 按 PE `RUNTIME_FUNCTION.EndAddress`；逻辑函数 = chain 合并后的 `[first.Begin, last.End)` |

---

## Residual (not this slice)
- Linux eh_frame size / macOS LC_FUNCTION_STARTS
- Delete GameLua ReplaceApis getstack/getinfo workarounds after regenerating signatures_client.json and smoke
- Optional UNW_FLAG_CHAININFO confirmation beyond adjacent End==Begin

---

**Implemented.** Path: `docs/superpowers/specs/2026-08-07-win-function-ranges-design.md`
