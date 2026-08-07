# Design: 基于 **Nucleus（进树改工程面）** 的函数体区间

**Date:** 2026-08-07  
**Status:** Approved（用户 2026-08-07：vendor 进树 + 改工程面；算法面保留 Nucleus）  
**Scope:** 函数起点/体边界以 VUSec **[Nucleus](https://www.vusec.net/projects/function-detection/)**（*Compiler-Agnostic Function Detection in Binaries*, EuroS&P 2017）的 **CFG / 函数划分实现** 为唯一权威；以 **vendor 进树 + 修改工程面** 方式接入本仓库，供签名生成（pattern ⊆ body）与目标侧命中回退（`function_containing`）使用。

---

## 0. 集成形态（用户锁定）

| Decision | Choice |
|----------|--------|
| 算法归属 | **Nucleus** 的 CFG / 函数发现实现（`cfg.cc` 等主路径） |
| 产品形态 | **Vendor 进树**（`3rd/nucleus` 固定 revision），**不是**黑盒 so/dll 包依赖 |
| 允许修改 | **工程面 only**（见 §0.1） |
| 禁止修改 | **算法面**（见 §0.2）；禁止自研平行主算法 |
| 自研启发式 size / ret 探针 / 魔法距离 | **禁止**作为权威边界 |
| 回退 | **目标模块** Nucleus 区间；训练几何不用于目标回退 |
| Pattern | **必须 ⊆** Nucleus 函数体（BB 并集 / `[start,end)`） |
| pdata | **交叉验证 / 告警 only**，不能替代 Nucleus 主路径 |

### 0.1 工程面（**允许**改 Nucleus 树内代码）

| 区域 | 目的 |
|------|------|
| **Loader** | Windows：用本仓库 PE 映射填 `Binary` / `Section` / `bytes`，减少/去掉对 libbfd 的硬依赖；Linux 可保留 BFD |
| **构建** | CMake 目标 `nucleus_static`（或等价），进 `function_relocation` |
| **导出 API** | 稳定入口：如 `nucleus_analyze(path|image) → FunctionTable`；可去 CLI 硬依赖 |
| **Capstone 共存** | 与 Frida Gum 的 `cs_*` 协调（统一版本或静态隔离初始化） |
| **`3rd/nucleus/patches/`** | 通用 bugfix 以补丁文件记录；说明「为何不是算法分叉」 |

### 0.2 算法面（**原则上不改**）

| 区域 | 说明 |
|------|------|
| `CFG::make_cfg` / `find_functions` / `expand_function` 等划分主流程 | 保持 Nucleus 语义 |
| ICSCG / addrtaken / switch / padding 检测主逻辑 | 不替换为自研启发式 |
| 为个别符号（如 `lua_getstack`）写硬编码 entry | **禁止** |

若 Nucleus 在某类 PE 上系统性错误：

1. 优先 **通用修复**（属工程/边界情况，写入 patches 并说明），或  
2. **pdata 交叉告警** + 失败可见，  
**禁止** 在适配层 `if (name == "lua_getstack")`。

### 0.3 明确否决的形态

| 形态 | 否决原因 |
|------|----------|
| 纯黑盒依赖上游发布物 | Nucleus 无稳定库 ABI；Windows/签名场景不适配 |
| 「参考算法」在本仓库重写一版 | 易漂成自研启发式；维护与论文对照成本高 |
| 本地 next-export / 第一 ret / 0x1000 当权威 size | 已证导致 getstack 类错误 |

**一句话：**  
**算法归属 Nucleus；产品形态归属本仓库。依赖的是算法实现（进树可改 loader/导出），不是上游发布形态。**

---

## 1. Goals / Non-goals

### Goals

1. Vendor Nucleus 源码到 `3rd/nucleus`（固定 git revision + LICENSE）。
2. 工程面改造后，作为 **FunctionRelocation 的函数发现与体边界引擎**：
   - 输入：PE/ELF 路径或已映射映像  
   - 输出：`FunctionTable`：`{ start, end, bbs[] }` + `containing(addr)`
3. **签名契约**：
   - 生成：pattern **仅**来自 body  
   - 匹配：目标 raw match → 目标 `containing` → `pattern_offset` **仅目标几何**
4. Windows RelWithDebInfo 可编可链；工具 `signature_updater` 与运行时分析共用同一套区间源。
5. 验收：getstack 类「体同构」不得再因函数外地标 + 训练 po 写错 entry。

### Non-goals

- 自研与 Nucleus 平行的函数发现主算法。  
- 匹配层 per-symbol 硬编码作为正解（ReplaceApis 运行时特判另切片删除）。  
- 改写 Nucleus 论文级算法语义（仅工程面 + 经记录的通用 bugfix）。  
- 一次重写全部 Karta 打分。

---

## 2. 问题与 Nucleus 对齐（证据摘要）

| 事实 | 含义 |
|------|------|
| 训练 lua51 与游戏 **getstack 体** 一致 | 非游戏私改函数体 |
| 旧 pattern 唯一命中在 **体后邻函数 prologue** | 依赖链接排版的地标 |
| 训练 `pattern_offset` 搬到游戏 | 排版差 → 回退进 leaf stub |
| export 跨度 336 ≫ 真体 ~0x7a | **禁止** next-export 当 body |
| 自研线性 `function_limit` / ret 截断 | 半 CFG，不足以为权威 |

Nucleus 提供编译器无关的函数边界（CFG 向），用于替换上述权威来源。

---

## 3. Nucleus 能力（公开源码）

```text
Binary / Section / Symbol     // loader — 工程面可替换填充方式
DisasmSection
CFG::make_cfg(Binary*, disasm)
CFG::functions → Function { start, end, entry BBs, BBs }
BB { start, end, insns, ancestors, targets, padding, ... }
```

| 项 | 事实 |
|----|------|
| 上游形态 | 研究 CLI + Makefile，非 CMake 包 |
| 依赖 | Capstone；默认 libbfd 加载 |
| 许可 | BSD-3-Clause（可改源码再分发，保留版权） |
| 平台文档 | 偏 Linux → **我们必须做 Windows 工程面** |

---

## 4. 仓库架构

```text
3rd/nucleus/                 # 固定 revision 的 vendor
  LICENSE
  cfg.cc / function / bb …   # 算法面：默认不动
  loader.*                   # 工程面：可改为 PE 填充
  patches/*.patch            # 可选通用修复

cmake/Nucleus.cmake          # nucleus_static

src/FunctionRelocation/
  NucleusAdapter.*           # 调进树 Nucleus → FunctionTable
  FunctionTable.*            # containing / spans
  Signature.cpp              # 只消费 FunctionTable
```

```text
映像 → [工程面 Loader] → Binary
     → [算法面 make_cfg] → CFG.functions
     → FunctionTable
     → Signature gen / match resolve
     → (opt) pdata 交叉 log
```

### 4.1 Capstone

- Nucleus 与 Frida Gum 均可能使用 Capstone。  
- Plan 钉死：统一版本 **或** Nucleus 静态隔离；避免双初始化冲突。  
- **不**借 Capstone 问题改写函数发现算法。

### 4.2 pdata

- 有区间则与 Nucleus `[start,end)` 对比，冲突 **log**。  
- **权威：Nucleus**（用户锁定第三方算法）。  
- 无 pdata 的 leaf：完全 Nucleus。

---

## 5. 签名契约

### 5.1 生成（训练模块）

1. Nucleus 分析训练 DLL → `FunctionTable_train`  
2. export `S` → 对应 Function（entry/start）  
3. Body = 该函数 BB 并集（或一致时的 `[start,end)`）  
4. Pattern **仅** Body 内（相对寻址可 `??`）  
5. 训练模块上：唯一命中且 resolve 回同一 entry  

### 5.2 匹配（目标模块）

1. Nucleus 分析目标 PE → `FunctionTable_target`  
2. pattern **offset=0** 扫 match  
3. `entry' = containing(match)`  
4. 唯一；`pattern_offset = entry' - match`（**仅目标**）  
5. 失败则换 Body 内窗口；**禁止**训练 po 线性回退  

### 5.3 废除

- next-export size、训练 po 跨模块不变量、函数外唯一地标、匹配层硬编码/魔法距离。

---

## 6. 错误处理

| 情况 | 行为 |
|------|------|
| Nucleus 分析失败 | 错误可见；**禁止**静默启发式顶替 |
| export 无对应函数 | 该符号失败/跳过并 log |
| match 不落在任何函数 | 丢弃 |
| Loader/构建失败 | 构建期或运行期明确失败 |

---

## 7. 测试与验收

| 门禁 | 期望 |
|------|------|
| N0 | `nucleus_static` Win/本地可编译 |
| N1 | 对 `lua51.dll`：`FunctionTable` 非空；getstack export 落入合理函数；**end−start ≪ 336** |
| N2–N3 | pattern ⊆ body；目标 resolve 无训练 po |
| 重生 client | `lua_getstack` 入口字节与训练 export 同类（body），非 stub leaf |
| getinfo / open_io | 无回归 |
| 许可 | 分发保留 BSD 声明 |

---

## 8. 阶段（实现 plan）

| 阶段 | 内容 |
|------|------|
| **N0** | Vendor + CMake；工程面 loader（默认 **PE 填充 Binary**，算法面不动） |
| **N1** | `NucleusAdapter` + `FunctionTable`；单测/工具打印 getstack 区间 |
| **N2** | 签名路径权威区间改读 FunctionTable；去掉 next-export body |
| **N3** | Signature：⊆ body + 目标侧 resolve only |
| **N4** | 重生验收；删除临时硬编码向补丁；spec → Implemented |

---

## 9. 风险

| 风险 | 缓解 |
|------|------|
| 研究代码 Windows 不友好 | 工程面 loader/CMake；算法不重写 |
| 进树后与上游漂移 | 固定 revision；patches 目录可追溯 |
| Capstone 双份 | 统一或隔离 |
| Nucleus 误检 | 失败可见 + pdata 告警；通用修复进 patches |
| 误把工程改动做成算法分叉 | Code review 对照 §0.1 / §0.2 |

---

## 10. 决策摘要

1. **不是**黑盒包依赖，**不是**从零复述算法。  
2. **是** vendor Nucleus + **改工程面**（loader/构建/导出）+ **保算法面**。  
3. 签名只消费 Nucleus 体区间；回退只用目标表。  
4. 禁止硬编码兼容与自研主发现。  
5. N0–N4 分阶段；本 spec 批准后再 writing-plans。

---

## 11. Spec self-review

| Check | Result |
|-------|--------|
| 用户「改源码做集成」 | §0 锁定 |
| 用户「直接用算法」 | 算法面保留 Nucleus，非重写 |
| 禁止硬编码 | 多处写明 |
| Windows | PE loader 工程面默认 |
| 许可 | BSD-3 |

---

**请 review。**  
路径：`docs/superpowers/specs/2026-08-07-function-body-cfg-design.md`  

**批准前不写实现代码。** 批准后进入 `writing-plans`（N0–N4）。