---
name: dst-macos-i386-to-x64-symbol-migration
description: DST macOS 跨架构符号迁移（r181048 i386 → r759671 x86_64）走 Ghidra MCP：特征导出、通道取舍、落名/回退规范、精度验证。
---

# DST macOS 跨架构迁移：i386 r181048 → x86_64 r759671

适用：Don't Starve Together macOS 旧版（i386，符号完整）向新版（x86_64，符号稀疏）补函数名。
**不是**同架构同步；单人版 `r578406` 是不同产品，只能当参考。

## 0. 前置约束

- 只用 Ghidra 项目里已有程序，**不要从磁盘导入**：
  - 施主 `/macos_dontstarve_steam_x86_r181048`（i386，19.7k 函数，19.4k 具名）
  - 目标 `/macos_dontstarve_steam_x64_r759671`（x86_64，25.9k 函数）
  - 参考 `/macos_dontstarve_steam_single_x64_r578406`（单人版）
- headless 里两个程序内部名都叫 `dontstarve_steam`，**同时打开会互相顶掉**：必须串行——开一个、跑脚本、`close_program`、再开另一个。输出文件名用指针宽度区分（`_x86` / `_x64`）。
- `fm.getFunctions(true)` 不含 external functions；函数总数要用 `getFunctionCount()`，两者差值是导入数。
- Ghidra 外部地址空间**永远没有入向引用**（实测 extRefs=0）：判断导入是否被用，要看"是否存在同名本地 stub 且 stub 被引用"。

## 1. 特征导出（inline Java，分程序串行）

每程序输出 4 个 TSV 到 `build/symmatch/mac_xarch/`：

| 文件 | 内容 |
|---|---|
| `<tag>.funcs.tsv` | 地址 / 大小 / 名字 / 命名空间 / SymbolSource |
| `<tag>.strings.tsv` | 指令地址 / 被引用的字符串（只取 `Data.getValue() instanceof String`） |
| `<tag>.calls.tsv` | 调用点地址 / 被调地址 |
| `<tag>.bind.tsv` | 脚本注册表：`name \t func \t table_base \t stride` |

脚本注册表扫描要点：指针宽度 `getDefaultPointerSize()`；stride 取 `2/3/4/5/6 × ptrsize`；条目判据是 `[0]=字符串指针` 且 `[1]∈可执行段且 getFunctionAt()!=null`，连续 ≥3 条成 run。i386 常见 stride 8/16，x64 常见 16/32。要求 name 指针在镜像内、可打印、2–48 字符。

## 2. 通道与实测产出（这套二进制上的真实数字）

| 通道 | 定义 | 原始对 | 结论 |
|---|---|---:|---|
| `bind` | 注册名在两侧各只对应一个函数 | 782 | 可用；与 `str` 合并后升 Tier A |
| `bindtab` | 注册表按条目序列 LCS 对齐，逐槽同名 | 452 | 可用，补 LuaProxy 方法 |
| `str` | 唯一字符串引用（≥10 字符，两侧各仅一个函数引用） | 1,053 | 主力，但单独用有误配 |
| `self` | 函数体字符串等于自身限定名 | 39 | 只做升权，不单独成 tier |
| 字符串集合投票 | 共享字符串计票（≥2 票、Jaccard≥0.4/0.5、双向唯一） | 402+510 | 适合扩大批量；目标已命名时先剔除 |
| 立即数多重集 | 0x10000–0xffffffff、非镜像内地址 | 44（唯一） | **不可用**：i386/x64 代码生成差异太大 |
| vtable 槽位偏移 | ≥3 指针 run + 槽位偏移投票 | 509（仅 3 个通过复核） | **不可用**：thunk/ICF/虚表头差异导致偏移漂移 |
| 图传播 | 锚点邻域打分（score≥4、margin≥2、双向唯一） | 228 | 仅 `same-short`（目标已有同名方法）可信；`different` 有系统性成对互换 |

## 3. 落名规范（可回退）

apply TSV 列：`target_addr \t ns \t short_name \t tier \t donor_qualified \t extra`。

Java 落名脚本（inline，不能定义方法，只能写脚本体）：

```java
HashMap<String,Namespace> cache=new HashMap<>(); cache.put("", currentProgram.getGlobalNamespace());
// 逐段 split("::") 建命名空间：createNameSpace 失败则 getNamespace(seg,parent) 兜底并写入 cache
fn.getSymbol().setNamespace(ns);
if(!fn.getName().equals(short)) fn.setName(short, SourceType.USER_DEFINED);
fn.setComment("sym:r181048 <限定名> tier=<A|B|D|D2|NS|P> [score=..] [old=<旧限定名>]");
```

- 只改 `FUN_*` 或"同短名只差命名空间"的；目标已有**不同**名字时跳过（判为新版改名或旧迁移误配）。
- `setNamespace` 会连带把 thunk 符号改成目标函数名（具名数会暴涨，别误判成批量写入）。
- 每次应用后 `save_program`，并写 `applied_*.tsv` 回退清单。

## 4. 验证

- 用目标原有 `IMPORTED` 符号做留出集（本二进制只有 685 个，覆盖太低，不能当唯一精度来源）。
- 更实用的是**名字交叉验证**：第三方通道给出的配对，若目标已有同名短方法名，说明配对正确；这类只改命名空间，风险低。
- 抽样用 `get_function_by_address` + 脚本打印 `ns::name + comment` 确认。

## 5. 名字来源审计（重要）

目标里的注释能直接区分来源：`sym:r181048`（本次）、`same-arch`（单人版 r578406 同架构迁移）、`cross-arch`（其它会话跨架构迁移）、无注释（原生/历史）。
统计口径：不同来源的名字可信度不同；`same-arch` 里约 44% 与 r181048 同名，其余要按 DST 语义复核。
