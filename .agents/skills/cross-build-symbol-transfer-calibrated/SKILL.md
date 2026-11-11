---
name: cross-build-symbol-transfer-calibrated
description: 当需要在同一产品的不同构建之间迁移函数符号（同架构换编译器/跨平台），且必须先验证通道精度再批量落名时使用；包含工程被占用时的 headless 解锁法。
---

# 跨构建/跨平台符号迁移:先标定,后落地

适用于同一产品不同构建之间迁移函数符号(同架构换编译器、跨架构、跨平台)。
**核心纪律:任何通道在落地前,必须用"两侧已同名"的符号对做 ground truth,测出覆盖率与精度;精度不达标的通道直接否决,不做批量落名。**

## 0. 准备

1. 目标程序必须在 Ghidra **工程**里(名字可比对,如 `x64_r759671.exe`)。
2. 两侧各导一份"函数清单":地址、大小、指令数、基本块数、字符串集、立即数集、被调地址/被调名。
   本仓库风格:`inv_*.jsonl`,每行 `{e,n,sz,ni,nb,str[],imm[],ce[被调名],cal[被调地址]}`。
3. **导出必须包含 thunk**。许多 Ghidra 导出脚本有 `if (f.isThunk()) continue;`,会漏掉上千个
   带真名的跳转包装,直接把覆盖率低估约 1 个百分点。用 `DstExportNamesAll.java`。

## 1. MCP 工程被占用时怎么跑 headless

MCP headless 只能 `switch_program` **已打开**的程序;`open_program` 需要 GUI;
`analyzeHeadless` 直接跑会 `LockException: Unable to lock project`。

解法:**复制工程**再 headless,不动用户会话:

```bash
robocopy /c/Users/fesil/dst.rep /c/Users/fesil/dstcopy/dst.rep /E /NFL /NDL /NJH /NJS /NP
cp /c/Users/fesil/dst.gpr /c/Users/fesil/dstcopy/dst.gpr
"C:/.../ghidra_12.1.3_PUBLIC/support/analyzeHeadless.bat" C:/Users/fesil/dstcopy dst \
  -process <ProgramName> -noanalysis -postScript <Script.java> [args]
```

先跑 `DstNamedStats.java` 确认函数数/具名数,再跑真正的导出脚本。

## 2. 通道(按实测精度排序,数字来自 DST mac r759671 ↔ Windows r759671)

| 通道 | 覆盖 | 精度 | 说明 |
|---|---:|---:|---|
| 字符串**互唯一**(两侧各自 freq==1) | 680/4078 | **94.7%** | 首选,最强 |
| 字符串严格(两侧 rare≤3, jaccard≥0.5, margin≥1) | 565 | 94.2% | |
| 被调名集合(margin≥2, 至少 2 个共享被调名) | 219 | **95.4%** | |
| 三通道并集(多通道投票,要求多数) | 803(19.7%) | **95.0%** | 落地用这个 |
| 地址序位插值(锚点窗口 + 尺寸最近) | 0 | — | **否决**:跨平台函数顺序无关,窗口跨度可达 MB |
| 调用者名集合 | 84 | **0%** | **否决** |
| 精确立即数指纹(sz+ni+nb+imm 全等) | 84 | 84.5% | 精度尚可但覆盖极低 |
| vtable 具名槽对齐 | 62 张表 | — | 受限于目标侧 vtable 检出数 |

> 关键教训:同架构≠同布局。MSVC vs clang、链接顺序差异会让"地址序位"完全失效。
> 不要因为"版本相同"就假设函数顺序一致。

## 3. 实现要点

```python
# 字符串互唯一
freqM = Counter(s for f in mac.values() for s in f["str"])
freqW = Counter(s for f in win.values() for s in f["str"])
owner  = defaultdict(list)   # win: string -> [func]
for s, f in ((s, f) for f in win.values() for s in f["str"]): owner[s].append(f)
# 只有当某字符串在两侧都只被一个函数引用时才投票
```

- 被调名集合:用 `cal` 地址映射到该侧已具名函数,再并上 `ce`(导入名);要求 overlap≥2 且 margin≥1。
- 多通道合并:**冲突即丢弃**(同一目标地址被两个不同名字认领 → 全丢),并用"多数投票"淘汰平票。
- 输出 TSV 时带 `tier` 与 `vote` 数,便于分级复核与后续回滚。

## 4. 标定流程(每轮必做)

```python
gt = {mac_addr: win_addr for 两侧同名符号}      # ground truth
pred = matcher(gt.keys())                       # 只在 gt 上评估
for tier in ("T1","T2","T3","T4"):
    print(tier, len(sub), covered_correct/len(sub))
```

只有 **精度 ≥93%** 的 tier 才允许批量落地;并把"实测精度"写进落地 TSV 的证据列。

## 5. 落地与验证

```bash
DstApplyNames.java  <tsv: addr \t name \t tier \t evidence>,apply
DstExportNamesAll.java <out.tsv>          # 落完必须重导
```

抓 20–30 条随机行,用 `get_function_by_address` 与**活的**程序比对名字,报告 x/y 一致;
只报实际跑过的验证。

## 6. 常见坑

- 名字里不能有空格(`unsigned long` → `unsigned_long`),否则落地脚本解析失败。
- 表里有 header 行时,脚本 `parseUnsignedLong` 会抛 `NumberFormatException` —— 先剥表头。
- `~T` 与 `OP_DELETE<T>` 靠"是否 `delete this`"区分;`___assert_rtn` 专用桩不是函数本体。
- 落名后 Ghidra 的 `thunk_` 前缀与 `_hex` 去重后缀会干扰比对,比较前统一归一化。
