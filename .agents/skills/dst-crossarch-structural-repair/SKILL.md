---
name: dst-crossarch-structural-repair
description: 修复 DST 跨架构符号迁移的结构性证据缺口：.pdata 补函数、尾调用边、luaL_Reg 抽取错位、顺序假设验证；不是普通匹配算法调参。
---

# DST 跨架构证据源修复（先修结构，再谈匹配）

适用：Android 有符号 ↔ Windows 全剥离的符号迁移，覆盖率停滞、传播精度低、或名字来源可疑时。

## 0. 先确认分母诚实

Ghidra 的已定义函数数往往远小于真实函数数。跑 `DstPdataCoverage.java`（.pdata 12 字节 RUNTIME_FUNCTION = begin/end/unwind RVA，加 imageBase）：

- 若 "undefined" 占比 > 20%，先补函数再谈覆盖率与传播。
- 实战数值：25,270 条目 / 14,698 已定义 / 10,572 缺失（41.8%）。

## 1. 用 .pdata 补函数（机械、不改名）

`DstDefinePdataFunctions.java`：对每个 begin 非函数的地址 `createFunction`。实测 created=10,510 / refused=59 / exists=14,701。

## 2. 补尾调用边

inventory 只统计 `ins.getFlowType().isCall()` 会漏掉尾调用，而 .pdata-only 的函数体恰恰只被尾调用到达。

在 exporter 的非 call 分支加：

```java
if (ins.getFlowType().isJump()) {
  for (Reference ref : refMgr.getReferencesFrom(ins.getAddress())) {
    if (!ref.getReferenceType().isJump()) continue;
    Function target = fm.getFunctionAt(ref.getToAddress());
    if (target == null || target.isExternal()) continue;
    if (target.getEntryPoint().equals(func.getEntryPoint())) continue;
    callees.add(target.getEntryPoint().getOffset());
  }
}
```

实测：Windows +6,272 边（52,137→60,215，+15%），不同被调用者 11,482→16,287；Android 侧仅 +338（MSVC 与 clang 的尾调用生成差异）。**两侧都要补**，否则跨架构图比较不对称。

## 3. 校验 luaL_Reg 抽取没有错位

Windows 真实布局是 stride 24：`{char* name; void* func; 0}`。抽取器若"取最长 run"，无关指针数组里的伪对齐会胜出，整表错位。

判据：取一个已知绑定名，`search_strings` 找到字符串 → `search_byte_patterns` 找指向它的 qword → 读 `+8` 得到真实函数 → 反编译核对语义。

修法：一个 run 只有在**每个名字都是合法标识符**（`Character.isJavaIdentifierStart/Part`，长度 2–48）时才接受。修正后应做审计：live 绑定函数中名字与绑定名一致的比例（实测 1104/1105）。

## 4. 别指望"地址顺序"当匹配器

先测三个数（`order_align.py`）：

| 问题 | 判据 |
|---|---|
| 类内顺序是否保持 | 按类分组锚点，看 Windows 地址是否随 Android 升序（实测 ≥5 锚点类 45/47）|
| 全局顺序是否保持 | 相邻锚点对里 Windows 是否逆序（实测 44% 逆序 → 不可用）|
| 等长间隙比例 | 相邻锚点间两侧函数数相等的间隙占比（实测 3.2%）|

结论模板：类内保持、全局不保持 → 顺序只能用于 ABI 固定场景（vtable 槽序），不能做地址相邻对齐；DP 单调对齐即使加 size+立即数相似度也只召回 ~2%。

## 5. 顺序的实际用途：只作弱门

caller 传播上加"顺序一致性"注解可把精确率从 0.421 提到 0.571，但作为排序项没有增益。默认关闭（`--order-weight 0`）。

## 6. 收尾检查

- 修复后重跑导出与通道，确认 vtable 对齐表数未变（说明补函数没破坏既有结论）。
- 覆盖率必须按修复后的分母报告（例：4,876 / 29,248 = 16.7%）。
