---
name: windows-binding-table-selfnaming
description: 用脚本注册表给 DST 一类 lua 绑定函数自命名/纠错：表格扫描、类名推导、ICF 共享桩过滤、两阶段交换改名与证据分级
---

# 用注册表给 lua 绑定函数自命名（并能纠错）

适用：DST 一类用 `luaL_Reg` 风格表注册 lua_CFunction 的引擎（Windows MSVC 步长 24，macOS clang 32 或 48）。
不需要孪生二进制就能命名；有同一构建号的另一平台符号时，可以直接纠错已有名字。

## 1. 取表

```
DstExtractBindingsRows.java <out.tsv>   # table_base, index, name, func
```

- Mach-O：注册表在 `__data`/`__DATA_CONST`，**可能只读**，所以扫描所有“已初始化且非可执行”块（别用 isWrite 过滤）。
- 步长先探明：拿一个已知方法名（如 `SetTexture`）的字符串地址查 xref，`read_memory` 看真实行距。Windows 常见 24，macOS 常见 32/48，裸 `{name,func}` 是 16。

## 2. 定类名（关键）

表的槽位只给方法名，类名要从外部来，按优先级：

1. **同构建号的另一平台符号**（如同版本 macOS 旧构建的符号表）对齐同一张表 → 逐槽位拿 `Class::Method`；
2. 本程序里该表已有的具名槽位（`name` 的 base 要等于槽位 method，否则不算）；
3. 表的引用者（注册函数 / 类 ctor / vtable）。

**优先用 1**：本程序现有的名字可能整表错（例如整表都是引擎类名 `VFXEffect::X`，而真实类是 `VFXEffectLuaProxy`）。

## 3. 提案与过滤

对每个槽位 `(method, addr)`：目标 = `Class::method`。

必须跳过的三类：
- **同一地址被多个方法名注册**（ICF 折叠的空桩、no-op）：整槽跳过，不能按名落；
- 目标名字**已在别的地址存在**且那个持有者不在本批会被改名 → 跳过并记录；
- 类名推导不出来（表里没有具名槽位且没有孪生）→ 跳过。

纠错（名字与槽位方法不符）只在**孪生符号也一致**时才提；否则进 review 队列，不落地。

## 4. 两阶段应用（交换/错位组）

同一类表内“整体错 N 格”或“成对互换”时，直接改名会撞名，`DstApplyNames` 会造出 `name_<hex>` 后缀：

```
阶段1：把这类函数全部改成 TMP_<addr>
阶段2：再改成最终名（含新增名与命名空间迁移）
```

应用后必须校验：无 `TMP_` 残留、无重名、抽查 5–10 条体证据（包装体最后调用的引擎方法名应与方法名一致）。

## 5. 证据分级

| 级别 | 判据 |
|---|---|
| bindsym-callee | 表槽位 + 孪生符号 + **被调引擎函数同名** |
| bindsym-table | 表槽位 + 孪生符号 |
| review | 只有表槽位，或与现状冲突 |

## 6. 实测经验（DST r759671）

- 59 张表 / 1566 槽位：1350 已具名、216 未具名；补 166、纠 101，净增 166。
- 错名形态：TileGroupManagerLuaProxy 6 环错位、InputHandler Connected/Enabled 互换、MiniMapEntity 两两互换、若干“引擎方法名落到 LuaProxy 包装体上”。
- 76 个全局名（`Enable`、`SetShadeRotationSpeed`…）应迁入 `XxxLuaProxy::` 命名空间。
- 共享桩 72 个、无类名槽位 124 个、孪生未确认 35 条 —— 这些都不硬上。
