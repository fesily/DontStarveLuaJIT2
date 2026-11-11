---
name: windows-binding-registry-naming
description: "Windows lua 绑定引擎：用脚本注册表 ({method,func}) 自命名绑定函数、纠正错位/互换错名、ctor 与 deleting-dtor 判别、两阶段交换应用"
---

# 用 Windows 脚本注册表自命名 + 纠错（DST 这类 lua 绑定引擎）

目标：给 lua 绑定函数（`lua_CFunction` 包装体）命名，并纠正历史错名。
**不需要任何孪生二进制**：注册表本身就是“运行时把 method 名绑到这个函数”的事实。

## 1. 取注册表

```
DstExtractBindingsRows.java <out.tsv>   # table_base, index, name, func
```

- 步长：Windows/MSVC `{name, func, 0}` = 24；macOS clang `{name, func, 0, 0}` = 32（也见过 48）；裸 `{name, func}` = 16。
- 表在只读段（`__DATA_CONST`/`.rdata`）里也可能有 → 扫描所有“已初始化且非可执行”块。
- 先用一个已知 method 名字符串的 xref + `read_memory` 确认真实步长，再决定 STRIDES。

## 2. 推类名

按优先级：

1. 该表内**已具名**槽位的类前缀（多数票）；
2. 同一构建的**另一平台**（macOS r759671）同名表的逐槽名字（旧 mac 符号是权威）；
3. 表的引用者（注册函数/ctor）。

PUC Lua 标准库表（base/co/db/io/math/os/string/table/package）没有类名且本来已具名，直接跳过。

## 3. 会给三类结果

- **新名**：槽位函数无名 → `Class::Method`；
- **纠错**：已有名与槽位 method 不符，且 mac 同槽确认 → 改写（实测纠正过整体错位一格、成对互换、跨类错名）；
- **入命名空间**：原本是全局名（`Enable`、`SetShadeRotationSpeed`）→ 移进 `XxxLuaProxy::`。

## 4. 必须做的过滤

- **ICF 共享桩**：同一地址被多个 method 名注册（空实现折叠）—— 不能按槽位命名（实测 72 个）；
- **同名已存在于别处**：跳过，不制造 `_<hex>` 后缀；
- **大表槽位漂移**：跨版本增删方法会让相邻槽错位，两个方向都会出现 ⇒ 该表只能**逐函数体裁决**（看包装体最后调的引擎方法），不能批量改。

## 5. 交换组两阶段应用

```
P1: 冲突的全部改成 TMP_<addr>
P2: 再落最终名（交换组、环替换必须这样）
```
应用后检查：无 `TMP_` 残留、无重名。`DstApplyNames.java <tsv>,apply` 是幂等的。

## 6. ctor / dtor 判别（顺带通道）

- ctor 与 **MSVC scalar deleting destructor** 都写 vptr ⇒ 都要单独判据：
  **delete 标志习语 `AND/TEST imm 1`**（`DstCtorFilter.java`）。“调用 free” 不可靠——分配器常是未命名 `FUN_`。
- 用“存的 vtable 的槽名”推类名错误率高（派生 ctor 先存基类 vtable，bullet/proxy 家族会 20+ 个候选撞同一类名）。
  只有 **vtable 数据标签自带类名**（`PTR_~cTextEditWidget_1404cc7c0`，用 `DstLabelsAt.java` 读）时才可信。
- 验收：body 里 `*this = &vtable` + 基类 ctor 调用 + 字段初始化；批量前抽 3-5 个反编译看一眼。

## 7. 通道饱和的判据

出现下面任一情况就说明这条通道到头了，别再堆规则：

- vtable 槽位“未具名数 = 0”（说明虚函数已被别的通道覆盖）；
- 未具名候选只剩个位数，且都是“同名冲突”或已否决项；
- 纠错候选集中在一张表且方向不一致（槽位漂移，非名字错）。
