---
name: samearch-32to64-engine-symbol-migration
description: "Same-arch (x86 32→64) cross-compiler engine symbol migration: coverage metrics, evidence channels, systematic error classes"
---

# mac 32→64 引擎符号迁移（同系列 x86，跨编译器）

## 度量口径（先定口径，否则数字毫无意义）

```python
LIBNS={"libzip","vorbis","ogg","theora","theoraplay","jansson","minizip","lua51",
       "rapidxml","RakNet","DataStructures","boost","std","bullet","bt","KleiFile","antlr"}
def key(n):              # 去 _hex 折叠后缀 + 剥离库命名空间（2 段名也要剥！）
    p=re.sub(r"_[0-9a-f]{4,}$","",n).split("::")
    while len(p)>=2 and p[0] in LIBNS: p=p[1:]
    return "::".join(p[-2:])
```

- 分母用**32 位符号表**，不要用 64 位函数总数（后者含 thunk/external 且大量无对应体）。
- 初版 bug：`while len(p)>2` 漏剥两段名（`theora::_oc_pack_look1`），统计偏低约 5 个百分点。
- 分引擎 / 第三方报数，不要只报总和——用户真正关心的是引擎。

## 判定通道（按产出排序，实测）

| 通道 | 产出 | 关键点 |
|---|---:|---|
| `Pool<T>` / `cResourceManager<T>` / `FrameDelayedResourceManager<T>` 实例 | ~250 | 元素 ctor 目标 + `operator_new(n*stride)` + 4 槽 vtable `[~D1,~D2,GetNew,Recycle]`；`Recycle` 是共享体 |
| `T::ComponentID()` 存根 | ~120 | 6B `mov eax,imm32; ret`，被 `AddComponentToEntity<T>` 直调 → 类身份 100% |
| vtable 槽语义对齐 | ~180 | 槽内 `lea rax,[串]` 的 `GetName`、`mov eax,imm32` 的 `GetID` 最硬 |
| 容器模板实例 | ~200 | 元素步长 + 唯一调用者 |
| 第三方源码逐句对照 | ~120 | theora/vorbis/ogg/zlib/rapidxml/libzip/RakNet |
| `cFactory<>::Register<T>` 块 | 38 | 定长 stride 连体 + 每型专属 `ComponentID()` |
| Lobby2 消息块自证 | ~40 | `GetName` 返类名串、`GetID` 立即数 → 块内 10 槽可定 |
| 旧版本同架构带符号表 | ~60 | 布局/尺寸精确佐证 |

## 已知系统性错误（每轮都会撞上）

1. **assert 桩被当成函数本体**：体只有 `___assert_rtn("name","file.cpp",line,...)` 的是断言点，不是那个函数。全库 1,135 个「唯一调用者=assert runtime」的体，19 个被错挂名。
2. **基类 vtable 整体错挂 + 偏移一位**（例：`cEntityComponent` 13 个基体全记成 `FontComponent::*`）。用「派生类覆盖集合」对齐槽语义。
3. **模板实参错位**（`Pool<PathfinderComponent>` 实为 `FollowerComponent`）。
4. **LTO/ICF 合并体抢名**：一址一名，按调用者集合判归属，其余记 `folded:<addr>` 并把别名写进该体 plate comment。
5. **`~T` 与 `OP_DELETE<T>` 混淆**：看 32 位体是否 `delete this`。
6. **`cxx_runtime::operator.delete` 批量标签**掩盖各类删除析构（D0 槽 5B jmp），需按 vtable 槽归位。

## 落地注意

- 名字**不能含空格**：`unsigned long` → `unsigned_long`，否则 apply 脚本解析失败（症状：脚本无输出、`success=false`）。
- TSV 行尾必须是 LF，不能 CRLF；不能带表头行。
- 批量 apply 前先 `get_current_program_info` 断言程序名，防止在错误程序上写名。
- 大批量 apply 失败时，按 10 行切片定位问题行。

## 折叠实例的正确处理

对 `ABSENT folded:<addr>` 的行，不要改共享体的名字；写脚本把 `alias: <name32>` 追加到该体 plate comment（幂等），并保留一份 `FOLDED_ALIASES_*.tsv` 作为可审计清单。
