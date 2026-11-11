---
name: cross-abi-vtable-slot-transfer
description: "跨编译器(Itanium/mac clang ↔ MSVC/Windows)vtable 槽位对齐迁移虚函数名:先排除 ABI 析构槽差异,再用 ctor-vptr 引出的真 vtable 做 1:1 对齐与体级验证"
---

# 跨编译器 vtable 槽位对齐(Itanium ↔ MSVC)

## 何时用

同一份源码的两个构建在不同编译器/ABI 下(典型:mac clang/Itanium ↔ Windows MSVC),需要把一侧的
虚函数名迁到另一侧,且特征通道(字符串/被调名)已饱和。裸按槽下标对齐会全错。

## 铁律:先排除 ABI 前缀

| ABI | vtable 布局 |
|---|---|
| Itanium(mac/linux clang) | `[offset-to-top=0][typeinfo ptr][D1][D0][方法0][方法1]…` |
| MSVC(Windows) | `[COL ptr][scalar-deleting dtor][方法0][方法1]…` |

MSVC 只有**一个**析构槽,Itanium 有**两个** → mac 比 Windows 多一槽。
忽略这点会整体错位一格,精度直接归零(实测 0/917)。

## 步骤

1. **导出真 vtable**:用「ctor 里存 vptr 的代码引用」引出(`DstExportVtablesViaRefs.java`)。
   ❌ 不要用指针-run 扫描:会把相邻表合并、把非 vtable 的指针数组也导出(mac 侧导出过
   `_Cocoa_GetDisplayBounds` 这种 dynapi 表,导致对齐 0%)。
2. **规整槽下标**:mac 丢前 2 槽(offset-to-top / typeinfo)并丢弃 D1/D0;Windows 丢 COL 与
deleting-dtor 槽。之后两侧方法槽从 0 开始一一对应。
3. **打分对齐**:对每对 vtable 统计「同名槽数 / 共有具名槽数」,要求比值 ≥0.75 且
   同名槽数 ≥4;再做**1:1 贪心指派**(一个 mac 表只能配一个 Windows 表)。
4. **只对「Windows 未命名槽」提案**:取对齐 mac 表中该下标的完整名(带定义类限定,不要只留尾名)。
5. **先定义函数再改名**:vtable 槽目标常不是 Ghidra 函数(`get_function_by_address` 报
   No function found)。先 `DstDefineFunctionsFromList.java`,再批量改名。
6. **体级抽验**:改名前挑 2–3 条比两侧反编译体(同字段偏移/同常量为准)。
   实例:`btConvexInternalShape::setMargin` 两侧都是 `*(float*)(this+0x40) = v`。

## 残留歧义怎么办

多个派生类共享基类槽时,同一张 Windows 表会被多个 mac 派生类命中。此时用基类共有槽对齐
必然歧义,只能改用**派生类独有槽**(仅该类实现的虚函数)做唯一命中判定。

## Ghidra MCP 实操坑

- `load_program_from_project` 的参数是 **`path`**(不是 `program`/`program_name`)。
- `switch_program` 用 query string:`POST /switch_program?program=<name>`;脚本里 `currentProgram`
  只有在真正切换成功后才变(用 `DstNamedStats` 的 `Program:` 行确认)。
- `run_ghidra_script` 把脚本参数**用逗号拼成一个字符串**传入;脚本需 `args[0].split(",")`。
- 名字里不要有空格(`unsigned long` → `unsigned_long`)。
