---
name: dst-android-type-header-retarget
description: "Retarget 3rd/dst/game_decompiler/types_android.hpp to a newer libDontStarve build via 1.1.28↔2.2.1 A/B evidence; use for DST arm64 type-library refresh, not for plain C++ porting."
---

# DST arm64 类型库跨版本重定向

目标：把 `types_android.hpp`（手写/生成的 AArch64 C++ 类型库）从旧 build 更新到新 build，且**每条改动都有地址证据**。

## 0. 准备两个二进制（A/B 的前提）
- 新：`C:/Users/fesil/Downloads/lib/arm64-v8a/libDontStarve_2.2.1.so`
- 旧：`DontStarveTogether_<ver>.apk.7z`（其实是 zip）→ `7z e … split_config.arm64_v8a.apk` → `7z e … lib/arm64-v8a/libDontStarve.so`
- 基线头文件：`git show HEAD:3rd/dst/game_decompiler/types_android.hpp > C:/tmp/dst221/types_android.orig.hpp`。**生成器只读这份 pristine 副本**，绝不读写已生成的文件（否则二次变形：provenance 行三连、字段重复）。
- 注意：bash 无法执行含空格的 exe（`C:\Program Files\LLVM\bin\llvm-nm.exe` 报 command not found）→ 一律用 `python -c "subprocess.run([...])"`。

## 1. 批量抽事实（本地，秒级，不用 MCP）
`C:/tmp/dst221/extract.py <so> <outdir>`：pyelftools 取 dynsym + `.rela.dyn`（428 个 reloc/符号解析：symbolic 取符号值、RELATIVE 取 addend），扫 `.data.rel.ro` 得全部 RTTI（含未导出类的 `_ZTV`+`_ZTI`）、解析 `__si`/`__vmi` 基类边、vtable slot 顺序；llvm-objdump 一次全 `.text` 过滤出 store/load/bl，做**基于 x0(this) 的寄存器传播**得到每个函数的 `stores[(off,width)]`、`loads`、`memset` 大小。

必须处理的坑：
- `_ZNK…`（const 成员）必须从索引 4 开始解析，否则 const 方法/虚函数**整体丢失**（曾导致 651→706 虚函数差异）。
- `mov w0,#imm` 等常量是调用参数，**不是 this 偏移**；只有 `#0` 或 `mov xN,x0` 的链才是 this 偏移，否则 ctor 会算出 0x2900 这种假 extent。
- store 与 load 分开：`extent` 只取 store（load 会读到对象外）。
- 判 alignment：未对齐访问直接丢弃。

## 2. 判定每个 struct
1. 把 hpp struct 映射到 mangled class scope：用 struct body 里的 `_Z…` 注释**按符号重合度打分**，再用 RTTI `typeinfo` 名字兜底（classes 字典的 key 可能是 mangled 的 `N6RakNet16…E`，要拿 typeinfo 比对）。
2. 两版 ctor store 集合做 **union 后比较**（C1/C2 别名互换属噪声）：相同 ⇒ 布局未变；不同 ⇒ 交 agent 反编译。
3. 分层结论写进文件：`layout+vtables identical` / `changed member set` / `vtable changed` / `ctor store set differs` / `audited: … field list NOT re-derived here`。

## 3. 判布局的绝对权威
- 2.2.1 ctor 反编译（Ghidra 地址 = ELF+0x100000）：`*(T*)(this+N)` 序列即字段表；`operator new(N)`/`memset(this,0,N)` 给总大小。
- 别信自己的 extent 推断，凡 `sizeof < extent` 的都要人/agent 复看（`ProcessId`、`HWBuffer`、`BaseVertexDescription`、`btDefaultCollisionConfiguration` 都是 Ghidra 证明 hpp 本来是对的、extent 是噪声）。

## 4. 生成器（regen.py）关键规则
- 地址：所有 `_Zsym @0x…` 用**符号名**映射到新版地址；映射不到的旧引用显式标 `1.1.28:0x…`（绝不留裸地址冒充新版）。
- 成员段：按 scope 的全量导出函数重生成，签名由 demangle 生成；**参数列表用配对括号截断**（`void (*)(…)` 这种函数指针参数会截错），const 后缀 `() const` 要单独保留。
- 模板实例化成员无法声明 → 降级为注释行；同名不同参（`Read(T&)` vs `Read(T*)`）简化后重名 → 第二条降级为注释。
- 虚函数段：**只有原 struct 原本就有 `virtual` 行时才重生成**（该文件字段偏移是绝对值，凭空加 vptr 会整体 +8）。重生成结果若比原来少条目或出现 `UnnamedSlot`（纯虚/无符号）→ 保留旧列表只刷新证据。
- 前向声明：只收集**类型部分**的标识符（不能把字段名 `UNKNOWN_0x…`、寄存器 `x30` 当类型），并且只在正文里真正出现时才保留；C++ 关键字/`uint8_t` 等要进黑名单。
- patch 应用：agent 的字段表若是**整对象列表**（含基类字段）→ 去掉 `: public Base` 变扁平，并保留其 `<vptr>` 占位（用虚 dtor 落实）；若是**局部列表**（长度不足）→ 拒绝，标 `field list NOT re-derived`。

## 5. 验证闸门（缺一不可）
1. `clang++ -std=c++17 -fsyntax-only -target aarch64-linux-android24` 通过。
2. `-Xclang -fdump-record-layouts-complete`：每个有 ctor 证据的 struct 满足 `sizeof >= extent`（除已由 Ghidra 证明的反例）；同时拿它当 `sizeof` 权威表。
3. 地址审计：正则扫全文 `_Zsym @0x…`，逐个与 facts 的 addr/vtable_addr 比对，必须 0 mismatch。
4. 抽样：`batch_decompile` 2–3 个重生地址，核对函数名与预期一致。
5. 装回仓库后**再用仓库路径编译一次**（git checkout 基线后不要忘记从 pristine 副本重新生成）。

## 6. 多 agent 分工
- 每个 agent ≤ 7 个 struct，输出 `C:/tmp/dst221/slices/sliceN_out.json`（schema: struct/verdict/size_2_2_1/fields/null/notes/evidence）。
- `scout` 只读、没有写工具：让它写 `local://sliceN.json`（bash 里 `cp local://x.json slices/` 可取），或截图式内联 JSON；一次给 14 个 struct 会因输出长度被截断/失败。
- agent 的字段表常把**基类字段也列进去**、常只列改动字段；整合时必须按上面的规则分流，并用 clang 实测 size 做闸门。
