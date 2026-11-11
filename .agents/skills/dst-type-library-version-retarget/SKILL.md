---
name: dst-type-library-version-retarget
description: "Retarget DST arm64 type library (types_android.hpp) from one libDontStarve version to another using ctor store-set diffs, RTTI/vtable extraction, Ghidra MCP audits, and clang layout validation."
---

# DST 类型库跨版本重定向

适用：把 `3rd/dst/game_decompiler/types_android.hpp`（或同类 offset-anchored 类型库）从旧 libDontStarve 版本改到新版本；不适用一般 C++ 头文件维护。

## 0. 前提资产
- 新二进制：`C:/Users/fesil/Downloads/lib/arm64-v8a/libDontStarve_2.2.1.so`（Ghidra 程序名 `libDontStarve_2.2.1.so`）。
- 旧二进制：`DontStarveTogether_1.1.28.apk.7z` → `split_config.arm64_v8a.apk` → `lib/arm64-v8a/libDontStarve.so`（7z 先当 zip 打开）。
- 工具：`C:\Program Files\LLVM\bin\llvm-objdump.exe`、`llvm-cxxfilt.exe`、`clang++.exe`；`pyelftools`（pip）。**注意**：bash 无法 exec 带空格的路径，统一用 `python -c subprocess.run([...])`。
- Ghidra 地址 = ELF 虚拟地址 + `0x100000`。

## 1. 本地提取（不要靠 Ghidra 逐个查）
写一个 extractor，对两个 .so 各跑一遍，输出 facts.json：
1. `.dynsym`（名字/addr/size/type）+ `llvm-cxxfilt` 批量 demangle。
2. RTTI/vtable：`.rela.dyn` 中 `r_info_sym != 0` 的重定位必须用 `dynsym[sym].value + r_addend` 解析（RELATIVE 的 addend 为 0，直接读会全是 0）。用 `[offset-to-top, typeinfo, slots...]`；typeinfo 名是 Itanium 裸编码，嵌套类需 `_Z` + name 再 demangle。
3. 构造器 store 集：`llvm-objdump -d --no-show-raw-insn` 一次全量，只留 `str/stur/stp/strb/strh/mov/add/bl` 等行；按 x0=this 跟踪寄存器偏移，记录 `(offset,width)` 集合与 max extent。

作用域解析坑：`_ZNK…`（const 成员）必须从 index 4 开始，否则 const 方法全被丢弃；别把 `mov w0,#imm` 当 this 偏移；load 不要计入 size 上界；`add x0,x0,#imm` 在 x0 未知时不得视为 0+imm。

## 2. 判版（核心判据）
对每个 hpp struct 解析出 mangled 类作用域（用 body 里的 `_Z…` 取证 + RTTI 名兜底），然后：
- ctor store 集 old == new ⇒ **布局未变**（最可靠）。
- 再比 vtable slot 名序列、RTTI 基类、导出成员集。
- 输出 verdict：identical / symbols_only / vtable_changed / stores_changed / unresolved。

## 3. 并发审计（只审有分歧的）
只把 `stores_changed / unresolved / vtable_changed` 的 struct 派给 agent，每片 ≤7 个（14 个会因输出过长失败）。每个 agent 拿到 slice JSON（hpp 文本、算好的偏移、2.2.1 ctor 地址、观测访问集），要求**构造器优先**、每条结论带地址、输出 JSON。
- scout 无写文件权限：让它把 JSON 存 `local://sliceN.json`（可写），再由主进程 `cp local://sliceN.json ...`。
- agent 返回的字段表常常是「完整扁平布局（从 offset 0 起，含基类字段）」或「只列变更字段」；二者语义不同，整合前必须区分。

## 4. 生成（regen + 两段校验）
- 只对 `verdict == layout_changed` 的 patch 生效；字段行先归一化（容器/不完整类型 → `uint8_t name[N]`，`Base::field` → 注释，丢掉整段 struct 文本的碎片行）。
- 成员/虚函数按 2.2.1 重新生成；**只有原 struct 本来声明了 vptr（有 virtual 行）才重新发虚函数**，否则会平移所有字段偏移；若 2.2.1 vtable 解析不完整（含 `UnnamedSlot` 或槽数少于原行数）就回退到 1.1.28 虚函数行（地址重标 `1.1.28:`）。
- 用 clang 实测校验：`-Xclang -fdump-record-layouts-complete` 拿 sizeof；patch 必须复现其声称 sizeof（差 0）才接受，否则拒绝并在 struct 上写 `audited: … field list NOT re-derived here`。做 2–3 轮 pass：生成 → 测 → 剔除不合格 patch → 重生成。
- 前向声明只允许出现在真正被引用的类型上；类型 token 收集只能取「类型部分」，不能把字段名/寄存器名混进去（否则一堆 `struct UNKNOWN_0x08;`）。
- 最终交付门：`clang++ -target aarch64-linux-android24 -fsyntax-only` 通过 + 所有 `_Z… @0x` 与 2.2.1 facts 逐条比对为 0 不符。

## 5. 收尾
- 旧证据地址统一前缀 `1.1.28:0x…`，2.2.1 地址写 `@0x…`，header 里写清证据模型。
- 报告分四类：新增类 / sizeof 变化 / 仅 API 变化 / 已审计但字段未重推；用 clang sizeof 前后对比表量化。
