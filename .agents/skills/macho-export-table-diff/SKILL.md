---
name: macho-export-table-diff
description: "Compare Mach-O (macOS) export tables across two game builds: Ghidra MCP headless load, LC_DYLD_EXPORTS_TRIE ground truth, demangled name diff"
---

# When to use

问某 macOS/x64 Mach-O 两个版本"导出表重复多少、差异多少"，或需要“仅新/仅旧”的反解析符号名单。也适用于任何要走 ghidra-mcp headless 打开 project 内已导入 program 的场景。

# 1. 定位 program（headless 下不能列 project files）

`list_project_files` / `open_program` 在 headless 报 `requires GUI mode`。直接读 project 磁盘：

```bash
grep -a NAME= ~/dst.rep/idata/*/*.prp | head -40      # NAME="macos_dontstarve_steam_x64_r759671" 等
```

装载：

```
xd://mcp__ghidra_mcp_load_program_from_project  →  {"path":"/macos_dontstarve_steam_x64_r759671"}
```

- 返回的 `program` 字段才是真实 program 名（可能是原文件名，重名会加 `_<id>` 后缀）。
- `current_program` **不会**自动切换：后续每次调用都显式传 `program=`。
- 身份核实：`get_metadata` 的 `executable_path` + `file` 判断 thin/fat；fat 时比对 x86_64 切片大小。

# 2. 真实导出表 = LC_DYLD_EXPORTS_TRIE，不是 list_exports

`mcp__ghidra_mcp_list_exports` 每页最多几百行（用 `offset/limit=400` 翻到返回空串为止），但行数被 demangler 别名和同名多址放大：

| 二进制 | list_exports 行 | 唯一名 | trie 名 = nlist 外部定义符号 |
|---|---|---|---|
| r759671 | 2525 | 1953 | 1262 |
| r578406 | 15475 | 12783 | 9749 |

所以“重复/差异”一律按 trie 名集合算，Ghidra 行数只作旁证。

解析要点（纯 Python，无需 nm）：

- fat magic `0xcafebabe` 取 cputype `0x01000007` 的切片偏移。
- `LC_DYLD_EXPORTS_TRIE`(0x80000033) 偏移在 `p+8`；`LC_DYLD_INFO[_ONLY]`(0x22/0x80000022) 的 export 在 **`p+40`**（前缀 5 对 off/size），极易取成 rebase 而解出乱码。
- 节点格式：`terminalSize(uleb)` → 跳过 terminalSize 字节 → `childCount(uleb)` → 每个子节点 `edge字符串\0` + `childOffset(uleb)`（offset 相对 trie 起点）。
- 地址需加 image base `0x100000000`（`__mh_execute_header` 自证）。
- 交叉验证：nlist 里 `N_EXT && !N_UNDF` 的条数应等于 trie 名数；不等就是解析错了。

# 3. 反解析与分组

- Mach-O 名比 Itanium 多一个前导 `_`：`__Z…` → 去掉 1 个 `_` 再喂 `llvm-cxxfilt`。
- `llvm-cxxfilt` 对函数模板会输出返回类型（`void RPCDirection::ServerOnly<…>`），分组前剥掉 `void `/`int ` 前缀。
- scope 切分要按 `<>`/`()` 嵌套深度找最后一个顶层 `::`，否则 `Lunar<…>::new_T`、`ComponentLuaProxy<A,B>::Add` 会被切碎。

# 4. 语义校验（防止把差异说错）

把“仅新”名字拿到旧二进制 nlist 里查：`0/N 命中` 才说明是真符号差异；若命中，只是导出可见性/白名单变化。反之亦然。这一步决定结论是“新增 API”还是“改 visibility”。

# 5. 输出

落盘两份：完整版（`完整反解析签名 \t _Z修饰名 \t VA`，按 `[scope]` 分组）+ 紧凑版（每行 ≤6 个名字）。回答里给分组名单 + 校验结论 + 文件路径。
