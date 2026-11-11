---
name: macos-macho-export-table-compare
description: "Compare Mach-O export tables of two builds via GhidraMCP: trie vs symbol-table row counts, dedup, overlap"
---

# When to use

用 GhidraMCP 对比 Mach-O（macOS/iOS）两个 build 的导出表，量“多少重复 / 多少差异”。也适用于任何需要判断“导出面是否被剥离”的 Mach-O 二进制。

## 1. 先把两个 program 加载进来（headless 环境）

- `mcp__ghidra_mcp_open_program` 与 `list_project_files` 在 headless 下直接报 `requires GUI mode (PluginTool not available)`。
- 用 `mcp__ghidra_mcp_load_program_from_project`（args: `{"path":"/<项目内名称>"}`），或 REST `POST /load_program_from_project`（body 同形，header `Authorization: Bearer <token>`，token 在 `%LOCALAPPDATA%\ghidra-mcp/<profile>/auth-token.txt`）。
- 项目内 program 名可从 `<project>.rep/idata/*/*.prp` 的 `NAME` 状态项读出（headless 下无 GUI 列表接口时的兜底）。
- 加载后必须 `GET /list_open_programs` 或 `get_metadata` 核对：`name` 取自原始文件名（可能被加 `_<数字>` 后缀）、`executable_path` 指向导入时的源文件、`language` 应为 `x86:LE:64:default`；后续所有调用显式带 `program=`。
- fat 二进制 Ghidra 只导入一个切片；对比前确认两边都是 x86_64 切片（`file` 显示 `Mach-O universal binary` 时也不能假定）。

## 2. 取两份导出列表

`mcp__ghidra_mcp_list_exports` 每次返回内容会受输出截断影响，**按实际返回行数推进 offset**，直到返回空：

```python
out, off = [], 0
while True:
    r = await tool.mcp__ghidra_mcp_list_exports({"program": p, "offset": off, "limit": 400})
    lines = [l for l in r["text"].split("```json")[0].splitlines() if "->" in l]
    if not lines: break
    out += lines; off += len(lines)
```

名字与地址用 `l.rsplit(" -> ", 1)` 拆；同名多址要保留 list，不能塞进 set 后直接丢。

## 3. 关键判据：别把 Ghidra 行数当导出表

- `list_exports` 的行 = 符号表全局符号 + demangler 别名，行数虚高（实测 DST macOS x64：2525 vs 真实 1262；15475 vs 9749）。
- 真实导出表 = `LC_DYLD_INFO_ONLY`（cmd 0x80000022，字段在 `p+40`）或 `LC_DYLD_EXPORTS_TRIE`（0x80000033，字段在 `p+8`）指向的 export trie，**不要**误把 DYLD_INFO 的 rebase_off 当 trie。
- 交叉校验：trie 名数 == nlist 中 `(n_type & 1) && (n_type & 0x0e) != 0` 的外部定义符号数；相等即可确认口径正确。
- 结论汇报两份口径都给出：Ghidra 行数/唯一名（含表内重复：同名多址行数）与 trie 口径（共同 / 仅A / 仅B）。

## 4. trie 解析要点

节点格式：`terminalSize(uleb)` → 跳过 terminalSize 字节 → `childCount(uleb)` → 每child：`nul-terminated edge` + `childOffset(uleb，相对 trie 起点)`。terminal payload 内：`flags(uleb)`，`flags&0x08` 为 re-export（两个 uleb），否则 `addr(uleb)`，`flags&0x10` 再跟 `stub(uleb)`。地址需加 image base（0x100000000）。

## 5. 结果解读

- 共同名中“同址”通常只剩 `__mh_execute_header`（0x100000000），其余全因重排漂移 —— 不要用地址交集算重合。
- 对比时给出分类计数（C++ mangled / SDL / boost / lua / C 其他），能直接看出新 build 是否做了 `-fvisibility=hidden` 导出收敛。
- 实测基线：DST macOS x64 r578406 导出 9749 → r759671 只剩 1262（砍 95%），共同 495、仅新 767、仅旧 9254。
