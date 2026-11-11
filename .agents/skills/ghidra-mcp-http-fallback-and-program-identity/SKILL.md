---
name: ghidra-mcp-http-fallback-and-program-identity
description: ghidra-mcp 工具未挂载时用 REST+token 驱动同一后端，并在分析前用 PE TimeDateStamp 校验 program 身份
---

# When to use

omp 只挂载了少量 ghidra-mcp 工具（`list_instances/check_tools/search_tools/load_tool_group/import_file/connect_instance/oracle_*/debugger_*`），而 `decompile_function/search_strings/get_xrefs_to/run_analysis/load_program` 等不在 `xd://` 设备表里。`load_tool_group(all)` 返回 `new_tools: 0` —— 服务器端 214 端点已加载，宿主会话的设备表是启动快照，不会动态增加。

## 1. 直接走同一后端的 REST 接口

Token 来源（bridge 的 `config.py` 也这么取）：

- `%LOCALAPPDATA%\ghidra-mcp\auth-token.txt`
- 或 `%LOCALAPPDATA%\ghidra-mcp\<GHIDRA_MCP_PROFILE>\auth-token.txt`
- `/health`、`/mcp/health`、`/check_connection` 免鉴权

```python
TOK = open(r"C:\Users\<u>\AppData\Local\ghidra-mcp\dst\auth-token.txt").read().strip()
# GET  /decompile_function?address=0x...&program=<name>
# GET  /search_strings?search_term=...
# GET  /search_byte_patterns?pattern=<hex bytes>   # 精确、不受“未定义字符串”限制
# GET  /get_xrefs_to?address=0x...
# GET  /read_memory?address=0x...&length=N
# POST /run_analysis?program=<name>   body {}
# GET  /mcp/schema  → 全量端点/参数 schema
```

Header: `Authorization: Bearer <token>`。

## 2. 程序身份必须先验证，再分析

坑一：`/load_program` 对已存在的**同名** program 返回 `success`，但 `switch_program`/`get_current_program_info` 仍指向旧对象 → 会静默分析错版本。
坑二：headless 下 `load_program_from_project` 成功，`current_program` 也可能不变；所有查询**显式带 `program=`**。

判据（不要看文件名/版本号）：

1. `read_memory 0x140000000 length=1024` 解析 PE → `TimeDateStamp = u32@(e_lfanew+8)`，与磁盘 exe 对比。
2. 段表 `.text` vsize / `.rdata` VA 与磁盘 PE 对比。
3. `search_byte_patterns` 查一个已知字符串（如 `IsBarterQueueEnabled`）的地址，和按文件偏移换算出的 VA（`imagebase + va + fileoff - rawoff`）对照。

`search_strings` 可能漏报（未定义字符串区），用 `/search_byte_patterns` 兜底。

## 3. 清理与脚本执行

- 删除误导入的 program：`/delete_file` 要 GUI；用 `/run_script_inline`（需 `GHIDRA_MCP_ALLOW_SCRIPTS=1`）：

```java
DomainFolder root = currentProgram.getDomainFile().getParent();
DomainFile f = root.getFile("dup.exe");
if (f != null) f.delete();
```

headless 下 `state.getProject()` 为 null，必须用 `currentProgram.getDomainFile().getParent()`。
若脚本报旧的编译失败，删掉 `C:\Users\<u>\ghidra_scripts\McpInline_*` 再跑（build 缓存噪音，实际脚本可能已成功）。
