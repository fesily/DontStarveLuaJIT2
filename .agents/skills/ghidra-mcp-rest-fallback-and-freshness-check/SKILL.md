---
name: ghidra-mcp-rest-fallback-and-freshness-check
description: "Use when ghidra-mcp analysis tools aren't mounted in the session, or a loaded program turns out to be a stale build after name collision."
---

# Ghidra MCP without the mounted tool set

## Symptom
`xd://mcp__ghidra_mcp_decompile_function` / `search_strings` / `get_xrefs_to` / `run_analysis` / `load_program` → `No such tool`, even though `search_tools` says callable and `load_tool_group(all)` returns `new_tools: 0`. The omp session's `xd://` device list is a snapshot from session start; reloading fixes it, otherwise use the REST path below.

## REST fallback (same backend)

```python
TOK = open(r"%LOCALAPPDATA%\ghidra-mcp\<profile>\auth-token.txt").read().strip()
BASE = "http://127.0.0.1:8089"
# GET  /mcp/schema                     -> full endpoint + param schema (needs auth)
# GET  /health, /check_connection      -> auth-exempt
# GET  /get_current_program_info, /list_open_programs
# GET  /search_byte_patterns?pattern=<hex>&program=<name>
# GET  /read_memory?address=0x..&length=N&program=<name>
# GET  /get_xrefs_to?address=0x..&program=<name>
# GET  /decompile_function?address=0x..&program=<name>
# POST /load_program {"file": path}
# GET  /switch_program?program=<name>
# POST /run_analysis?program=<name>
```
Header: `Authorization: Bearer <TOK>`. Without it every non-health endpoint returns 401.

## Never trust a name-colliding program

1. Copy the target binary to a unique filename (e.g. `%TEMP%\<build>_<name>.exe`).
2. `load_program` → `switch_program` with that unique name.
3. Prove freshness before analyzing: PE section table (`read_memory` at image base, parse e_lfanew/nsecs) must match the on-disk file, and a known string's VA computed from its file offset must be found by `search_byte_patterns`.

`load_program` returns `success` for a colliding name but `switch_program` then re-selects the pre-existing program; analysis and every decompile silently describe stale bytes.

## Notes
- `search_strings` only sees strings already defined by analysis; use `search_byte_patterns` with the ASCII hex for ground truth and to get the VA.
- xrefs to those strings appear only after `run_analysis` completes.
- Headless mode rejects GUI-only endpoints: `/import_file` and `/open_program` answer `requires GUI mode`; `/load_program` (body `file`) is the headless path.
