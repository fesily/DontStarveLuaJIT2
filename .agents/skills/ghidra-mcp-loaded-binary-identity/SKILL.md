---
name: ghidra-mcp-loaded-binary-identity
description: "Before trusting GhidraMCP results after a game/binary update: prove the loaded program matches the on-disk build (PE TimeDateStamp, unique-string VA, distinct-name load_program), and call the REST API directly when tools are not mounted."
---

# Verifying you are analyzing the *current* binary in GhidraMCP

Use when a Ghidra MCP answer must be trusted (symbol/gate re-verification after a game update), or when an analysis contradicts strings that `grep -a` finds in the file.

## 1. Get the real build dates before decompiling

- Disk exe: parse PE header — `TimeDateStamp` at `e_lfanew+8` (UTC), plus mtime.
- Steam: `steamapps/appmanifest_<appid>.acf` → `buildid`, `LastUpdated` (epoch). `version.txt` may not change across rebuilds.
- Ghidra program: read memory at `image_base`, 0x600 bytes, parse `e_lfanew`, then `struct.unpack_from('<I', h, pe+8)`.
- Ghidra's reported `creation_date` is the **DB/program** creation date, not the PE build date — do not use it.

## 2. Force-load the exact file

`POST /load_program {"file": <abs path>}` returns `success` even when a program with that basename already exists; `switch_program` then selects the **old** object. Copy the binary to a distinct name first:

```
cp <exe> %TEMP%/<tag>_<name>.exe   # e.g. dst759671_steam_x64.exe
POST /load_program {"file": "C:/Users/.../Temp/dst759671_steam_x64.exe"}
GET  /switch_program?program=dst759671_steam_x64.exe
GET  /get_current_program_info      # check executable_path + memory_size
```

Then `POST /run_analysis?program=<name>` (a 7 MB PE ≈ 60–120 s). Analysis is required before `get_xrefs_to` resolves; `read_memory` / `search_byte_patterns` work immediately.

## 3. Prove the loaded bytes match the file

1. `grep -abo "<unique string>" <exe>` → file offset.
2. Map offset → VA with the PE section table (`VA = image_base + sec.VirtualAddress + off - sec.PointerToRawData`).
3. `GET /search_byte_patterns?pattern=<hex of ascii>` must return that address; `GET /read_memory?address=<va>&length=64` must show the string.
4. Cross-check section sizes (`.text VirtualSize`) between program header and disk header.

## 4. Resolve Lua bindings

- String xref is a `luaL_Reg`-style DATA table; read 16 bytes at the xref: qword0 = name ptr, qword1 = lua_CFunction.
- Decompile qword1. Typical tells: constant `pushboolean(L,1)` = feature flag hardcoded on; `return 0` = no-op stub (e.g. `TheSim:ValidateLineNumber` on Windows DST).

## 5. If an MCP device is "No such tool"

The harness may mount only a subset of ghidra-mcp tools. `load_tool_group(all)` does not add mounts. Same server, direct REST:

- Token: `%LOCALAPPDATA%/ghidra-mcp/auth-token.txt` or `.../ghidra-mcp/<GHIDRA_MCP_PROFILE>/auth-token.txt` (bridge `config.py` fallback).
- `curl -H "Authorization: Bearer $T" http://127.0.0.1:8089/mcp/schema` for endpoint+param schemas.
- Works headless: `/load_program`, `/run_analysis`, `/decompile_function`, `/search_strings`, `/search_byte_patterns`, `/read_memory`, `/get_xrefs_to`, `/switch_program`.
- `import_file` / `open_program` / `list_project_files` refuse with "requires GUI mode".

## 6. Report

State the PE timestamps of both the loaded program and the disk file, the one address you byte-verified, and then the new addresses. Old addresses from a previous build are not evidence.
