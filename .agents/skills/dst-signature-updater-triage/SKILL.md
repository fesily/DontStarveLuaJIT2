---
name: dst-signature-updater-triage
description: "DST signature_updater runs and graph-seed/matching failure triage (offsets, log markers, inlining mismatch)"
---

# DST Lua signature generation / triage (`signature_updater`)

## When
`Mod/signatures_{client,server}.json` is stale or a new Lua API was added and the in-game Auto/`create` pass misbehaves (long stalls, unresolved exports, crash).

## Tool
- `tools/Creater/main.cpp` → `builds/<cfg>/tools/Creater/<Config>/signature_updater.exe create|update`.
- Baked defines: `GAMEDIR`, `LUA51_PATH=Mod/deps/lua51.dll` (reference implementation), `WORKER_DIR=Mod` (output JSON).
- Needs `spdlog*/fmt*.dll` on PATH: `builds/<cfg>/vcpkg_installed/x64-windows-custom/<debug|>/bin`.
- The tool inspects **exports of the loaded reference `lua51.dll`**; a name missing there is never matched/replaced.

## Procedure
1. Verify the reference DLL: imports `msvcr90`/`msvcp90` (VS2008), export table contains the new names; parse PE export dir rather than grep strings (names may be renamed).
2. Run `signature_updater.exe create` (backup `Mod/signatures_*.json` first). Keep stdout+stderr in one log; `create` rewrites both client and server DBs.
3. Triage from the log:
   - `has no byte match; deferring` → graph-seed candidate set.
   - `graph-seed ... -> 0x... (offset=N)` → verify candidate against Ghidra function list; graph-seed can pick a sibling (e.g. `luaL_prepbuffer` → `lua_isstring`, offset 1312).
   - `unresolved Lua functions after call-graph recovery: ...` → run aborted; exit code = 1 per binary (client+server → RC=2), DB not written.
4. Cross-check addresses in Ghidra: base anchor is `index2adr` (Windows r759671 `0x140482210`); `offset = entry - base`. `search_functions` uses substring matching, not `^...$`.

## Known failure on r759671
Reference VS2008 build uses `InlineFunctionExpansion=1` (OnlyExplicitInline), no LTCG; the game’s embedded Lua 5.1.4 was built with AnySuitable inlining. These differ by body and never byte-match:

| name | game entry | offset | note |
|---|---|---|---|
| `luaL_pushresult` | 0x1404840F0 | 7920 | `lua_pushlstring` path inlined |
| `lua_getupvalue` | 0x1404838B0 | 5792 | `aux_upvalue` inlined |
| `lua_isstring` | 0x140482730 | 1312 | `lua_type`+index2adr inlined |
| `luaL_prepbuffer` | 0x140483FF0 | 7648 | mis-resolved by graph-seed to 1312 |

Options: rebuild reference with `/Ob2` (or `/GL`), or add the names to `src/missfunc.txt` (not required for LuaJIT replacement).

## In-game Auto path
Same code (`SignatureUpdater::create_or_update`); a stale DB missing a newly exported name forces regeneration at load time, so avoid shipping an old DB with new reference exports.
