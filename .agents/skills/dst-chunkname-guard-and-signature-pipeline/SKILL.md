---
name: dst-chunkname-guard-and-signature-pipeline
description: "Use when DST unravel/weave fails under a LuaJIT/client mod (E_BALANCE_MISMATCH), or when adding/verifying the chunkname-marker custom Lua APIs and regenerating Lua signatures"
---

# DST item-server chunkname guard (unravel/weave disabled under LuaJIT)

## Symptom
Client log: `[BarterLoseItem_Complete Failure:200] {"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}`; UI says "Failed to contact Klei Servers". Signature/pricing/inventory load fine (`saved pricing_cache`, `saved inventory_cache_prod`). Only mods that swap the Lua VM (LuaJIT) reproduce it; restart does not help; disabling the mod fixes it.

## Root cause (client-side, not server)
`cItemServerLuaProxy::BarterLoseItem` (and GainItem/duplicates) formats the whole Lua stack through a private formatter and byte-compares it with a hardcoded expected trace. On mismatch the client itself fabricates the E_BALANCE_MISMATCH JSON. The per-frame chunkname comes from a private helper that walks PUC Lua 5.1 layout:

    TValue.tt(+0x8)==6 -> Closure.isC(+0xA)==0 -> Proto(+0x20) -> Klei field(+0x78, TString*) -> data(+0x18)

`+0x78` is NOT stock `Proto.source`; it is filled by `lua_setchunkname` -> `setproto_chunkname` right after `luaL_loadbuffer` (DoLuaFile stores the bare path while the loader name is `"@"+path`; kleiloadlua uses the bare name). Under LuaJIT those layouts do not exist -> NULL for every frame -> trace renders `[**untrusted** ...]` -> guard always fails.

## Addresses (r759671)
| item | Windows | Linux |
|---|---|---|
| chunkname helper | 0x140483B20 | 0x4AC6D0 |
| lua_setchunkname | 0x140483AB0 | 0x4AC670 |
| trace formatter | 0x1401010E0 | ~0x1C13xx |
| index2adr (signature base anchor) | 0x140482210 | from lua_topointer offset |

Signature offsets are relative to the index2adr anchor: helper 6416, setter 6304 (client and server agree for r759671).

## Correct fix (custom Lua APIs, no runtime export lookup)
1. `src/lua51` reference build exports `lua_setfuncchunkname` / `lua_getfuncchunkname` (Klei Proto field at +0x78; getter returns NULL for C closures/unmarked).
2. LuaJIT `lj_api.c` exports the same names; declarations in `lua.h` must be unconditional (lua.h is included before lj_arch.h).
3. `LuaApi.hpp` `LUA_API_DEFINES` lists both, so every VM context has `ctx->api._lua_setfuncchunkname` / `_lua_getfuncchunkname` and `ReplaceApis` swaps the game entries automatically.
4. Do NOT add ad-hoc MemorySignature hooks for these; the standard replace pipeline covers them once signatures exist.

## Verify / regenerate signatures
- Reference `Mod/deps/lua51.dll` must be VS2008 SP1. Check: `grep -a msvcr90.dll`; decode PE Rich header (product 0x83/0x84, build 30729). VS2022-built references make the trainer degrade into graph-seed and hang.
- Build tool: `cmake --build builds/ninja-multi-vcpkg --config Debug --target signature_updater`
- Run (needs vcpkg debug DLLs on PATH):

      set PATH=<repo>\builds\ninja-multi-vcpkg\vcpkg_installed\x64-windows-custom\debug\bin;%PATH%
      signature_updater.exe create

  `create` ignores the stored DB and rebuilds every entry; log lines `update signatures [lua_getfuncchunkname:...]: 0 to 6416` / `[lua_setfuncchunkname:...]: 0 to 6304` prove auto-detection.
- `signatures_{client,server}.json` are generated caches — NEVER hand-edit; back up before test runs.
- Tiny Klei accessors (e.g. `lua_isunsafedataallowed`, 5-byte leaf) can AV the trainer (0xC0000005). Add them to `src/missfunc.txt` and run `python tools/missfunc.py`.

## Diagnosing a stale/wrong reference
- Dump the DLL export table (PE export directory) and compare with `src/lua51/lua51.def`.
- Chunkname names went through a rename: old draft `lua_ds_*`, final `lua_setfuncchunkname` / `lua_getfuncchunkname`; grep the right names.

## Ghidra pitfalls
- Same-named program in the project is NOT replaced by `load_program`; load a copy under a new name and always pass `program=` to MCP calls; `current_program` may stay on another program.
- The helper is often merged into a neighbouring function: disassemble at the entry, trim the parent body, then create the function; name it `lua51::luaGetFuncChunkName` with prototype `char *(void *L, int idx)`.
