---
name: dst-custom-lua-api-signature-pipeline
description: "Adding a Klei/custom Lua API to DST's Lua-module replacement and signature pipeline (src/lua51 export + LuaJIT export + LuaApi.hpp), including signature regeneration caveats"
---

## When
You need a Klei-added Lua API (e.g. `lua_setchunkname`, a custom getter) to work under the mod's LuaJIT replacement, or the game function must be swapped for a DS-specific implementation.

## Do not
- Never hand-edit `Mod/signatures_{client,server}.json`; they are generated caches (`SignatureJson::update_signatures` rewrites them).
- Do not resolve VM exports ad hoc with `gum_module_find_export_by_name` in hook code; the API table is the contract.

## Add the API (4 places)
1. `src/lua51` reference build (this is the name/feature source for the matcher):
   - implement the function in `src/lua51/src/lapi.c` (mirror the engine body so train features match),
   - declare in `src/lua51/src/lua.h` (and `lua_head.h` if used),
   - export in `src/lua51/lua51.def` with the **exact name LuaJIT will export** (`lua_ds_*` for DS-only APIs).
2. LuaJIT (`luajit/src`): export the same name (`LUA_API ...`); declare it in `luajit/src/lua.h` **unconditionally** — `lua.h` is included before `lj_arch.h`, so `#if LJ_DS_*` guards there are always off for external consumers.
3. `src/DontStarveInjector/plugins/plugin_core_vm/LuaApi.hpp`: `_(name)` in `LUA_API_DEFINES`. This creates `ctx->api._name`, loads it per VM, and makes `GetLuaExport(name)` return it.
4. Nothing else: `GameLuaContextImpl::ReplaceApis` iterates the reference module's exports and swaps the matched game entry for `GetLuaExport(name)`.

## Generate/validate signatures
- In-game Auto path and the offline tool are the same code (`SignatureUpdater::create_or_update`).
- Offline: `signature_updater.exe create` (built from `tools/Creater`), configured with `GAMEDIR`, `LUA51_PATH=<mod>/deps/lua51.dll`, `WORKER_DIR=<mod>`; writes `signatures_client.json` / `signatures_server.json`.
- The reference `lua51.dll` MUST be the official VS2008 build. The game exe is VS2008 SP1 (msvcr90/msvcp90, Rich builds 21022/30729); a VS2022-built reference loses byte matches and `create` degrades to long graph-seed inference.
- Expected success line: `update signatures [name:0x...]: 0 to <offset>` (offset relative to the Lua anchor `index2adr`).
- If `create` AVs on a tiny Klei accessor (seen: `lua_isunsafedataallowed`), add the name to `src/missfunc.txt` and regenerate `src/missfunc.h` via `python tools/missfunc.py`.

## Verify
- Build outputs export the name (grep the DLL for it).
- In game, log shows the generic `replace <name> (fast): ...` line.
- The feature works with the LuaJIT VM and the PUC VM both (reference export covers PUC).
