---
name: dst-luajit-custom-lua-api-signature
description: "Add a custom/private Lua entry point to the DST LuaJIT replacement end-to-end: reference lua51 export, LuaApi table, generated signature DB, and the signature_updater pitfalls."
---

# Adding a custom Lua API to the DST LuaJIT replacement

Use when a game-side Lua entry point must be swapped for a LuaJIT implementation
(new Klei addition, private helper, or anything not in the stock Lua C API).

## Model

- The engine statically links PUC Lua 5.1. `plugin_core_vm` finds game-side Lua
  functions through the **reference module** (`src/lua51`, a PUC build whose
  exports are enumerated) plus `signatures_{client,server}.json`.
- `ReplaceApis()` iterates the reference module's exports, resolves each name to
  `signatures.funcs.at(name).offset` relative to `luaModuleSignature.target_address`
  (the `index2adr` address), and replaces the game function with the same-named
  export of the active VM module.
- Therefore a custom API needs **the same name in three places**: reference
  `src/lua51` export, the active VM (LuaJIT `LUA_API`), and `LuaApi.hpp`'s
  `LUA_API_DEFINES` (so it lands in `ctx->api._name` and `GetLuaExport`).

## Steps

1. **Implement in the reference PUC build** (`src/lua51`):
   - body must mirror the engine function's shape (the matcher is feature/train
     based, not name based);
   - `src/lua51/lua51.def`, `src/lua51/src/lua.h`, `src/lua51/lua_head.h`,
     tests (`src/lua51/test/klei_additions_test.c`).
2. **Implement/export in the VM** (`luajit/src/lj_api.c`, `lua.h`,
   `lj_obj.h` if a field is needed). Public declarations in `luajit/src/lua.h`
   must be **unconditional or defaulted in lua.h**: lua.h is included before
   `lj_arch.h`, so `#if LJ_DS_*` hides them from the injector.
3. **API table**: add `_(name)` to `LUA_API_DEFINES` in
   `plugins/plugin_core_vm/LuaApi.hpp`. This gives `api._name` in every context
   and lets `GetLuaExport` match it.
4. **Do not hand-edit** `Mod/signatures_{client,server}.json` (generated).
   If a bootstrap is unavoidable, merge fixed entries in
   `SignatureJson::read_from_signatures()` (a generated entry must win);
   remove it once generation works.
5. **Generate**: build target `signature_updater`, then run
   `tools/Creater/Debug/signature_updater.exe create` (paths are baked in:
   `GAMEDIR`, `LUA51_PATH=Mod/deps/lua51.dll`, `WORKER_DIR=Mod`). It rewrites
   both JSONs; a full `create` takes minutes (per-export train match, then
   graph-seed inference, client + server).
6. **Verify**: the JSON entry's `offset`/`pattern` must hit
   `base + offset`; `create` logs `update signatures [name:0x...]: 0 to <offset>`.
   Then run the game and look for `replace <name> (fast): ...`.

## Pitfalls seen in practice

- `lua_isunsafedataallowed` (Klei 1-instruction accessor) makes
  `signature_updater create` **AV-crash (0xC0000005)** after printing
  `try create signature [lua_isunsafedataallowed]`. Temporarily add it to
  `src/missfunc.txt`, run `python tools/missfunc.py`, rebuild the tool; decide
  separately whether to exclude it permanently (it would otherwise also crash
  in-game regeneration).
- Offsets are per game build but identical for client/server when the Lua
  layout is unchanged (r759671: custom chunkname setter 6304, getter 6416).
- Tool needs `vcpkg_installed/x64-windows-custom/debug/bin` on PATH for
  spdlogd/fmtd; running the exe directly without it exits silently.
- Check the tool's real exit code without a pipe (`| tail` masks it).
- On Linux the JSON is regenerated in-place on that machine; Windows patterns
  in a seed entry will simply invalidate and trigger regeneration.

## Related finding (do not re-derive)

The DST item-server call-stack guard (`BarterLoseItem`/`BarterGainItem`/
`BarterLoseDuplicateItems`) compares the formatted Lua stack against a
hardcoded trace and, on mismatch, **locally fabricates**
`{"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}` (UI: "Failed to contact
Klei Servers"). Chunk names come from the Klei-added `Proto+0x78` field written
by `lua_setchunkname`, not from `lua_getinfo`. LuaJIT provides
`lua_ds_setchunkname` / `lua_ds_getfuncchunkname` for exactly this pair.
