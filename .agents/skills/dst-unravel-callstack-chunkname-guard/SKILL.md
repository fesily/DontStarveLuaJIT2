---
name: dst-unravel-callstack-chunkname-guard
description: "DST unravel/weave disabled with LuaJIT mod: locate the client call-stack guard and chunkname helper, wire lua_setfuncchunkname/lua_getfuncchunkname as custom APIs, and build the reference lua51 with matching inlining (/Ob2)."
---

# DST unravel/weave disabled under LuaJIT (call-stack guard)

## Symptom
With the LuaJIT mod enabled, unravel/weave always fails; UI shows
"Failed to contact Klei Servers". client_log.txt shows
`[BarterLoseItem_Complete Failure:200] {"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}`
while signature/pricing/inventory loads succeeded (`saved pricing_cache`, `loaded inventory_cache_prod`).
Restarting does not help; disabling LuaJIT fixes it.

## What the guard is
- The client formats the whole Lua stack of `TheItems:BarterLoseItem`
  (and BarterGainItem / BarterLoseDuplicateItems) and byte-compares it with a
  hardcoded expected trace; mismatch fabricates the JSON above locally.
- Expected trace lives in .rodata (`[C]:-1[string 'scripts/screens/redux/barterscreen.lua']:114...`).
  Linux r759671 has both `:86` and `:114` variants.
- Per-frame name comes from an engine-private helper, NOT lua_getinfo:
  - Windows `lua51::luaGetFuncChunkName` = 0x140483B20; Linux 0x4AC6D0.
  - chain: index2adr -> TValue.tt@+8==6 -> Closure.isC@+0xA==0 ->
    Proto@+0x20 -> Klei field@+0x78 (TString*) -> data@+0x18.
  - populated by `lua_setchunkname` (Win 0x140483AB0 / Linux 0x4AC670) ->
    `setproto_chunkname`, called after luaL_loadbuffer by DoLuaFile / kleiloadlua.

## Fix pattern
1. Treat both engine functions as custom Lua APIs:
   - LuaApi.hpp: add `_(lua_setfuncchunkname)` / `_(lua_getfuncchunkname)` to
     LUA_API_DEFINES so ctx->api holds them and GetLuaExport finds them.
   - src/lua51 reference build exports same names (getter mirrors the helper).
   - LuaJIT exports same names (dschunkname marker field + setter/getter).
   - ReplaceApis then swaps the game functions; no ad-hoc MemorySignature hooks.
2. Signatures are generated, never hand-edit signatures_*.json:
   - offsets relative to index2adr base: 6304 (setter) / 6416 (getter),
     same on client and server r759671.
   - `signature_updater create` auto-resolves both via train match.

## Reference build matters (inlining)
- Build the reference src/lua51 with VS2008 cl, `/O2 /Ob2 /MD`, LUA_BUILD_AS_DLL.
- The stock Release|x64 project used Optimization=3 + InlineFunctionExpansion=0,
  so lua_isstring / lua_getupvalue / luaL_pushresult (same-TU static helpers
  inlined in the shipped Lua) failed byte match, fell into graph-seed for
  10+ minutes, and mis-resolved luaL_prepbuffer (1312/131712 instead of 7648).
- No .sln/msbuild if .NET is absent: invoke cl directly from
  tools/vcc2008varsamd64.bat, output release\lua51.dll (+ .lib).

## Verification
- client_log: `[BarterLoseItem_Complete Success:200] ... "NewCurrency":...`
- signature_updater create: no `has no byte match` for the 3 functions;
  offsets 6304/6416; run completes and writes the JSON.
