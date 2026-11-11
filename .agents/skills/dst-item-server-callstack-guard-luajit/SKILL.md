---
name: dst-item-server-callstack-guard-luajit
description: "DST unravel/weave fails under a LuaJIT VM swap with a fake E_BALANCE_MISMATCH: client-side call-stack anti-tamper guard, FUN_140483B20 PUC-layout chunkname extraction, fix by hooking it."
---

# DST item-server call-stack guard vs LuaJIT

## Symptom
With a Lua-VM-replacement mod (LuaJIT), unravel/weave/barter fails every time, restart does not help, disabling the mod fixes it. `client_log.txt` shows:

```
[BarterLoseItem_Complete Failure:200] {"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}
ERROR: Failed to contact the item server. status=	FAILED_TO_CONTACT
```

but `Account Communication Success`, `saved .../pricing_cache` and `saved .../inventory_cache_prod` are all present.

## Read the log correctly
- `Failure:200` + JSON = a *client-side* verdict (HTTP 200 is synthetic).
- `FAILED_TO_CONTACT` is only the status argument printed by the popup's OK callback (`barterqueue.lua:91`), not a network event.
- The popup text comes from `STRINGS.UI.BARTERSCREEN.FAILED_TITLE/BODY` (`strings.lua`, "Failed to contact Klei Servers"), so it is misleading.

## Verified mechanism (r759671, PE TimeDateStamp 0x6ADA8C08)
1. `TheItems:BarterLoseItem` binding `0x14020D1E0`:
   - `trace = FUN_1401010E0(&str, L)` — formats every frame as `[C]:line` or `[string '<chunkname>']:line`.
   - compares with the hardcoded expected stack at `DAT_140680C08` (initialized by `FUN_1404B68F0`; contains `barterscreen.lua:114` … `input.lua:752`).
   - on mismatch: fabricates `{"Error":"true","ErrorCode":"E_BALANCE_MISMATCH"}` (`0x1404FDC58`) and calls the completion callback with fail/200. **No HTTP request is sent.**
2. Chunkname extraction uses `FUN_140483B20`, which hard-parses PUC 5.1 object layout on the function pushed by `lua_getinfo('f')` (`lua_topointer`, tag at +8, `proto+0x20`, `+0x78`, `+0x18`).
3. A VM swap replaces `lua_getinfo` with LuaJIT's `lua_getinfo_game`, so those offsets read LuaJIT structures → helper returns 0 → frames render `[**untrusted** ...]` → mismatch is guaranteed.
4. Same pattern exists on the other item-server entry points (`BarterGainItem_Complete`, `BarterLoseDuplicateItems_Complete`, purchase/report paths reference the same `FAILED_TO_CONTACT` status).

## Diagnose a new report
- Confirm the guard fired: `grep -n "BarterLoseItem_Complete\|E_BALANCE_MISMATCH" client_log.txt`.
- Confirm client data is healthy: `saved pricing_cache` and `saved inventory_cache_prod(_sig)` present; optional in-game `=TheItems:GetBarterSellPrice("wilson_none"), TheInventory:CheckOwnership("wilson_none")`.
- If the error is truly absent and the button is just grey: check `CurrencyMap.SPOOLS` in `client_save/inventory_cache_prod` and the generic Lua gates (`skinsutils.lua IsUserCommerceSellAllowedOnItem`).
- Always verify which program Ghidra has open (PE TimeDateStamp / `.text` size); `load_program` does not replace an existing same-named program.

## Fix direction (lightest first)
- Hook `FUN_140483B20` by signature and, for LuaJIT Lua functions, return the chunkname (`lua_topointer` → `isluafunc` → `funcproto` → `proto_chunkname` → `strdata`, strip leading `@`); keep returning 0 for other values so the existing comparison stays intact.
- Do not globally change `lua_getinfo('f')` semantics (debugger/other callers depend on it).
- Bypassing the string comparison works but is an anti-cheat bypass and breaks on client updates.
- Note the latent bug in `luajit/src/lj_debug.c:lua_getinfo_game`: `ar->source` is assigned before `memcpy(ar,&iar,...)`, so the `@`-strip is dead code (assign `iar.source` instead).

## Verify the fix
After the change, with the mod enabled the log should read `[BarterLoseItem_Complete Success:200]` with `"Error":false` and `NewCurrency`, and `E_BALANCE_MISMATCH` must no longer appear.
