---
name: static-lib-symbol-coverage-and-layout-bypass-audit
description: "Audit a statically linked library's symbol coverage and API-boundary (VM layout) bypasses in Ghidra: blob census, luaL_Reg slot naming, mis-name detection via \"extras\", inlining verdicts."
---

# Auditing symbol coverage + API-boundary bypasses in a statically linked library

Context: a library (e.g. PUC Lua 5.1) is statically linked into a big PE. You have a reference build
with full symbols (`lua51ref.dll`) and a Ghidra DB of the target.

## 1. Delimit the blob

- Function-level census of a candidate address range (`DstRegionGaps.java`): uncovered bytes in the
  range must be padding (`0xCC`), jump tables (4-byte offsets) or already-explained fragments.
  Dump them (`DstGapDump.java`, min size 8) before concluding anything.
- Confirm no stray copies elsewhere: sort all library-style names by address and check the region
  outside the blob; then check that a *core* symbol is only called from inside the blob
  (e.g. every caller of `luaD_throw` / `panic` lives in the range).

## 2. Definition-level naming (exact, no similarity)

- Scan non-executable memory for `{char* name, fn*}` pairs, then chain-match the library's
  `luaL_Reg`-style tables by *contiguous 16-byte stride and identical name sequence*
  (`DstLuaRegScan2.java` accepts pointers into executable memory even when no function exists yet;
  create the missing ones with `DstCreateAndName.java`, e.g. `getS`).
- Compare the target's table contents against the reference build's: tables that differ prove
  *removed* APIs (e.g. os.execute/os.getenv, io.popen/io.tmpfile) — definition-level evidence, not
  "matching failed".

## 3. The trap: `absent` vs `mis-named`

Never treat "no function with name N" as "N is absent".

1. Build `ref_names` (all library names) and `blob_names`.
2. List blob functions whose name is **not in** `ref_names` (= "extras").
3. Decompile each extra:
   - body matches an upstream function => it is a **mis-named** upstream symbol (cross-arch transfers
     love to stamp engine methods onto library code); rename it.
   - otherwise => genuine downstream addition (document it as such).
4. Only after that step, produce per-name verdicts: `named` / `absent:inlined` /
   `absent:no-out-of-line-copy` / `absent:removed` / `absent:merged`, each with evidence
   (caller-match + callee-set superset, or table diff, or census).

Real examples of extras that were mis-names: `hb_lazy_loader_t<...>::get` = `lua_pushcclosure`,
`jsonp_error_set_source` = `luaO_chunkid`, `btStaticPlaneShape::setLocalScaling` = `lua_setlevel`,
`EntityLuaProxy::SetParent` = `add_value`, `cNetworkRPCManager::CallLuaClientRPC` = `ll_register`,
`SimLuaProxy::Crash` = `aux_close`, `PlotLines` = `g_write`,
`SimLuaProxy::GetFileModificationTime` = `pusherror`, `GetMinimumRadiusForPointsLua` = `luaL_checkany`.

## 4. API-boundary bypass scan (who hardcodes the VM layout)

Run **two** scanners; either alone gives a false negative.

(a) Engine side, anchored on the public API:
  - decompile every function that calls `^libprefix_` symbols;
  - take the balanced first argument expression of each call (`*(undefined8 *)(this + 0xb0)` etc.);
  - search for `(EXPR + 0x...)` in the same function.
  - Batch <=500 functions per script invocation (MCP request timeout); report false positives and
    dismiss them by identity of the anchored object.

(b) Library side, no anchor:
  - inspect every "extra" from step 3 plus every non-upstream helper for the known structure offsets
    (state `top/ci/base`, `TValue.tt @8`, closure `l.p`, proto `source`, `sizeof(lua_Debug)`);
  - a scan that requires an API call will miss helpers that call *internal* symbols
    (`index2adr`, `aux_upvalue`) — that is exactly how `luaGetFuncChunkName` was missed.

Report both layers separately: "engine bypasses: 0; library-internal hardcoding: these 3 additions".

## 5. Also worth reporting

- hardcoded ABI constants: pseudo-indices (-10000/-10001/-10002), `sizeof(lua_Debug)=0x78` strides,
  per-function counts (`DstLuaConstScan.java`).
- private VM entry points the engine calls (`lua_setupvalue_byname`, `luaL_geterrortext`).
