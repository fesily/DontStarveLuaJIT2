---
name: stripped-pe-puc-lua-core-symbol-recovery
description: "Recover luaV_/luaH_/luaD_/luaS_/luaC_ symbols in a stripped PE that statically links PUC Lua (Ghidra MCP), and separate engine-side layout pokes from core internals."
---

# Naming a statically-linked PUC Lua core in a stripped PE (Ghidra MCP)

Use when a stripped Windows x64 binary statically links PUC Lua 5.1/5.3 and you must recover
`luaV_*`/`luaH_*`/`luaD_*`/`luaS_*`/`luaC_*`/`luaG_*`/`luaF_*`/`luaT_*` symbols.

## 0. Prerequisite gotcha
`run_ghidra_script` / `run_script_inline` run on the **currently active program**. If a different
program is open, the script silently runs there and dies with
`AddressOutOfBoundsException: Offset must be between 0x0 and 0xffffffff`. Always
`switch_program` to the target first, and pass `program` on the MCP decompile/xref tools.

## 1. Locate the Lua module
- `list_exports` / `list_imports` show no `lua*` for static links. Instead: `search_strings`
  `"Lua 5"` → versioning string (e.g. `Lua 5.1.4`), and `search_functions` `lua` → the named API
  cluster (lapi). Anchor range = [first `lua_*` body, last `luaopen_*`].
- Do NOT expect one giant `luaV_execute` to be the largest function in that neighbourhood; confirm
  by body, not size (the real VM was 5 KB here, next to worldgen code far larger).

## 2. Find the interpreter (decisive trick)
1. `search_strings` `perform arithmetic|attempt to index|attempt to compare` → get `luaG_aritherror`
   via `get_xrefs_to` on the string (the function containing the DATA xref).
2. `get_xrefs_to` that function and list caller functions with sizes.
3. The caller with **two** call sites and a mid-size body is `luaV_execute`. Disassemble its entry to
   confirm: `ci=[L+0x28]` → `func=[ci+8]` → `cl=*func` → `p=[cl+0x20]` → `code=[p+0x10]`, loop reads
   `[L+0x64]` (hookmask) and decrements `[L+0x6c]` (hookcount), `ins=*pc++`.

## 3. Fan out from the named API (highest yield)
For each named API function (`lua_gettable`, `lua_settable`, `lua_objlen`, `lua_next`,
`lua_createtable`, `lua_call`, `lua_pcall`, `lua_pushlstring`, `lua_newuserdata`, `lua_close`,
`luaL_loadfilex`), list callees; the single unnamed non-leaf callee is the internal:
`lua_gettable→luaV_gettable`, `lua_settable→luaV_settable`, `lua_next→luaH_next`,
`lua_createtable→luaH_new`, `lua_objlen→luaH_getn`, `lua_call→luaD_call`,
`lua_pcall→luaD_pcall`, `lua_newuserdata→luaS_newudata`, `lua_pushlstring→luaS_newlstr`.

## 4. Discriminate siblings by body semantics (never by size alone)
- `luaV_arith`: switch over TMS 5..11 (add/sub/mul/div/mod via floor/pow/unm), calls `luaG_aritherror`.
- `luaV_concat`: `"string length overflow"`, TString len@+0x10 / data@+0x18, interns via `luaS_newlstr`.
- `luaV_lessthan` / `luaV_lessequal`: TM events 0xd/0xe + `l_strcmp`.
- `luaV_tostring`: `sprintf("%.14g")` then rewrite tt=4.
- `luaD_call`: nCcalls@L+0x60 ++/--, `"C stack overflow"` at 200, calls `luaD_precall` then
  `luaV_execute` when precall returns 0, `luaC_checkGC` when gcrunning@L+0xc0.
- `luaD_pcall`: saves ci/base/errfunc@L+0xb0/nCcalls/allowhook, calls `luaD_rawrunprotected`,
  error path → `luaF_close` + `luaD_seterrorobj`.
- `luaH_getn`: binary search for nil in the array part (stride 0x10, size@table+0x38) then unbound_search.
- Upvalue helpers (ldebug): read `Closure.isC@0xa`, `l.p@0x20`, `Proto.sizeupvalues@0x48`,
  `Proto.upvalues@0x38`, `UpVal.v@0x10`; one of them also returns `Proto.source@0x78 + 0x18`
  (TString data) — i.e. chunk-source getter, a sibling of `lua_getinfo`.

## 5. Apply names with evidence
Write a TSV `addr<TAB>name<TAB>tier<TAB>evidence` and run `DstApplyNames.java <tsv>,apply`
(or your equivalent rename script). Keep the evidence column factual (offsets, string literals, call
sites) so later waves can audit it. Save the program, re-run `DstExportNames.java` to refresh the
name snapshot, and only then recompute any ledger/metrics built on it.

## 6. Then answer the real question: who touches internals?
With the core named, compute both directions over the call graph:
- engine → core **internals** (names not starting `lua_`/`luaL_`): expect ~0 hits; if 0, engine cannot be
  calling internals and any layout dependence must be memory reads.
- core → engine: `luaL_loadfilex` calling engine file loaders and `luaC_checkGC` calling engine thunks
  reveal the game's own patches to the Lua build.
- Memory-layout pokes are then found by reading the candidates, not by offset heuristics: offset
  vocabularies (0x10/0x18/0x20/0x28, `cmp dword [r+8], imm`) give hundreds of false positives
  because every engine struct has those fields.
