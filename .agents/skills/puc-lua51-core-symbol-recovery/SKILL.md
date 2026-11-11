---
name: puc-lua51-core-symbol-recovery
description: "Symbolize a statically linked PUC Lua 5.1 core in a stripped PE via luaL_Reg table scan, Lua error-string anchors, and call-graph anchors; not LuaJIT or same-arch version migration"
---

# Recovering PUC Lua 5.1 symbols in a stripped PE (x64)

Use when the binary statically links Lua 5.1 and Ghidra only has the public API named.

## 0. Confirm the version and the module window
- Search strings for `Lua 5.1.<n> Copyright` and for `perform arithmetic on` / `attempt to compare`.
- Named API functions (`lua_*`, `luaL_*`) cluster in one address range; the internals live around it. Do NOT expect one giant `luaV_execute` by size alone at first — locate it structurally (step 3).

## 1. Highest-yield pass: luaL_Reg tables (zero guessing)
Scan `.rdata` for runs of 16-byte entries where `[+0]` points to a short printable identifier and `[+8]` points into the code range; stop at `{0,0}`; require >= 3 entries and skip addresses whose preceding 16 bytes are also a valid pair (to land on table start).

Ghidra inline script shape:

```java
for (long a = rdataLo; a < rdataHi; a += 8) {
  long p0 = mem.getLong(toAddr(a)), p1 = mem.getLong(toAddr(a + 8));
  if (isPair(a - 16)) continue;            // must be table start
  if (!printableName(p0) || p1 < codeLo || p1 >= codeHi) continue;
  // walk to {0,0}, emit "table\tluaname\tfuncaddr"
}
```

Each hit gives `luaopen_<lib>` / `luaL_register`-style tables (base, coroutine, string, table, math, os, debug, io, io.file, openlibs). Map the Lua-visible name to the canonical 5.1 C identifier (`len`->`str_len`, `sin`->`math_sin`, `insert`->`tinsert`, `getinfo`->`dbg_getinfo`, `print`->`luaB_print`, `flush` in the file table ->`f_flush`, `__gc`->`io_gc`).

Some entries are 10-byte thunks Ghidra never defined; run `createFunction(addr, null)` then rename.

## 2. Second pass: string anchors (lexer / parser / undump)
Iterate defined strings, match substrings, then map references to the containing function:

| string | function |
|---|---|
| `unfinished string` | `read_string` |
| `malformed number` | `read_numeral` |
| `unexpected symbol` | `primaryexp` |
| `function arguments expected`, `ambiguous syntax (function call x new statement)` | `funcargs` |
| `no loop to break` | `gotostat` |
| `chunk has too many syntax levels` | `enterlevel`, and every function with it inlined (`block`, `subexpr`) |
| `%s: %s in precompiled chunk` with `unexpected end`/`bad integer`/`bad constant` | `LoadBlock`/`LoadInt`/`LoadFunction`/`LoadConstants` |

## 3. Third pass: call-graph anchors
- `luaD_call`: increments `L->nCcalls`, raises `C stack overflow` at 200, then `if (callee(...) == 0) luaV_execute(L,1)` -> the callee is `luaD_precall`.
- `lua_pcall` -> `luaD_pcall`; its callees give `luaD_rawrunprotected`, `luaD_seterrorobj`, `luaF_close`.
- `lua_close` -> `luaF_close`, `luaC_freeall`, `luaS_freeall`, `luaD_freestack`.
- `luaH_new` -> `luaC_link`, `setnodevector`, `luaH_resize`; `luaH_get` -> `luaH_getstr`? (string keys) / `luaH_getnum`.
- `luaV_gettable/settable` -> `luaT_gettmbyobj`, `luaT_callTM`, `luaH_get`, `luaH_set`.
- `luaV_arith` -> `luaT_trybinTM`, `luaG_aritherror`; `luaV_concat` -> `luaG_runerror("string length overflow")`.
- `luaL_loadfilex` / `luaL_loadbuffer` -> `lua_load` (does `luaZ_init` itself) -> `luaD_protectedparser` (does `luaD_pcall`).

## 4. Verify the interpreter structurally
`luaV_execute` prologue: `ci=[L+0x28]`, `func=[ci+8]`, `cl=*func`, `p=[cl+0x20]`, `code=[p+0x10]`, `base=[L+0x18]`; loop reads `[L+0x64]` (hookmask), `ins=*pc++`, decrements `[L+0x6c]` (hookcount).

## 5. Guardrails
- Any pre-existing name inside the Lua region may come from a cross-architecture fingerprint and be wrong; verify by body (e.g. `vector::insert`/`get_line` were `LoadFunction`/`LoadConstants`).
- Record a tier per symbol: `luaL_Reg-table` (certain), `body` (certain), `callers`/`callees` (high), `call-site` (medium).
- Apply with an address->name TSV + a rename script; re-export names afterwards; the export may need the program switched to the right target first (script tools act on the *current* program).
- `lua_topointer` in such builds is frequently really `index2adr` (returns `TValue*` and resolves every pseudo-index); confirm before using it as the escape hatch.
