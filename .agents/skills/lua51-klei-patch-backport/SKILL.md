---
name: lua51-klei-patch-backport
description: "Port client-only Klei patches into src/lua51 with LUA_KLEI_* switches: probe struct offsets, patch API/fields/guards, wire GC marking + preinit, verify with a linked regression test"
---

# Backport a shipped client's private Lua patches into `src/lua51/`

Use when the vendored Lua source must reproduce behaviour that only exists in a
shipped binary (extra entry points, struct fields, sandbox guards, lexer
changes), or when auditing "is this Klei's or PUC's?".

## 1. Establish ground truth

- `grep -rn "Klei" src/lua51/src/*.c src/lua51/src/*.h` and
  `grep -rn "LUA_KLEI_" src/lua51/src/lua.h` — the vendored tree is Klei's and
  annotates its own patches. That block is the authority, not
  `src/lua51original` (also pre-patched).
- Diff the binary against the vendored inventory: names in the Lua region that
  the vendored build does not produce = candidate additions. Classify each
  (decompile, not guess): stock function under a 5.2/5.3-style name, macro
  out-of-line copy, compiler-split half, or genuine Klei addition.
- Cross-arch/neighbour transfers leave engine names on Lua functions
  (`jsonp_error_set_source` for `luaO_chunkid`, `PlotLines` for `g_write`, ...).
  Verify every suspicious name by body before trusting it.

## 2. Pin the ABI with a compile-time probe

Write a throwaway `probe.c` that includes `lstate.h`/`lobject.h` and prints
`offsetof`/`sizeof` for every field you touch; compare with the offsets the
binary's own code uses. Do this BEFORE editing: it tells you exactly where the
new field must land (e.g. appending a pointer to `Proto` puts it at 0x78 only
because stock `sizeof(Proto)` is 0x78; `allowed_unsafedata` lands at 0xC1 only
because it directly follows `allowed_gcstep` at 0xC0).

## 3. Patch behind one switch per feature

- Add `#ifndef LUA_KLEI_<FEATURE> / #define ... 1 / #endif` to the Klei block in
  `lua.h`, extend its doc comment, declare the new `LUA_API` entry points there.
- Keep the client's semantics, not a nicer variant: same argument order, same
  accept/reject sets, same error strings (`luaL_error(L, "invalid filepath")`).
- C89: declarations before statements — restructure blocks instead of inserting
  statements above a `FILE **pf = newfile(L);`.
- Add the symbols to `lua51.def` and `lua_head.h` (both are hand-maintained).

## 4. Two pitfalls that only bite at runtime

- **Any new GC object field must be marked**: add it to the matching
  `traverse*()` in `lgc.c` (`stringmark` for `TString*`), and NULL it in the
  constructor (`luaF_newproto`). Otherwise the string is collected and the field
  dangles after the next full cycle.
- **Any new state byte must be cleared in `preinit_state`** (`lstate.c`).
  Uninitialised heap bytes look like a random flag value and silently flip a
  sandbox path on.

## 5. Verify

- `src/lua51/test/klei_additions_test.c` is the pattern: link the library
  objects (drop `loadlib.c`, stub `luaopen_package`), open io through
  `lua_cpcall` because `luaopen_io` installs its table as the C functions'
  environment and panics with "no calling environment" at top level.
- Assert behaviour, not just "no crash": literal parsing, the recursive field
  set (walk `Proto.p[]` directly) plus two `collectgarbage('collect')` cycles,
  each accept/reject path, getter/setter round-trip.
- Recompile the whole library with every switch `0` and confirm the behaviour
  disappears (negative control) and the tree still builds.

## 6. Commit scope

Stage only the source-tree paths (`git add src/lua51`); this repo usually has
unrelated pending edits (`.vscode/`, `CHANGELOG*`, `luajit` submodule) that must
not ride along.
