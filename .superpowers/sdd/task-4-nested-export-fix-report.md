# Task 4 Important Finding Fix: export-aware span split

**Branch:** `feature/nucleus-function-body`  
**Worktree:** `C:/Users/fesil/DontStarveLuaJIT2/.worktrees/nucleus-function-body`  
**Date:** 2026-08-07  

## Problem

Nucleus often emits one large outer span that wholly contains later export
entry-points (e.g. `lua_yield` outer body covering `lua_resume`). After Task 4
tightest-container lookup, `containing(resume)` still returned the outer start
because no dedicated resume span existed → both symbols shared offset `26480`
(yield entry).

## Fix (no per-symbol names)

1. `FunctionTable::split_at_known_entries(entries)`  
   For each parent span `[S,End)` and sorted interior known VAs `e_i` with
   `S < e_i < End`, emit sub-spans `[S,e0), [e0,e1), …, [en,End)`.

2. `nucleus_analyze_file` — after mapping Nucleus functions, split on all
   PE `SYM_TYPE_FUNC` export VAs from the loaded Binary.

3. `apply_nucleus_function_table` — after process-VA remap, split again on
   module known function addresses; size rule is always
   `fn.size = End - fn.address` (keep address = export VA `E`, never move to `S`).

## Verification

```text
test_nucleus_adapter.exe
  lua_getstack: entry=va size=0x7a functions=917
  lua_resume: entry=va end=+0xbe
  lua_yield:  entry=va end=+0x4a  (distinct)

signature_updater → version 740477
  lua_getstack offset 12624 (0x3150) entry bytes 4c 8b 49 28 …
  lua_resume   offset 28352 (0x6ec0) entry bytes 40 53 48 83 ec 20 …
  lua_yield    offset 26608 (0x67f0) entry bytes 48 89 5c 24 08 57 …
  lua_getinfo  offset 16816 has 80 3a 3e nearby
  luaopen_io   offset 110176 prologue 48 89 5c 24 08 …
```

resume != yield offsets; getstack body gate still holds.

## Files

- `src/FunctionRelocation/FunctionTable.hpp`
- `src/FunctionRelocation/NucleusAdapter.cpp`
- `src/FunctionRelocation/ModuleSections.cpp`
- `tests/function_relocation/test_nucleus_adapter.cpp`
- Regen: `Mod/signatures_*.json`, `Mod/deps/signatures_*.json`
