---
name: macos-xarch-i386-to-x64-symbol-sync
description: Cross-architecture (i386→x86_64) macOS DST symbol sync between two Ghidra project programs using binding-table/string channels; use when migrating symbols across arch where opcode/size channels fail.
---

# macOS i386 → x86_64 symbol sync (Ghidra MCP, DST)

## Preconditions
- Both binaries exist **in the Ghidra project** (e.g. `macos_dontstarve_steam_x86_r181048`, `macos_dontstarve_steam_x64_r759671`). Open with `load_program_from_project`; check `list_project_files` alternative: read `dst.rep/idata/*/*.prp` and grep `NAME" TYPE="string"` to enumerate saved programs offline.
- **Never re-import from disk** if the project already has the program — program names collide (`dontstarve_steam` for every mac build), so a second open with the same domain name silently replaces the first. Work **sequentially**: export features from one program, close it, open the other.

## Feature export (inline Ghidra script, per program)
Writes `build/symmatch/mac_xarch/<tag>.{funcs,strings,calls,bind}.tsv`, tag = `dontstarve_steam_x64` / `_x86` via `getDefaultPointerSize()` (a program *name* tag collides because both are named `dontstarve_steam`).
- funcs: `addr size name ns source`
- strings: instruction addr + string value from defined data (`Data.getValue() instanceof String`)
- calls: caller insn addr + callee addr, `refType.isCall()`
- bind: scan non-executable blocks for `{namePtr, funcPtr, …}` runs; strides `2..6 × pointerSize`; require ≥3 consecutive entries whose funcPtr is an existing function entry and whose namePtr reads printable ASCII; dedupe by func addr. On i386 expect strides 8/16, on x64 16/32.

## Matching (offline Python; strong → weak)
1. `bind` unique: registration name maps to exactly one function on each side.
2. `bindtab`: group bind rows by `(tableBase, stride)`, align the two sides' name sequences with LCS; pair slots where names are equal; require LCS ≥4 and ≥60% of the shorter table.
3. `str` unique: a string (len ≥10) referenced by exactly one function on each side.
4. `strvote`: shared-string inverted index (skip strings appearing in >12–20 functions per side), votes ≥2, Jaccard ≥0.4–0.5, unique best both directions.
5. Resolve one-to-one (drop donors/targets with multiple candidates).

Do **not** rely on: opcode hashes, function size, address order, immediate multisets (i386 vs x64 codegen kills them: ~44 candidates, ~14% wrong), or naive call-graph propagation (callee/caller neighbour scoring produced >90% wrong pairs even when seeded).

## Apply
CSV columns: `target_addr, namespace, short_name, tier, donor_qualified`. Java script: resolve `FunctionManager.getFunctionAt(toAddr(addr))`, create missing namespaces (`SymbolTable.createNameSpace`, catch duplicate then `getNamespace(seg, parent)`), `fn.setName(short, USER_DEFINED)`, `fn.getSymbol().setNamespace(ns)`, `fn.setComment("sym:<donor-version> <qualified> tier=<tier>")`. Dry-run by a boolean first; then `save_program`.

Safety rules:
- Skip pairs where target already has a non-auto name and a **different** short name (treat as newer-build rename).
- Same short name but different namespace → namespace-only fix.
- Never overwrite names carrying another campaign's provenance comment without review.

## Provenance audit (critical when other sessions ran)
Functions carry comments from previous runs (`same-arch: seed | O=0x…`, `cross-arch`, or your `sym:<ver>`). Dump `addr name ns source comment` and classify by comment prefix; cross-check each provenance bucket against the current donor's name set. Mismatch pairs from strong channels → `review_conflicts.tsv` (kind: same-short/different × provenance). Single-player builds are reference-only donors; do not let their names override the same-product donor.

## Gotchas
- `run_script_inline` bodies cannot declare methods — inline every helper loop.
- `FunctionManager.getFunctions(true)` excludes external functions; `getFunctionCount()` includes them.
- Renaming a function makes Ghidra re-expose same-address secondary symbols/thunks, so the "named" count can jump far beyond the number of rows applied — always measure progress by **unique qualified donor names matched**, not by target named-function count.
