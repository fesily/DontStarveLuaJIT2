---
name: dst-windows-graph-evidence-preconditions
description: "Before trusting DST Windows x64 cross-arch graph/layout matching: verify .pdata function coverage, tail-call edges, and luaL_Reg extraction correctness."
---

# DST Windows x64: graph-evidence preconditions

Run these three checks **before** any caller/callee, order or layout-based matching on `dontstarve_steam_x64.exe`. Each one has silently corrupted results in this repo.

## 0. Prereqs
- GhidraMCP headless with `GHIDRA_MCP_ALLOW_SCRIPTS=1`
- Scripts synced: `cp tools/symmatch/ghidra/*.java /c/Users/fesil/ghidra_scripts/`

## 1. Does the function list match `.pdata`?
```
DstPdataCoverage.java <out.tsv>      # prints entries= / defined= / undefined=
```
Expected on DST 2.x x64: ~25,270 entries, only ~14,700 defined → 40%+ of bodies invisible.
If undefined > 5%, repair:
```
DstDefinePdataFunctions.java <out.tsv>   # createFunction at every missing begin
```
Then use the new count as the coverage denominator (29,248 on this image), never the pre-repair number.

## 2. Are tail calls in the call graph?
The inventory must record `jmp fn` (target is a function entry, not the current function) as a callee. Symptom of the bug: thousands of functions with zero callers, and `.pdata`-only code unreachable.
- Reference numbers: MSVC +6,272 edges, NDK clang +338. A large positive delta in the log line `inventory: tailcalls=` is correct for Windows.
- Re-export **both** sides with the same rule (`inv_win_tail.jsonl`, `inv_android_tail.jsonl`), otherwise the graphs are asymmetric.

## 3. Is the luaL_Reg extraction structurally validated?
Bug seen: a stride-24 run inside an unrelated pointer array is longer than the real table, so `longest run per function` wins and the whole table shifts by one entry (0/1,468 entries agreed with the corrected file).
Validation rule that fixed it: accept a run only when **every** name satisfies `isJavaIdentifierStart/Part` and length 2–48 (this rejects source paths, `%s` format strings, sentence fragments).
Spot check after extraction: the name at a known binding must land on the function that uses it, e.g. `SetTint → 0x14006b620` (reads 4 `luaL_checknumber`, builds a colour), not a `std::vector` helper.

## 4. Sanity gate after repair (do not skip)
- Re-run the vtable pass: run count must stay the same if only `.text` changed (`1,306` runs here).
- Re-run the stages that depend on strings (`stages_rerun.py`): that is where the new bodies actually pay off (+105 names), whereas gated propagation yielded ~0.
- Audit provenance before applying anything new (`audit_live.py`): a name without an independent root must not be written, or it will be reused as an anchor later.
