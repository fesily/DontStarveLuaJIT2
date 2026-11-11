---
name: dst-vtable-symbol-transfer
description: "Use when migrating DST Android (arm64 Itanium) symbols onto the Windows x64 binary via vtables, component IDs and propagation; not for same-arch matching."
---

# DST vtable-based symbol transfer (Itanium arm64 → MSVC x64)

Use when only the Android build is symbolized and the Windows build is stripped.
Everything below is measured on `libDontStarve_2.2.1.so` → `dontstarve_steam_x64.exe`
via ghidra-mcp; scripts live in `tools/symmatch/`.

## ABI model (do not guess a global shift)

Slot order is declaration order on both sides.  Head differs:

| | Itanium `.so` | MSVC `.exe` |
|---|---|---|
| header | `[offset-to-top, typeinfo]` | none |
| destructors | complete + deleting | deleting only |
| extra | — | some classes have a `0` hole after the dtor |

So `win = android + delta` with **delta ∈ {-2,-1,0}, solved per table**.

## Order of work

1. `DstDefineVtPointers.java` — define every `.rdata`/`.data` qword that points
   into `.text` as a function (+552 here). Ghidra leaves 10-byte virtuals
   (name getters, `ret` stubs, `jmp [import]` thunks) undefined, which silently
   breaks run detection, E/P/N shape and fingerprints.
2. `DstExportVtables.java <out.tsv>` — pointer runs, tolerant of one `0` hole.
3. `DstAnnotateVtables.java <in> <out>` — per slot `addr:size:kind:const:str`
   plus the nearest preceding `.cpp`/`.h` literal (TU hint). `kind` = `E` empty,
   `P` thunk, `N` real, `Z` hole.
4. `DstExportReturnConstants.java` / `DstFindConstants.java` — 4CC component ids.
   `GetComponentID()` returns a 32-bit four-char constant (`0x7eebc81d`), identical
   on both sides. Prefer the **raw little-endian byte scan of `.text`** over
   instruction-shape matching: it covers `mov eax,imm32`, arm64 `mov`+`movk`, and
   code behind a stack-cookie prologue. Result: 50/50 ids found, 42/42 agreement
   with the shape scan.
5. `python tools/symmatch/vtable_transfer.py` — four identity passes
   (name getter → Android `_ZTV<class>`; TU hint (gated off, precision ~43 %);
   4CC id; **already-named virtual slots as anchors**) then global deconfliction.
6. `DstApplyNames.java <tsv> dry|apply` — tier `vtable`; ICF-folded duplicates get
   `<base>_<addr>` instead of being dropped.
7. `python tools/symmatch/propagate_seeded.py --names <live names export>` — re-run
   caller-set + callee-set propagation from the enlarged seed.

## Traps that cost hours

- **A pointer run is not a vtable.** 30 of 579 named functions in runs were
  OpenSSL/imgui callback or jump tables. Never report "named slots" without
  checking the name is an Android vtable slot.
- **Abstract base tables have no ctor reference** (nothing constructs them), so a
  ref-driven scan misses exactly the tables you want; slide a window over runs
  instead of trusting run boundaries (adjacent tables merge into 478-slot runs).
- **Anchor set must not include the channel's own output** or it reinforces itself
  and drags shifted windows (90 tables/443 names → 86/477 when excluded).
  Folded aliases `Foo::Bar_1a2b3c` may be unwrapped when `Foo::Bar` is an Android
  vtable slot — the fold is a fact about the function, not a restatement of the guess.
- **ICF folding** merges every empty virtual into one `ret` stub (`0x14027a420`,
  931 slot uses). Its name is right for one class and misleading for the rest.
- `matches.tsv` is stale: the *live* symbol table is the only valid anchor source
  (378 vs 12 functions in runs).
- Seed from the live state, not from the old matches file; a name join of Windows
  qualified names onto Android `q` names adds 3,222 pairs by itself.

## Quality gates (keep precision high)

- Alignment: E/P/N agreement ≥0.80, ≥6 slots, prefer the window covering the most
  slots (shifted windows silently drop the table head).
- Folded vs named: 2 anchors ⇒ ≥0.70 pattern agreement; 1 anchor ⇒ ≥0.90 AND ≥6 slots.
- Callee propagation is tier `medium`: apply only with instruction-count ratio ≥0.8
  **and** score ≥0.85. Drop every proposal whose Android side is `FUN_*` — the
  pairing may be real, but there is no name to transfer.
- Audit with `vtable_anchor_audit.py` before trusting new anchors.

## Exhaustion signals

- Anchor pass: second iteration adds ~10 rows, third adds 0.
- Propagation: rounds keep proposing pairs but **all** have an unnamed Android side.

## Verification (always decompile, never infer)

- `0x14002b390` → `return "GroundCreepEntity";` = `GroundCreepEntity::GetComponentName`.
- `0x14003b8c0` → `return 0xb7134338;` = `cLightEmitterComponent::GetComponentID` (same constant as Android).
- `0x1404722c0` → `return *(this+0x40)+0x10` = `btTriangleMeshShape::getLocalScaling`.
- The channel also *corrects* earlier false positives (a string-anchored
  `SetWaveEffect` was really `GraphicsOptionsComponent::GetComponentName`).

## Measured totals

Windows named functions 3,185 → 5,433 (29.0 % of 18,733; 32.6 % of the original
16,649). Vtable channel alone +389; re-run propagation +118. Ceiling: 5,311
distinct Android vtable slots ⇒ vtables can never cover the 80 % target alone;
mix with binding tables, unique strings and propagation.
