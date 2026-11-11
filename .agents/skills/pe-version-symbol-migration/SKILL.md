---
name: pe-version-symbol-migration
description: "Migrate function names from an older to a newer build of the same PE (same compiler/arch, version bump) using Ghidra inventories plus staged binary diffing; use when a symbol table must follow a game/client update."
---

# PE version-to-version symbol migration

Goal: carry an existing name table from build A to build B of the same PE. Same compiler and arch,
so this is a binary-diff problem, not the cross-architecture problem — but *measure the drift first*.

## 0. Measure the drift before trusting any matcher

```
.text size delta, function count (Ghidra), fraction of B's 16-byte .text windows found verbatim in A,
shared string-literal ratio (from the feature inventories)
```

Reference numbers for "real update, not rebuild": .text −6.9 %, functions −11 %, byte-identical
windows 58.8 %, strings shared 79.1 %. If byte-identical windows were >95 % you can skip to stage 1.

## 1. Prepare both programs

- Copy B to a version-suffixed working copy (`<name>_b<steam buildid>.exe`); read the build id from
  `steamapps/appmanifest_<appid>.acf` and the PE `TimeDateStamp` for the report.
- Headless: `load_program` (file) → `run_analysis` (MCP call times out at 30 s but analysis continues;
  poll `analysis_status` until `analyzed:true`) → `DstExportInventory.java <out.jsonl>`.

## 2. Staged matching (each stage validated separately)

Order matters: strongest and cheapest first, and every stage feeds anchors to the next.

| stage | tool | rule | typical yield |
|---|---|---|---|
| 0 fingerprint | `verhash.py` | capstone tokens, mask rel32/rip, unique both sides, **size equal** | largest |
| 1 exact body | `vermatch.py` | raw SHA-256 (only position-independent leaves) | medium |
| 2 size+imm | `vermatch.py` | same size + same immediate multiset, unique | medium |
| 2b strings | `vermatch.py` | identical string-literal set + size band | medium |
| 3 callee vote | `vermatch.py` | max overlap of already-mapped callees, strict margin | medium |
| 5 gap string | `vermatch.py` | inside the anchor gap, old strings ⊆ new strings | small |
| 6 fuzzy | `verfuzzy.py` | difflib ratio on token lists ≥0.80, unique + margin, inside anchor gap; iterate | medium |
| 7 tiny | `vertiny.py` | ≤48 B: unique unnamed function in the class emission block, or the unique shared callee of the mapped callers | small |
| 8 graph | `vergraph.py` | name-level callee/caller set overlap ≥3, unique, size band 0.7–1.4; iterate to fixpoint | small |
| 9 block | `verblock.py` | basic-block fingerprints (mask rel32/rip), ≥50 % distinctive blocks, margin ≥2 | small |

## 3. Guards that keep precision

- **Size ratio 0.7–1.4** for every heuristic stage. A block match with median ratio 3.5× means the new
  analysis *merged* functions: naming a merged parent after a child is wrong.
- Drop ties; never accept a runner-up.
- Deduplicate: one new address, one old address. Priority = stage order.
- Record the stage in the applied tier so weak names can be filtered or rolled back.

## 4. Validation (do this before applying)

- **Edge preservation**: among mapped pairs, what fraction of A's call edges (both ends mapped) exist
  as B edges. ≥0.95 = coherent mapping; a wrong name almost always breaks its edges. Reference:
  0.968 overall, fuzzy 0.981, neighbour 0.904.
- **Order preservation**: adjacent-pair monotonicity (~0.95 expected; code motion is real).
- **Size-ratio distribution** per stage.

## 5. Apply, export, persist

`DstApplyNames.java <tsv> apply` (idempotent: re-running skips same-name) → `DstExportNames.java <out>`
→ `save_program`. Then measure: `coverage.py`, `ledger.py` against the new snapshot.

## 6. Report the residue honestly

Classify untransferred names before claiming "gone": exception/CRT labels (`Catch@`), duplicates with
address suffixes, third-party library symbols, trivial ≤12 B accessors, and only then real functions.
For a core-table metric, report the core-row loss separately from the raw name loss — they differ by ~3×.
