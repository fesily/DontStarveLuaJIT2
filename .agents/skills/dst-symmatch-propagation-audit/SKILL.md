---
name: dst-symmatch-propagation-audit
description: Audit DST cross-arch call-graph propagation precision on a held-out slice before applying names; also use when propagation output must be rolled back.
---

# Auditing call-graph propagation (DST cross-arch symbol migration)

Use when a propagation/call-graph stage proposes symbol matches, or when
previously applied propagation names are suspected wrong.

## Why
Projected Jaccard over *mapped* neighbours measures agreement inside the known
subgraph only. With ~10% coverage a pair sharing two mapped callees scores 1.0
while 80% of its edges are unknown. Measured baseline precision on the
Android 2.2.1 ↔ Windows x64 pair is **0.278**.

## Procedure

1. Export inventories + sorted names through Ghidra MCP
   (`DstExportInventory`, `DstExportNames`).
2. `python tools/symmatch/propagation_eval.py` — hides 20% of the verified
   pairs (hash split), seeds with the remaining 80%, scores each variant only
   on the hidden slice. Deterministic; ~30 s.
3. Pick the variant with acceptable precision **before** any apply. Reference
   numbers (held out 729 of 3483 seeds):

   | variant | precision | recall |
   |---|---|---|
   | callers + callees, greedy (baseline) | 0.278 | 0.427 |
   | callee direction only | 0.223 | 0.230 |
   | caller direction only | 0.567 | 0.128 |
   | caller + independent evidence | **0.762** | 0.044 |
   | + IDF-weighted Jaccard | 0.281 | 0.427 |
   | + mutual-best assignment | 0.275 | 0.416 |
   | + coverage hard gate 0.5 | 0.266 | 0.252 |

   Independent evidence = shared string literals with Jaccard >= 0.5 **or**
   instruction-count ratio >= 0.9. IDF weighting and mutual-best do not help;
   the error mode is a shared helper, not a tie.
4. Apply with `DstApplyNames.java <tsv> apply`; keep `sym:<tier>` tags so the
   set is reversible.
5. Rollback: build an address list of the rejected rows and run
   `DstClearNames.java <tsv> apply` (restores `FUN_*`, drops `sym:*` and the
   provenance comment).
6. **Re-verify dependent channels** after any rollback: re-run
   `vtable_transfer.py` and compare table count / names with the previous run.
   Propagation names can act as vtable anchors (anchors are matched by name
   against Android vtable slots), so a wrong name can pin a wrong table.

## Pitfalls

- The held-out truth is itself derived from the earlier stages (precision
  ~0.95), so a measured 0.76 is a floor, not a ceiling.
- `matches.tsv` is stale relative to the live program; build seeds from
  `A=0x...` columns plus a unique qualified-name join against the Android
  inventory, and cross-check counts against `DstExportNames`.
- Filter proposals whose Android side is unnamed (`FUN_*`): the pair is real
  but there is no name to transfer.
- Applied-name deltas are recoverable by diffing consecutive
  `win_names_live*.tsv` exports — use that when the apply list was overwritten.
