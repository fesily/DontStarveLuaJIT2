---
name: crossarch-signal-acceptance-gate
description: "Before applying a new cross-architecture symbol-matching signal: measure it on a held-out slice, test true-vs-random separation, and only then set a gate. Use when a new matcher (strings/immediates/order/graph) is proposed for DST or similar stripped-binary symbol transfer."
---

# Accepting a new cross-arch matching signal

Never apply a signal because it is plausible. Each new matcher costs one holdout
run; a wrong name is worse than `FUN_` because it misleads the decompiler and can
act as an anchor for later stages.

## 1. Holdout harness (already in `tools/symmatch/`)

```bash
python tools/symmatch/propagation_eval.py     # variants for S5/S6 propagation
python tools/symmatch/tu_blocks.py --eval     # layout/block matchers
python tools/symmatch/immseq_blocks.py --eval # immediates
```

Pattern: hide 20% of the verified pairs (`hash((android, windows)) % 5 == 0`),
seed with the other 80%, score proposals **only** on the hidden slice.  Print
precision/recall per threshold, not just the top-line number.

## 2. Separation test before anything else

If the score does not separate true from random pairs, no threshold will help:

```python
# medians: true pairs vs random pairs
median(lcs_ratio(a, w[true])) vs median(lcs_ratio(a, w[random]))
```

Measured on DST Android↔Windows: immediate-set Jaccard 0.28→0.29 (noise),
immediate LCS 0.375 vs 0.294 (noise), string-set Jaccard separates strongly.

## 3. Gate design rules learned the hard way

- **Independent evidence beats graph evidence.** Neighbour overlap alone measured
  0.22–0.57 precision; adding an independent root (native binding name equality
  or a rare shared literal) gives 0.76–0.905.
- **Coverage is a confidence penalty, not a filter**: `min_cov >= 0.5` halved
  recall without improving precision.
- **Do not let a channel use its own output as evidence** (self-reinforcement
  drifted table alignments: 90 → 86 tables); except folded aliases
  (`name_<hex>`) which describe a function, not a table guess.
- **Prefer callers over callees**: S5 0.223 vs S6 0.567 on the same seeds.

## 4. Apply, then audit from provenance

```bash
# apply (dry first); DstApplyNames also names ICF-folded copies <name>_<hex>
DstApplyNames.java <tsv> dry|apply
# audit: export plate comments, re-test every claim against its own method
DstExportProvenance.java build/symmatch/vt2/provenance.tsv
python tools/symmatch/audit_live.py            # reports ok/fail per class
```

A claim is only auditable through the recorded provenance
(`cross-arch: <tier> | <method> A=0x…`); the TSV history is append-only and later
stages overwrite earlier pairings.

## 5. Rollback path

`DstClearNames.java <list.tsv> apply` restores `FUN_*`, drops `sym:*` tags and
the plate comment. Always re-run the vtable pass afterwards to prove no table
alignment depended on the cleared names (expected: identical table/name counts).
