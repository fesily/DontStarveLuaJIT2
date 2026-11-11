---
name: dst-symbol-channel-precision-audit
description: "When a cross-arch symbol-transfer channel (propagation, vtable, binding, name) needs a precision number instead of an opinion: holdout harness, planted-seed cascade, and rollback of already-applied names."
---

# Auditing a symbol-transfer channel by measurement

## When to use

A channel already produced names (propagation S5/S6, vtable anchors, binding tables,
name joining) and you need to know whether to trust it, keep it, or roll it back.
Applies to `tools/symmatch` in DontStarveLuaJIT2, transfers Android→Windows.

## 1. Holdout harness (never trust a channel's own output)

Seeds = every `A=0x...` column in `build/symmatch/*.tsv` **plus** a name join
(Windows qualified name == Android `q`, unique on both sides).  Split 80/20 by
`hash((android, windows)) % 5`.  Seed with 80%, score proposals only on the 20%.

    python tools/symmatch/propagation_eval.py
    python tools/symmatch/evidence_propagation.py --eval --modes callers

Report precision **and** recall; a channel at 0.9 precision / 0.03 recall is a
completely different product from one at 0.28 / 0.43.

## 2. Vary one factor at a time

Measured on this pair (Android 2.2.1 ↔ Windows x64):

| factor | effect |
|---|---|
| caller direction vs callee | 0.567 vs 0.223 |
| independent evidence gate (strings Jaccard ≥0.5 or size ratio ≥0.9) | callers 0.567 → 0.762…0.905 |
| IDF-weighted Jaccard | none (0.281) |
| mutual-best assignment | none (0.275) |
| coverage gate (`min_cov`) | loses recall, no precision gain |

Stop adding terms once a factor shows no movement; the bottleneck is evidence
quality, not scoring.

## 3. Cascade test (does an error spread?)

Plant N *wrong* seeds, run propagation, then retract them and count.
Two traps, both silent:

- the planted pair must be **hub on both sides** (high in-degree Android,
many-caller Windows), otherwise it never generates a vote and the test measures
nothing — a `retracted_desc=0` result usually means this, not safety;
- the legacy/plain model must record `roots = frozenset()` (no independent
  evidence), otherwise `retract()` keeps everything and again reports 0.

    python tools/symmatch/evidence_propagation.py --cascade --plants 15

Measured: plain 902 wrong of 1141 found (retraction cleans only 143);
evidence-gated 351 of 424.  Prevention at acceptance time beats cleanup.

## 4. Roll back what the channel already wrote

1. Recover the applied set as a set difference of two `DstExportNames` dumps
   taken before/after the apply (`win_names_liveN.tsv`); keep the dumps.
2. Classify each row against the gate that the harness validated; write the
   failing addresses to a TSV.
3. `DstClearNames.java <tsv> apply` (dry first) — restores `FUN_*`, drops `sym:*`
   tags and the provenance plate comment.
4. **Contamination check:** re-run any channel that used those names as anchors
   (`vtable_transfer.py`) and diff table/name counts.  Identical output means no
   alignment depended on the reverted names.

## 5. Native-name data can itself be wrong

Before treating binding tables as ground truth, verify one entry end to end:
`search_strings` for the name → `search_byte_patterns` for that string address →
read the qword at `ptr+8`; that qword is the real `lua_CFunction`.  A "longest
run wins" extractor can lock onto a spurious alignment in an unrelated pointer
array (measured: 0/1468 entries correct).  Guard: accept a run only when every
name passes `Character.isJavaIdentifierStart/Part` and is 2–48 chars.
