---
name: cross-arch-match-channel-evaluation
description: "Evaluate a cross-architecture symbol-matching channel (holdout design, judged-vs-unjudged precision, spurious function filtering) before applying names"
---

# Evaluating a cross-arch matching channel before applying names

Use when adding/validating a new evidence channel for cross-arch symbol transfer (e.g. Android→Windows): strings, call graph, vtables, layout, body similarity.

## 1. Holdout design

- Build the seed map from *verified* pairs only (files with recorded A= plus unique qualified-name join).
- Split deterministically: `test if hash((android, windows)) % 5 == 0 else train`.
- Run the channel seeded with `train`; proposals may target `test` functions (they are unnamed with respect to the seed).

## 2. Report BOTH precision numbers, never one

```
proposals      = all emitted pairs
judged         = proposals whose windows addr is in the full seed map  (i.e. a held-out truth exists)
precision@judged  = correct / judged
precision@strict  = correct / proposals        # counts unjudgeable as wrong
```

- `precision@strict` is a **lower bound**: most proposals legitimately target functions that are still unnamed, so they can never be judged.
- `precision@judged` is **optimistic**: judged pairs are ones some other channel could already reach.
- Quote the interval, and settle the truth by manually decompiling a random sample of *applied* names.

A single-number report once produced two wrong conclusions: a block-matching channel reported as 0.795 was 19/19 on judged proposals, and a string-group channel reported as 0.34 was 11/11.

## 3. Spurious functions poison every structural channel

Before trusting function lists produced by `.pdata` (PE) or `.eh_frame_hdr` (ELF):

```
check: entry % 16 == 0   (MSVC x64 aligns function starts)
```

Measured on DST Windows x64: pre-existing functions 99.6% aligned; entries created from `.pdata` only 6.7% aligned → **74% were EH funclets / chained-unwind fragments**, visible in decompilation as `unaff_*` registers. Filter unaligned entries when creating functions; otherwise the denominator, call graph and naming targets are all wrong.

On ELF, `.eh_frame_hdr` FDE starts are complete (DST Android: 32,493 starts vs 32,413 Ghidra functions), so no ELF-side repair is needed — the gap is Windows-analysis-specific.

## 4. Per-channel sanity checks worth running first

| question | cheap test |
|---|---|
| does the dimension separate at all? | median of the signal on true pairs vs random pairs (e.g. LCS ratio 0.375 vs 0.294 ⇒ useless) |
| can the score pick the right one? | rank of the true partner among candidates in the local window (rank-1 < 20% ⇒ no usable signal) |
| is the body comparable? | instruction-count ratio on known pairs; only ~25% of true pairs are within 20% |
| do two channels overlap? | set intersection of proposals; zero overlap means complementary, union precision matters more than either alone |

## 5. Acceptance

Apply only channels that clear a stated bar on judged proposals **and** pass a manual sample; keep the applied list in a TSV with `A=<android addr>` so a later audit can re-derive the evidence per row.
