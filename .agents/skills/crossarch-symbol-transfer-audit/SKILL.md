---
name: crossarch-symbol-transfer-audit
description: "Audit/precision-check a cross-architecture symbol-transfer pipeline (symbolized ELF/ARM64 - stripped PE/x64): judgeable-precision metrics, evidence-channel ranking, extractor bug checklist, anchor hygiene, ceiling test."
---

# Cross-architecture symbol transfer: audit and precision discipline

Use when a symbolized binary must be transferred onto a stripped binary of a
different architecture, and you need to know which channels are trustworthy and
where the ceiling is.

## 1. Fix the measurement first, or every number lies

Proposals target functions that are *unnamed*, so a proposal can only be judged
when its counterpart happens to be a known (held-out) pair.

- Scoring `test.get(win) == android` over all proposals counts unjudgeable ones
  as wrong -> reports a **lower bound** (observed 0.04 where the truth was 1.00).
- Scoring only over proposals that land on known pairs **over-counts** (that
  subset is the easy one).

Report both bounds, and label applied pairs by manual sampling. Keep a tool that
re-checks every applied name against the evidence class recorded in its
provenance comment (tier + `A=0x...`) and refuses to audit by guessing.

## 2. Rank channels by measured judgeable precision

| channel | measured |
|---|---|
| binary-native registration tables (luaL_Reg and similar arrays) | 0.999 |
| unique string literals; string-set similarity | ~0.95 |
| vtable slot order + class-name getter + 4CC id constants | 1.00 |
| caller-signature propagation (needs a large unified anchor set) | 0.915 |
| per-TU monotone block matching | 1.00 on judged |
| segment-level group alignment | 1.00 on judged |
| body size / CFG / immediate sets / immediate LCS / P-code (BSim) | no signal |

A single dimension must be used as a *constraint* for the next one, not as a
hard gate: gating caller propagation on "shared rare literal or size ratio"
rejected a channel that audits at 0.915.

Body-sensitive channels fail because the builds diverge. Measure
`median(win_instructions / android_instructions)` on known pairs; ~0.67 with
only ~25% of pairs within 20% means size/immediate/CFG scores cannot work.
Confirm with a **rank test**: is the true counterpart the best body match inside
its own class? Below ~50% (observed 9-15%) the body dimension is dead, even in
families whose median ratio is ~1.0.

## 3. Extractor bug checklist (each cost a full round)

- **Table stride**: require every entry to yield an identifier-shaped name
  (`isJavaIdentifierStart/Part`, length 2..48). A "longest run wins" heuristic
  otherwise picks a spurious alignment and shifts *every* entry (observed:
  0 of 1468 entries agreed with the corrected extraction). Verify by decompiling
  the function one entry claims.
- **PE function boundaries**: `.pdata` entries are not all function starts.
  Real x64 starts are 16-byte aligned (pre-existing functions: ~99.6%). Creating
  the unaligned ones invents functions inside bodies (they decompile with
  `unaff_` registers) and inflates the denominator; ~74% of a naive sweep was
  spurious. Provide a delete-list rollback before trusting any count.
- **ELF function boundaries**: `.eh_frame_hdr` gives the linker's own list
  (u8 version, u8 ptr_enc, u8 cnt_enc, u8 table_enc, then the table of
  (initial_location, fde) encoded pairs). Ghidra may rebase the first PT_LOAD
  (observed +0x100000).
- **Call edges**: record `jmp fn` (tail calls) as well as `call`. Without them
  the graph misses exactly the code reached by tail-call optimisation, and
  cross-compiler asymmetry is misread (observed "6272 vs 338" collapsing to
  "270 vs 351" after the boundary fix).

## 4. Anchor hygiene and iteration

Merge every channel's recorded pairs into one anchor file, drop pairs whose
Android side is claimed twice, and never let a channel's own output become
evidence for that channel. Then iterate apply -> re-anchor -> re-run. Expect two
productive rounds and a hard stop: caller signatures die once the popular
helpers are named.

## 5. Test the ceiling before tuning further

For every still-unmatched function, ask whether any dimension produces a
candidate whose counterpart carries a symbol:

- no evidence at all -> unreachable by construction
- evidence pointing at an unnamed counterpart -> nothing to transfer
- evidence pointing at a named counterpart -> the real review pool

Observed: 95.9% / 2.2% / 1.9% on a 13k-function remainder. At that point stop
tuning; the only remaining moves are an external symbol source (PDB, symbolized
build) or manual review of the small third bucket. A review ranker is still worth
shipping: score candidates from all dimensions, require one strong dimension,
and emit per-dimension evidence plus an `auto`/`review` class per row.
