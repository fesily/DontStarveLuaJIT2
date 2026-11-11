---
name: dst-crossarch-evidence-channel-selection
description: Choose or reject a cross-architecture symbol-transfer evidence channel (Android clang vs Windows MSVC) using holdout-evaluated measurements; not for same-arch or symbolized-both-sides cases.
---

# Cross-arch evidence channel selection (DST Android↔Windows x64)

Use when asked to raise symbol coverage between a symbolized Android `.so` and a
stripped Windows `.exe`, or when tempted to add "similarity" scoring.

## Rule 0 — evaluate before applying

Never apply a channel that has not been measured on a holdout of already-verified
pairs: hide 20% of the anchors, seed with the other 80%, score only on the hidden
slice. Applying unmeasured channels is how 118 wrong names got written once.

Minimum bar for automatic apply: precision ≥ 0.8. Below that, report only.

## What works (measured)

| channel | precision | notes |
|---|---|---|
| binary-native luaL_Reg tables (name↔func, both sides) | 0.999 | audit via fixed tables; 1,104/1,105 |
| string literals (unique / rare, Jaccard) | high | only functions that reference literals |
| vtable slot order (ABI-fixed; per-table Δ ∈ {-2,-1,0}) | high | needs class identity, see below |
| ctor→base chain; caller sets + one independent root | 0.90 | ~3% recall |

## What does not work — do not re-try without new evidence

* immediate **sets**: 0.278 → 0.281 precision;
* immediate **sequences** (LCS, order survives inlining): 0.04 precision; true
  pairs' LCS ratio median 0.375 vs random 0.294;
* size / CFG / P-code (BSim-style) similarity;
* address order alone: exact-count gaps 3.2%, DP recovers 2%;
* per-TU block matching: 0.795 precision but complementary (0 overlap) and it
decays as anchors densify — run it *early*, not after names exist;
* family-restricted body matching: true pair ranks first only 9–15% of the time.

Cause: median win/android instruction ratio is 0.667 and only 25% of correct
pairs are within 20%. Divergence is family-dependent (Bullet `bt*` 0.83–1.00,
`cEntityComponent` 0.07), but even comparable families are unusable because
siblings resemble each other more than their cross-arch twin.

## Identity sources for vtables (Windows has no RTTI here)

1. class-name getter slot: `lea rax,[name]; ret` returning the class name;
2. `GetComponentID` 32-bit four-character constant (identical on both sides);
3. name-getter literal + table-level binding identity for duplicates;
4. anchors = already-named virtual slots (do NOT let a channel anchor on its own output).

Locate tables by data refs from constructors and *slide a window over pointer
runs*; run starts are not table starts.

## Known traps (all cost real time)

* `.pdata` lists 25,270 ranges vs 14,698 defined functions: define every begin
  (`DstDefinePdataFunctions`) — 10,510 created, +15% call edges;
* the inventory must record `jmp fn` tail calls; MSVC emits 6,272, NDK clang 338;
* Android side needs **no** repair: `.eh_frame_hdr` FDE starts 32,493 vs 32,413
  defined (the 176 "missing" are already functions);
* parse `.eh_frame_hdr` with `vaddr + 0x100000` when Ghidra rebased the first
  PT_LOAD;
* `luaL_Reg` stride: accept a run only if every name is a compact identifier, or
  a longer spurious 24-byte alignment wins and shifts the whole table (observed:
  0 of 1,468 entries agreed with the corrected extraction);
* Ghidra leaves tiny virtuals (≤10-byte getters, `ret` stubs) undefined: define
  every `.rdata` qword pointing into `.text` before measuring shapes;
* do not feed names produced by a channel back into that channel's anchors.

## Deliverable shape

Report per-channel precision/recall on the holdout, the doc's final ranking, and
the honest denominator (use the `.pdata` function count, not the pre-repair one).
