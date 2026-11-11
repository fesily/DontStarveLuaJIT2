---
name: crossarch-evidence-metric-discipline
description: "Cross-architecture symbol matching (symbolized ELF vs stripped PE): judge channels with the right precision metric, pick evidence by measured discriminative power, and audit structural repairs before trusting the denominator."
---

# Cross-arch evidence & metric discipline

Applies when transferring symbols from a symbolized binary (Android arm64 .so) onto a
stripped one (Windows x64 .exe) and deciding whether a channel "works".

## 1. Get the metric right before believing any precision number

Proposals necessarily target *unnamed* functions, so a proposal is only judgeable
when it lands on a held-out pair. Therefore:

- precision@holdout (unjudgeable counted as wrong) = **lower bound**;
- precision@judged (only proposals landing on held-out pairs) = **upper bound**
  (those pairs were reachable by other channels);
- report both, plus a hand-verified sample of the *applied* set (decompile and
  check the semantics). Numbers that looked like 0.05 turned out to be 1.00 on
  judged subsets in this project; treat any single number as untrustworthy.

Sanity rule: a channel emitting N proposals with only n≪N judgeable has an
*unknowable* precision — do not tune thresholds against it.

## 2. Rank evidence by measured discriminative power, not intuition

Works on a cross-build pair (same source, different compiler/version):

| evidence | how to use |
|---|---|
| binary-native tables (luaL_Reg, registries) | parse with structure validation, compare names |
| ABI-fixed order (vtable slot index) | identity first (class-name getter / 4CC id), then slot order |
| string literals | uniqueness on *both* sides is the anchor; IDF-weight for groups |
| call graph (caller sets) | strongest *late* dimension once anchors ≥ ~3-4k |

Does not work: body size, CFG/bb counts, immediate sets, immediate sequences
(measure LCS on true vs random pairs first), P-code/BSim similarity, address
order beyond per-class locality.

Diagnostic to run before investing: rank the *true* partner under the candidate
score inside its constraint group. If rank-1 is <50%, the dimension is noise.

## 3. Do not hard-gate a strong dimension

Cascade instead: small precise dimension narrows the candidate set, then *more*
dimensions decide inside that set. Requiring an "independent root" (string or
size) on top of a caller-set match rejected hundreds of correct names in this
project; with ~4k anchors the raw caller channel measured 0.915 judged.

## 4. Merge anchors from every stage before propagating

Per-stage history files undercount (only rows with an explicit source-address
column). Build one anchor table from all sources, drop pairs whose Android side
is claimed twice, and treat conflicts as unusable. Anchor count is the recall
knob for graph channels.

## 5. Audit structural repairs before trusting the denominator

- PE: compare `.pdata` RUNTIME_FUNCTION begins with defined functions, but only
  accept **16-byte aligned** begins; otherwise you create EH funclets /
  chained-unwind fragments as fake functions (74% of a naive sweep here), which
  inflate the function count and generate spurious tail-call edges.
- ELF: `.eh_frame_hdr` is a sorted (initial_location, fde) table — the cheapest
  true function list (beware: Ghidra may rebase the first PT_LOAD, e.g. +0x100000).
- Call-graph extraction should record `jmp <function-entry>` as an edge, but
  re-measure after boundary cleanup: most "tail calls" may be artifacts.

## 6. Sanity checks that caught real bugs

- verify a table entry end-to-end in memory (`{name, func, 0}` stride 24 on MSVC)
  and decompile the target; a shifted table gives 0 correct entries;
- require extracted names to be identifiers, or junk alignments win;
- after any rename/revert, re-run the downstream channel and diff table counts to
  prove no alignment depended on the removed names.
