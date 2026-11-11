---
name: dst-cross-arch-symbol-evidence-ranking
description: Choose and validate cross-architecture symbol-transfer channels for DST Android arm64 vs Windows x64; repair binary function lists; gate by measured precision.
---

# Cross-arch symbol transfer: evidence ranking and binary repair

Use when migrating Android (arm64, symbol-rich) symbols onto a Windows x64 DST
binary, or when a cross-arch matcher has stalled and you need to know which
signal can still work.

## Order of work

1. **Repair the Windows function list first.** `.pdata` is the linker's own list:
   `DstPdataCoverage.java` (count defined vs missing) then
   `DstDefinePdataFunctions.java` (creates them; expect ~10.5k on DST).
   Do NOT repeat this on Android: parse `.eh_frame_hdr` instead — 32,493 FDE
   starts, all already defined. Off-by-0x100000 is the Ghidra rebase.
2. **Add tail calls to the call graph.** The inventory exporter must record
   `jmp fn` to a function entry as a callee; MSVC emits ~6.3k, clang ~0.3k.
3. **Audit names from provenance, not from history TSVs.** Export the plate
   comments (`DstExportProvenance.java`) and re-test each claim against the
   evidence class that produced it (`audit_live.py`). History files are
   append-only and get overwritten by later stages.
4. **Pick channels by body sensitivity.** Measure the true-pair instruction
   ratio first (median 0.667 here): only library families (Bullet, templates)
   stay near 1.0, so size/immediates/P-code matching is confined to them.

## Channel ranking (measured on this pair)

| evidence | verdict |
|---|---|
| binary-native luaL_Reg names | works; 1104/1105 audited |
| string literals (unique / Jaccard) | works; re-run after any list repair |
| vtable slot order (ABI-fixed) | works; 87 classes / 469 methods |
| caller-set signature + independent root | works, low recall (0.9 precision) |
| callee-set signature | 0.22 precision — keep off by default |
| per-TU address blocks | complementary (0 overlap with callers), decays as anchors densify |
| immediate sets / sequences, BSim/P-code | no usable signal (LCS 0.375 vs 0.294) |

## Traps

- `luaL_Reg` extraction: never let the *longest* pointer run win. A spurious
  alignment inside an unrelated array shifts every name by one entry. Accept a
  run only when every name is a plausible identifier.
- A name produced by a channel must never become evidence for that channel;
  allow only its folded alias (`name_1a2b3c`) and only as a shape hint.
- Monotone maps cannot retract: gate at acceptance (`verified` needs an
  independent root), then keep `DstClearNames` ready for rollback.
- Coverage denominators must come from `.pdata` (29,248 here), not from
  Ghidra's initial function count.
