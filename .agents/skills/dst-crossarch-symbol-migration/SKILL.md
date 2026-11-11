---
name: dst-crossarch-symbol-migration
description: "Migrate Android arm64 symbols (libDontStarve.so, full symbols) onto the stripped Windows x64 exe with Ghidra: evidence-classified channels, holdout evaluation, structural traps."
---

# DST cross-arch symbol migration (Android arm64 → Windows x64)

Goal: name as many Windows functions as possible from the symbolized Android
build, without polluting the database with guesses.

## Layout

`tools/symmatch/` (DontStarveLuaJIT2), artifacts in `build/symmatch/` and
`build/symmatch/vt2/`. Ghidra scripts in `tools/symmatch/ghidra/` must be copied to
`C:/Users/fesil/ghidra_scripts/` before `run_ghidra_script`.

Programs: `libDontStarve_2.2.1.so`, `dontstarve_steam_x64_live.exe`.
Ghidra rebases the ELF by +0x100000: ELF vaddr + 0x100000 = Ghidra address.

## Order of operations (each step measured, not assumed)

1. **Bindings — binary-native names, strongest source.**
   `DstExtractBindings.java`. It must reject non-identifier names
   (`isJavaIdentifierStart/Part`, len 2..48); otherwise a spurious stride run wins
   by "longest run" and shifts the entire table (symptom: 0 of 1468 entries agree
   with a corrected extraction). Sanity check: `SetTint → 0x14006b620` is a
   lua_CFunction reading four `luaL_checknumber` args. Android side is already correct.
2. **Inventory** (`DstExportInventory.java`): emits `str`, `imm`, `imq` (ordered
   immediates), `cal` (call + `jmp`-to-entry tail calls), and follows one level of
   pointer indirection (≤48 qwords) so luaL_Reg-like tables attribute their strings
   to the owning function.
3. **String stages** (`stages_rerun.py`): S2 unique string + S3 set similarity
   against the current used-set. ~+100 names after a structural repair.
4. **String groups** (`string_groups.py`) — highest value per effort: strings with
   ≤8 referrers per side are *constraints*, not anchors; score inside the group with
   IDF-weighted shared strings + size ratio + mapped-callee overlap; decide per group
   with mutual-best + margin; aggregate confirmations across strings. Measured:
   true partner ranks 1st in 89.7% of groups.
5. **vtables** (`vtable_transfer.py`, `vtable_anchor_audit.py`): identity from the
   class-name getter slot (`lea rax,[name]; ret`), then per-table delta ∈ {-2,-1,0};
   names produced by the channel must be excluded from its own anchor set.
6. **Per-TU blocks** (`tu_blocks.py`): monotone anchor segments + assignment on rare
   literals + size ratio. Complementary to caller propagation, but decays as anchors
   densify — run it *early*.
7. **Propagation** (`propagate_seeded.py`, `evidence_propagation.py`): callers-only +
   independent root. Callees-only measured 0.22 precision; leave it disabled.

## Hard-won rules

- **Never quote a precision number without naming the population.** Proposals target
  unnamed functions, so a held-out-seed metric counts every unjudgeable pair as wrong
  (large underestimate), while judgeable-only metrics over-estimate (those pairs were
  reachable anyway). Report both, and decompile 2-3 applied names.
- **`.pdata` repair only at 16-byte-aligned begins.** 74% of unaligned entries are EH
  funclets / chained-unwind fragments: they inflate the function count (29,248 vs
  19,527 real) and fabricate call-graph edges. Android needs no repair (`.eh_frame_hdr`
  FDE starts all already present).
- **Body-sensitive evidence does not work here** (size, immediates, sequences, P-code):
  the true partner ranks 1st only 9.3% overall / 15.1% inside comparable families —
  intra-class siblings resemble each other more than the cross-build identity.
  Divergence is family-dependent (bt* ≈1.00, cEntityComponent 0.07) but that does not
  rescue it.
- **Audit before cleanup**: `audit_live.py` re-checks each applied name against its
  recorded provenance (plate comment `cross-arch: <tier> | <method> A=0x...`); clear
  only classes that fail their own evidence test (`DstClearNames.java`).
- **A wrong name is worse than `FUN_`**: it misleads the decompiler and can become an
  anchor for the vtable pass. Rollbacks (`DstClearNames`, `DstDeleteFunctionsFromList`)
  are cheap and preferred.

## Typical commands

```bash
python tools/symmatch/stages_rerun.py
python tools/symmatch/string_groups.py --eval --max-df 8      # then --emit
python tools/symmatch/tu_blocks.py --eval --rare-only --min-size-ratio 0.5 --min-score 0.7
python tools/symmatch/vtable_transfer.py
python tools/symmatch/audit_live.py --clear-file build/symmatch/audit_clear.tsv
```
