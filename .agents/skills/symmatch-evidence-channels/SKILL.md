---
name: symmatch-evidence-channels
description: "Evaluating/choosing evidence channels for cross-arch (ELF-symbolized - stripped PE) symbol transfer: holdout harness, provenance audit, precision gates, and the measured list of channels that work vs fail"
---

# Evidence channels for cross-arch symbol transfer

Use when transferring symbols from a symbolized binary (e.g. Android arm64 `.so`)
to a stripped one (MSVC `.exe`, no PDB/RTTI/exports), or when reviewing whether a
proposed matching signal is worth building.

## Rule 0: measure on a holdout before applying anything

Hide ~20% of the verified pairs (deterministic `hash((a,w)) % 5`), seed with the
rest, score only on the hidden slice. Report precision AND recall. Any channel
whose holdout precision is < 0.8 does not get applied: a wrong symbol is worse
than `FUN_` (it misleads the decompiler and can act as an anchor).

Reference numbers from DST Android->Windows (see repo README for detail):
caller-sets + independent root 0.90 @ 2.7% recall; per-TU blocks 0.795 @ 4.9%;
plain caller/callee propagation 0.46/0.22; immediate sequences 0.04;
family-scoped body matching 0.047.

## Channels in order of measured value

1. **Binary-native name tables** (`{char* name, fn}` arrays / luaL_Reg).
   Extract with a strict row validator (name ptr -> string, next qword -> code,
   trailing qwords zero). Never pick the stride by "longest run": a spurious
   alignment in an unrelated pointer array wins and shifts the whole table
   (observed: 0 of 1468 entries agreed with the corrected extraction).
   Require every name to be a plausible identifier instead.
2. **ABI-fixed order**: vtable slot order. Itanium vs MSVC heads differ
   (`[2 dtors]` vs `[1 dtor]`, sometimes a zero hole), so solve the shift per
   table over delta in {-2,-1,0}; identify the class from a name-getter slot
   (`lea rax,[str]; ret`), a 4CC component-id constant, or table-level binding
   identity. Slide a window over annotated pointer runs; run boundaries are not
   table boundaries and abstract bases are never ctor-referenced.
3. **String literals**: unique-on-both-sides (S2) or set similarity with margin
   (S3). Attribute one level of data indirection (char* arrays) only if you
   accept that it dilutes uniqueness; measured net was ~0.
4. **Call graph**: caller sets are ~2.5x more precise than callee sets; gate on an
   independent root (shared rare literal or instruction-count ratio) to reach 0.9.
5. **Layout/order**: per-class order survives (~96% of classes ascending) but
   global order does not (~44% of consecutive anchors invert); usable only inside
   monotone segments, and its yield decays as anchors densify.

## Falsified channels (do not rebuild)

Immediate sets (+0.003 precision), immediate sequences/LCS (true 0.375 vs random
0.294), size/CFG/P-code similarity (true counterpart ranks first 9-15% inside its
class), BSim. Root cause is measured body divergence: median instruction ratio
0.667 on known pairs, only 25% within 20%, and it is family-dependent (third-party
`bt*` ~1.0 vs engine components ~0.07) -- yet even in comparable families the
siblings are more similar to each other than to the cross-build counterpart.

## Hygiene that paid off

- **Function-list repair first.** On PE, `.pdata` is the linker's own function
  list: define a function at every RUNTIME_FUNCTION begin (created 10,510 on a
  28k-function image). Then record tail calls (`jmp` to a function entry) as
  edges: +15% call edges, and they are systematically missing on MSVC.
  On ELF, `.eh_frame_hdr` is the equivalent and is usually already complete.
- **Define tiny slots.** Undefined 5-10 byte virtuals silently break run
  detection, shape classification and fingerprints; define every pointer into
the code section before scanning.
- **Provenance is the audit key.** Write `cross-arch: <tier> | <method> A=0x..`
  plate comments on every applied name, export them, and re-test each claim
  against its own evidence class. History TSVs are append-only and later stages
  overwrite earlier pairings, so they cannot be audited.
- **Never let a channel anchor on its own output**, except through an explicit
  fold alias (`name_<addr>`), or alignments drift.

## Deliverable shape

One tool per channel, `--eval` / `--emit` modes, deterministic; an audit tool that
classifies every live name (`ok:binding/strings/graph/vtable`, `fail:*`); a clear
list for anything that loses its support, applied via the symbol-clearing script.
