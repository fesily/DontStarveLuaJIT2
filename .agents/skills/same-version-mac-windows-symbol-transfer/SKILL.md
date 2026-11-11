---
name: same-version-mac-windows-symbol-transfer
description: "Same-version cross-compiler symbol transfer (mac clang/Itanium ↔ Windows MSVC) in Ghidra: ABI-corrected vtable slot alignment, BSim filtering that lifts 48%→91% precision, and the measured channel-precision table to pick channels."
---

# Same-version mac ↔ Windows symbol transfer (clang/Itanium ↔ MSVC)

Goal: copy already-known symbol names from one platform build onto an **unnamed** function in the
other platform build of the **same version**. Works because layouts/signatures are shared; fails
when you rely on layout alone (names must be anchored by something observable in the target).

## 0. Prerequisites / gotchas (cost hours if missed)

- Ghidra MCP: load a project program with `POST /load_program_from_project {"path":"/<name>"}`
  (the key is **`path`**, not program/program_name). GUI-less works.
- Switch program with `POST /switch_program?program=<name>` (**query param**, body is ignored).
- `run_ghidra_script` passes args as ONE comma-joined string → scripts must split:
  `String[] args = raw.length == 1 ? raw[0].split(",") : raw;`
- Verify which program a script really runs on: run `DstNamedStats` and read the `Program:` line —
  `get_current_program_info` can be stale after `load_program_from_project`.
- Export names with **`DstExportNamesAll`** (includes thunks). `DstExportNames` does
  `if (f.isThunk()) continue;` and silently under-counts ~1k named wrappers.
- Rename one-off via `POST /rename_function_by_address {"function_address":"0x…","new_name":"…"}`
  (keys `function_address`/`new_name`). Returns "No function found" when the slot target is not a
  defined function → run `DstDefineFunctionsFromList` first (needs the comma-split fix).
- If the project is locked by the MCP server, headless fails (`LockException`). Either load through
  the MCP as above, or copy the whole project dir and run `analyzeHeadless` on the copy.

## 1. Channel precision table (measured; use it to pick)

Ground truth = names unique-by-tail on both sides. Same-version mac r759671 ↔ Windows r759671:

| channel | coverage | precision | verdict |
|---|---:|---:|---|
| mutual-unique strings (freq==1 both sides) | ~20% | **95-100%** | use |
| strict string jaccard ≥0.5, margin ≥1 | ~20% | 94% | use |
| callee-name set overlap ≥2, margin ≥1 | ~10% | 94% | use |
| call-graph propagation (≥3 shared callees, margin≥2, 4 rounds) | +5% | 100% (n=13) | use, strictly |
| assert **(file,line)** 1:1 | small | 100% | use; normalize `source/` suffix + `\`→`/` |
| **vtable slot alignment, ABI-corrected** | 25 vtable pairs | high | use (see §2) |
| BSim + margin≥0.08 + size-ratio band | ~5% | **91%** | use (see §3) |
| BSim raw top-1 | 30% | **48%** | never alone |
| (instr_count, block_count) exact bucket | 81% | **9%** | rejected |
| address-order interpolation | 0% | — | rejected (link order unrelated) |
| caller-name sets | — | 0% | rejected |
| MSVC RTTI (`.?AV…`) | 7 names only | — | engines compile with `/GR-` |

## 2. vtable slot alignment — the ABI correction that makes it work

Layouts differ in the **prefix**, not the method order:

```
Itanium (mac/clang): [offset-to-top=0][typeinfo][D1][D0][method0][method1]…
MSVC    (Windows):   [COL=0][scalar-deleting dtor][method0][method1]…
```

→ drop the leading slots (2 on Itanium + its 2 dtor entries; COL + 1 dtor on MSVC) and compare
**method slots at the same index**. Without this the agreement is 0/917; with it, tens of vtables
agree 100% slot-by-slot.

Procedure:
1. Export vtables via constructor-vptr stores (`DstExportVtablesViaRefs`) on **both** sides —
   run-based scanning merges neighbouring tables and corrupts slot counts.
2. Attribute each vtable to a class:
   - slot-0 dtor name (`~Class`) — exact when named;
   - else majority class of its named slots (needs **qualified** names: `q` field of the
     inventory, not `n`);
   - else constructor that stores it (`DstVtableUsers`) → ctor name gives `X`;
   - require ctor-derived and majority-derived to agree, or drop the table.
3. Pair **same-class** vtables, score = agreeing named slots / shared named slots;
   accept ratio ≥0.8 and ≥3 slots, then greedy 1:1.
4. Transfer names into slots the target has unnamed; define functions first if needed.
5. Self-validating bootstrap: name ctor `C::C` only when the stored vtable agrees ≥0.9 with mac's
   vtable of class C, then re-run attribution. **This loop converges** — stop when new ctors
   add 0 slot names.

## 3. BSim recipe (H2 local DB, no Postgres)

```bash
DstBsimCreate <db>,medium_64          # medium_nosize and medium_64 calibrate identically
DstBsimAdd    <db>,5                  # run on the NAMED side (source of names)
DstBsimQuery  <db>,out.tsv,5,3,0.5    # run on the UNNAMED side
```

Post-filters that convert 48% → 91% (all measured on held-out ground truth):
- `similarity ≥ 0.8`
- `margin = sim1 − sim2 ≥ 0.08`
- size ratio inside the class's median band: same function is ~**1.16×** bigger on MSVC than
  clang; per-class median with band `0.5×med … 2×med`
- candidate name must not already exist on the target side

Add a class prior (vtable-attributed class == hit's class) and precision reaches 96.8%;
the margin+ratio pair alone is enough to ship at ~91%.

## 4. Reporting discipline

Record per-symbol disposition, never a bare count:
`MAPPED / ALIAS (one body, another instance's name) / ABSENT: folded|inline|removed|platform|not-emitted`,
each with the fold target address where applicable, and a `evidence` column.
Sample-verify every batch (`get_function_by_address`) and at least one **body-level** comparison
for a new channel — "rename succeeded" is not evidence.
