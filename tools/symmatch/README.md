# symmatch — cross-architecture symbol transfer (DST)

Transfers function symbols from a symbol-bearing Android `libDontStarve*.so`
(AArch64) to a stripped Windows `dontstarve_steam_x64.exe` (x86-64).

No similarity-only guessing: exact anchors run first and seed a scored,
one-to-one assignment; every written name carries its provenance and tier.

## Pieces

| Path | Role |
|---|---|
| `ghidra/DstExportInventory.java` | per-function feature inventory (JSONL) |
| `ghidra/DstExtractBindings.java` | extracts `{name, func, 0…}` script-binding tables (TSV) |
| `ghidra/DstApplyNames.java` | renames functions from a `matches.tsv` (dry-run capable) |
| `run.py` | CLI: `export`, `fingerprint`, `match`, `apply` |
| `pipeline.py` | stages S1–S6 + threshold calibration |
| `fingerprint.py` | SHA-256 / build-id / section layout per binary |

`run.py export` copies the Java files into `GHIDRA_SCRIPT_DIR` (default
`C:\Users\fesil\ghidra_scripts`) before invoking them, so the Ghidra script
provider always compiles the current sources.

## Prerequisites

1. GhidraMCP headless server running with `GHIDRA_MCP_ALLOW_SCRIPTS=1`.
2. Both programs **open and analyzed** in that server.
   `load_program_from_project` does not run analysis; check
   `analysis_status` for `analyzed: true`. A fresh 17 MB AArch64 import needs
   several minutes; the MCP transport may time out on `run_analysis` while the
   analysis itself keeps running — poll `analysis_status`.
3. `GHIDRA_MCP_AUTH_TOKEN` exported in the shell if the server requires it.
4. Both binaries on disk for `fingerprint` (addresses are only valid for the
   fingerprinted pair).

## Run

```bash
# 0) pin the pair
python tools/symmatch/run.py fingerprint \
  --android C:/Users/fesil/Downloads/lib/arm64-v8a/libDontStarve_2.2.1.so \
  --windows "C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together/bin64/dontstarve_steam_x64.exe" \
  --out build/symmatch/fingerprint.json

# 1) export features + binding tables (through Ghidra MCP)
python tools/symmatch/run.py export \
  --android libDontStarve_2.2.1.so --windows dontstarve_steam_x64.exe \
  --out build/symmatch

# 2) match (offline, deterministic)
python tools/symmatch/run.py match \
  --android-inv build/symmatch/inv_libDontStarve_2.2.1.so.jsonl \
  --windows-inv build/symmatch/inv_dontstarve_steam_x64.exe.jsonl \
  --android-bind build/symmatch/bind_libDontStarve_2.2.1.so.tsv \
  --windows-bind build/symmatch/bind_dontstarve_steam_x64.exe.tsv \
  --out build/symmatch

# 3) apply (dry run first)
python tools/symmatch/run.py apply --tsv build/symmatch/matches.tsv \
  --program dontstarve_steam_x64.exe --mode dry
python tools/symmatch/run.py apply --tsv build/symmatch/matches.tsv \
  --program dontstarve_steam_x64.exe --mode apply

# 4) vtable channel (separate, because it needs three Ghidra passes first)
#    a) define tiny virtuals: DstDefineVtPointers.java  (otherwise slots look empty)
#    b) DstExportVtables.java <out.tsv>                 (pointer runs, hole tolerant)
#    c) DstAnnotateVtables.java <in.tsv> <out.tsv>      (addr:size:kind:const:str per slot)
#    d) python tools/symmatch/vtable_transfer.py        -> vt2/vt_transfer2.tsv
#    e) DstApplyNames.java <tsv> dry|apply              (tier `vtable`)
#    identity helpers for step (d):
#       DstExportReturnConstants.java <out.tsv>         (4CC component ids, both binaries)
#       DstExportCtorVtables.java <out.tsv>            (ctor -> vtable, for base chains)
# 5) re-run seed propagation now that the seed set is larger
python tools/symmatch/propagate_seeded.py --names build/symmatch/vt2/win_names_live8.tsv
#    -> vt2/prop_seeded.tsv (high tier) and vt2/prop_seeded_review.tsv
```

## Stages and what they rely on

| Stage | Signal | Tier | Notes |
|---|---|---|---|
| S1 | binding tables, 1:1 name | `exact` | `{name, func, 0…}` arrays, stride 24 (MSVC) / 32 (NDK) |
| S2 | string owned by exactly one function on **both** sides | `exact` | strongest non-table anchor |
| S3 | multi-string Jaccard ≥ 0.6 + margin | `high` | needs ≥2 shared strings |
| S4 | weighted score (strings .45, immediates .20, size .15, blocks .10, callee-consistency .10) + margin gate | `medium` | candidate pool is built once; scores are re-computed every round |
| S5 | callee consistency through the accepted mapping | `medium` | Jaccard ≥ 0.6 over mapped callee ids, alternates with S6 |
| S6 | caller-set signature (who calls this function) | `high` | ≥ 2 mapped callers, Jaccard ≥ 0.7, margin ≥ 0.2 |

Threshold for S4 is calibrated on the S1+S2 pairs: negatives are drawn from the
same size bucket, and the lowest threshold reaching the target precision wins.
The holdout block in `report.json` re-runs S4 blind on 20 % of the exact pairs
and reports how many it recovers.

## Outputs (`build/symmatch/`)

- `matches.tsv` — `windows_entry \t name \t tier \t note` (note includes the Android address, method, score)
- `review.tsv` — medium tier only, for manual review
- `report.json` — tier counts, coverage, calibration, holdout recall

## S6: caller-set signature (the one structural stage that worked)

Seeded from the Lua entry points, a helper such as `luaL_checknumber` is called by
hundreds of already-mapped functions, so *its caller set* is a fingerprint:

```
a_ids = mapped callers of the android function
candidates = callees of M[caller] for every caller
score = Jaccard(a_ids, back[candidates' callers])
```

Measured on this pair: 396 pairs at tier `high` (2 rounds) plus 91 at `medium`.
Held-out precision: 2 callers + Jaccard >= 0.7 -> **95.1 %** (39/41); requiring the
callers to be luaL_Reg entries (`--s6-proxy-only 1`) gave 91.3 % on 23 cases and
fewer pairs, so the filter stays optional and off by default. Recovered names
include `lua_pushstring` (327 callers), `lua_gettop` (238), `lua_pushnumber` (233),
`lua_touserdata` (149), `cLoggerImplementation::Log` (541),
`EntityLuaProxy::CheckPointer` (54), plus clusters such as `BoostMap::*`,
`BlendMap::GenerateBlendedMap`, OpenSSL `BN_new` / `X509_VERIFY_PARAM_new`.

## Anchor-reach experiment (`hop_reach.py`)

Multi-source BFS from the 1,148 Lua binding anchors over normalized callee
edges; a candidate is a Windows function at the same hop whose *anchor-reach set*
(the set of anchors that reach it) is identical.

| hop | reachable | unmatched | unique | 2-3 | 4-10 | >10 | no-cand | unique+few | measured precision |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 1,049 | 635 | 439 | 76 | 40 | 0 | 74 | 81.1 % | 1.00 (9/9 decided, 3 uncertain) |
| 2 | 791 | 497 | 146 | 81 | 114 | 36 | 104 | 45.7 % | 0.86 (6/7) |
| 3 | 581 | 444 | 50 | 80 | 104 | 81 | 113 | 29.3 % | 0.20 (1/5) |

Two structural facts: only **1 of 1,148** anchors has any direct caller (luaL_Reg
functions are invoked through pointers), so upward propagation is impossible by
construction; and hop-3 candidates are dominated by STL template siblings
(`__erase_multi` vs `__erase_unique`, `__tree::erase` vs `~AStarSearch`), which
is why uniqueness degrades with distance. Hop-1 candidates are usable as review
material (`hop_candidates_verified.tsv`, 221 corroborated), hop-3 is noise.

### Soft variant (Binding Provenance Signature) — measured, not adopted

`binding_provenance.py` scores candidates with an IDF-weighted Jaccard over the
binding set and treats hop distance as a soft constraint (|Δhop| <= 1):

| variant | unique | unique+few | precision hop1 / hop2 / hop3 |
|---|---:|---:|---|
| exact set + equal hop | 635 | 872 | 1.00 / 0.86 / 0.20 |
| IDF-weighted Jaccard, hop ±1 | 378 | 769 | 1.00 / 0.57 / 0.00 |

The weighted score is **saturated** (323/333 candidates scored exactly 1.000), so
it adds no ranking signal while the hop slack admits the function one call edge
away from the claimed one (Windows caller of the Android symbol). IDF is still
useful as a *gate*: df (bindings reaching a function) spans 1..714, 2,160 of 2,708
reached functions have df <= 2, while 17 LuaJIT internals exceed df 200 — skip
those for identification and stop propagation there.

## Linkage normalization (call-edge semantics)

Ghidra's raw call reference is not a semantic edge on PIC builds: a call reaches
`B@plt`, then the GOT/relocation decides whether `B` is a local body or an
import. Reading raw targets silently loses `A -> B` (measured: 86 % of Android
call refs point at PLT stubs). The exporter therefore classifies every call:

| class | rule | emitted as |
|---|---|---|
| local body | target is a defined, non-external, non-thunk function after `getThunkedFunction(true)` | `cal` (normalized edge) |
| external symbol | resolves to an import / has no local body | `ce` (identity only, never an edge) |
| unknown indirect | `COMPUTED_CALL` with no reference (`blr x8`, `call rax`) | counted in `ln[3]`, no edge |

`ln` = `[raw_refs, folded_thunks, external_calls, indirect_calls]` per function,
so the fold rate is auditable instead of assumed. Never fold a thunk blindly —
ELF symbols can be preempted at run time, so folding is only allowed when the
program itself defines the target body.

Measured after normalization (0 `cal` targets left inside `.plt`):

| program | internal edges | raw refs | folded | external | indirect |
|---|---:|---:|---:|---:|---:|
| Android 2.2.1 | 79,233 | 147,641 | 105,719 | 22,000 | 9,343 |
| Windows live x64 | 51,665 | 102,861 | 663 | 20,868 | 5,069 |

The Windows number dropped from 62,059 because `call [IAT]` targets used to be
counted as local edges; they are imports and now live in `ce`.

## PDB export (debugger / ETW symbolization)

Ghidra has no PDB writer, so the PDB is assembled from Ghidra data plus LLVM:

```bash
# 1) Ghidra: sections + publics
#    script DstExportPdb.java -> sections.tsv / publics.tsv
# 2) a donor PDB gives the YAML skeleton (once per toolchain)
clang -g -gcodeview -c tiny.c -o tiny.obj
lld-link /debug /pdb:donor.pdb /entry:main /subsystem:console /nodefaultlib tiny.obj
llvm-pdbutil pdb2yaml --all donor.pdb > donor.yaml
# 3) patch sections/publics + the target's CodeView identity, then build
python tools/symmatch/make_pdb.py --yaml donor.yaml \
  --sections build/symmatch/pdb/sections.tsv --publics build/symmatch/pdb/publics.tsv \
  --out dst.yaml --guid "{E9216706-A3F3-42AF-830E-C264016FED5B}" --age 3 --signature 1790818531
llvm-pdbutil yaml2pdb --pdb=dontstarve_steam_x64.pdb dst.yaml
```

The GUID/Age/Signature **must** equal the PE's CodeView `RSDS` record and
TimeDateStamp, otherwise dbghelp silently rejects the PDB ("symbols mismatch").
Read them from the debug directory (index 6) of the module under analysis.

## Validation (independent audit)

An independent audit (separate agent, deterministic stratified sample of the 2,839
names written into an older build, both sides decompiled) measured:

| stratum | judged | same | different | uncertain | accuracy |
|---|---:|---:|---:|---:|---|
| `bind` (exact) | 40 | 40 | 0 | 0 | 100 % |
| `string` + `jaccard` (exact/high) | 40 | 40 | 0 | 0 | 100 % |
| `callers` + `score` + `?` | 40 | 31 | 1 | 8 | 96.9 % |

Overall 113/114 decided = **99.1 %** (Wilson 95 % CI 95.2-99.8 %). The single
`different` came from a `medium`/`score` *pairing* (never applied; the name at
that address came from a binding table and is correct). All 8 `uncertain` rows
are Linux-only ImGui names without an Android reference. 104/105 sampled Android
counterparts carried a byte-identical symbol leaf name, which independently
confirms the address join.

Practical rule: `exact` + `high` are safe to use for profiling; `medium` pairs
need per-pair corroboration; `?` (binding names present only in the Linux build)
are plausible but have no cross-architecture reference.

Measured on the live Windows build (2026-10): 1,148 bind + 750 string + 383
jaccard + 608 score + 473 callee + 605 caller = **3,967 named pairs (23.7 %;
26.7 % of >=8 instr)**; the `{S6 -> S5 -> S4}` outer loop is worth +240 pairs over
a single sweep, and the S4 re-score alone +175.

## Profiler symbol files

`export_symbols.py` turns a `DstExportNames.java` dump into the schema
`tests/performance/rva_sym.py` already reads:

```bash
python tools/symmatch/run.py match ... --out build/symmatch/live     # per-build addresses
python tools/symmatch/run.py apply --tsv build/symmatch/live/apply_exact_high.tsv \
    --program dontstarve_steam_x64_live.exe --mode apply
# dump + convert (Ghidra script writes win64_names.tsv first)
python tools/symmatch/export_symbols.py --names build/symmatch/live/win64_names.tsv \
    --module <exe> --out build/symmatch/live --text-end 0x51375e
python tests/performance/rva_sym.py --symbols build/symmatch/live/dontstarve_steam_x64.exe.symbols.json 0x7aab0
```

Outputs: `<module>.symbols.tsv` (rva, va, size, name, source, tags),
`<module>.symbols.json` (`ranges` = [rva_start, rva_end, name], plus the module
sha256 and per-address provenance), `<module>.symbols.md` (counts/coverage).
Symbols are only valid for the exact build they were derived from — always
re-run the pipeline after a game update.

## Review triage

`review.tsv` holds the `medium` tier. The cheapest manual pass is to intersect it
with an independent signal rather than reading 500 rows:

1. keep `callers` rows with `score >= 0.75` and `callers >= 3`;
2. require corroboration from the inventory: size ratio >= 0.5 AND (immediate
   Jaccard >= 0.3 OR size ratio >= 0.8);
3. decompile one or two before applying.

On this pair that reduced 562 review rows to 12 candidates, 6 of which passed
corroboration (4 applied, 2 name collisions). Destructors with a size ratio
around 0.1 stayed in review as suspected mismatches.

## BSim (measured, not used for writing)

BSim is the only architecture-independent matcher Ghidra ships, so it was built and
measured on this pair. Setup is headless and needs no Postgres:

```bat
:: 1) pack both analysed programs, import them into a scratch project
::    (the live project is locked; GZF import preserves analysis, no re-analysis)
analyzeHeadless C:\Users\fesil\bsim\proj dstbsim -import android.gzf windows.gzf -noanalysis
:: 2) create DB, add the Android side, query the Windows side
... -process android_2.2.1 -postscript DstBsimCreate.java C:\Users\fesil\bsim\dst.bsim medium_nosize
... -process android_2.2.1 -postscript DstBsimAdd.java    C:\Users\fesil\bsim\dst.bsim 8
... -process windows_x64   -postscript DstBsimQuery.java  C:\Users\fesil\bsim\dst.bsim out.tsv 8 5 0.5
```

Result on DST 2.2.1 (AArch64/Clang) vs `dontstarve_steam_x64.exe` (x86-64/MSVC):

| check | medium_nosize | medium_64 |
|---|---|---|
| DB entries (Android, >=8 instr) | 26,989 | 26,989 |
| Windows functions scanned | 14,765 | 14,765 |
| Windows functions with any candidate | 4,142 (25%) | 3,702 (22%) |
| top-1 agrees with a proven pair | 28.0% | 27.6% |
| self-check (Android vs its own DB) | 87% top-1 self, median similarity 1.0 | — |

The machinery is sound (self-check passes); the cross-architecture/cross-compiler
signal is not. Agreement is *lower* for large functions (3.5% for >=128 instr), so
BSim is not used to write names. `run.py bsim` keeps the ingest path alive:
it measures agreement against the exact tier first and only then emits `bsim`
pairs, so a future re-run (other template, symbolized target, other version pair)
is a two-command experiment.

## Linux x64 bridge (measured, not viable)

The Linux client (`bin64/dontstarve_steam_x64`, latest Steam build) is **stripped**
too (531 dynsym entries, no `.symtab`), so it cannot seed itself. Two-hop
`Android -> Linux -> Windows` was measured:

| check | result |
|---|---|
| binding names | Linux 1,499; Linux∩Windows **1,381** (closest pair), Linux∩Android 1,286 |
| Android -> Linux match | 2,640 named (19.5 % of 13,511; 24.7 % of >=8 instr), applied to the Linux program |
| same-arch BSim Linux->Windows | top-1 29.0 % (38.6 % at thresh 0.5); correct target in top-10 only **48.9 %** |
| BSim + feature rerank | 31.5 % top-1 |
| marginal gain over direct Android->Windows | 409 Android functions named on Linux but not on Windows |

Same-arch GCC-vs-MSVC is not similar enough for P-code features, and the ceiling
is anyway ~400 names. Keep the Linux program named (it is useful on its own),
but do not route the Windows transfer through it.

## Vtable alignment (identity works; scale is the limit)

Order is ABI-stable: pure C++ declaration order on both sides.  The head is
*not* constant, so the shift must be solved per table:

| | Itanium (Android `.so`) | MSVC (Windows `.exe`) |
|---|---|---|
| head | `[offset-to-top, typeinfo, complete dtor, deleting dtor]` | `[deleting dtor]`, sometimes `[deleting dtor, 0]` |
| exported slot 0 in `vt_android.tsv` | `~Class` (complete dtor) | dtor |
| shift `win = android + delta` | — | `delta ∈ {-2, -1, 0}` per table; `-1` for a plain single-dtor head, `-2` when a zero hole follows the dtor |

Traps that invalidated earlier attempts:

- **Undefined tiny virtuals.**  Ghidra leaves 10-byte name getters, `ret`
  stubs and `jmp [import]` thunks undefined.  Run detection, `E/P/N` shape and
  fingerprints all degrade silently.  `DstDefineVtPointers.java` defines every
  qword in `.rdata`/`.data` that points into `.text` (+552 functions here).
- **Run starts are not table starts.**  Adjacent tables merge into one run (max
  478 slots) and abstract bases are never referenced by a ctor.  Slide a window
  over annotated runs instead of trusting the run boundary.
- **A zero qword inside a vtable** breaks naive run scanning; one hole is
  tolerated in `DstExportVtables.java`.
- **No RTTI on the Windows side** (8 `.?AV` strings only), so the class name
  must come from the code.

Identity channel that does work: DoD classes carry a tiny virtual that is
literally `lea rax,[rip+s]; ret` returning the class name
(`"GroundCreepEntity"`, `"MiniMapEntity"`, `"WaveComponent"`).  A slot with
kind `N`, size <= 24 and an identifier literal names the table's class, which
then selects the Android `_ZTV<class>` and transfers every slot.

Measured (`vtable_transfer.py`, 1,306 runs / 10,256 slots / 100 distinct class
name literals): **43 classes aligned, 231 slot names produced**.  Applying them
gives 188 newly named functions plus 16 ICF-folded copies (`<name>_<addr>`,
the same implementation referenced from several vtables) and 208 rows that
merely reproduced names other stages had already found — a free cross-check.

Three identity sources, in order of strength:

| source | yield | notes |
|---|---|---|
| name-getter slot (`lea rax,[name]; ret`) | 42 tables | strongest; class name is a literal |
| `GetComponentID` 4CC constant | 40 tables corroborated | see below |
| already-named virtual slots (anchor voting) | **+44 tables, +189 names** | every name from the other stages that lands in a vtable slot votes for (table, offset, delta); two agreeing anchors fix the shift, one anchor must also match the E/P/N pattern; names produced by this channel are excluded from its own anchor set or it would reinforce itself |
| translation-unit hint (`__FILE__` next to the table) | 0 accepted | 7 tables proposed at ratio 0.88, but 4 of 7 contradicted already-known names (`MapComponentBase` vs `QuadTreeNode`); a TU contains several classes, so it only helps as a tie-breaker |
| ctor → base-ctor chain | 3 candidates | still needs more roots; superseded by anchor voting |

Component ids: `GetComponentID()` returns a 32-bit four-character constant
(`0x7eebc81d`), identical on both sides and unique per component.  The Windows
side is found by **scanning the raw `.text` bytes for the little-endian value**
(`DstFindConstants.java`) instead of matching one instruction shape — that
covers `mov eax,imm32`, MSVC's two-half constructions, and code behind a
stack-cookie prologue alike: 50/50 Android ids found, 42 of them also agreeing
with the shape-based scan, which is what proved the two extractions correct.

Anchor voting converges in two iterations: 90 tables / 443 names, then +11
names, then 0.  `vtable_anchor_audit.py` classifies the whole anchor
population (579 named functions sit in a run slot):

| class | count | meaning |
|---|---|---|
| `android_slot` | **513** | genuine anchor: the name is an Android vtable slot |
| `free_function` | 30 | `ssl3_read_bytes`, `InputFloat3`, `EVP_PKEY_new` — these are library/callback tables that a pointer run cannot tell apart from a vtable, not wrong names |
| `fold_alias` | 22 | `<name>_<hex>` copies from ICF folding; usable as a shape hint only |
| `not_virtual` | 9 | Android has the symbol but not in any vtable — reviewed by hand, left alone |
| `ctor_or_init` | 4 | constructors / `_INIT_*`, never a slot |
| `stub_conflict` | 1 | `0x14027a420` (`cTextEditWidget::OnKeyUp`, 3 bytes, 931 slot uses): the ICF representative of every empty virtual; correct for one class, misleading for the other 930 |

Restricting anchors to true Android slots changes nothing (87 tables / 469 names
either way), i.e. the channel is not sensitive to the junk above, and its output
agrees with the already-applied names on 443 of 448 rows — the remaining rows
are only folded-name normalisation.

| measurement | value |
|---|---|
| Windows functions named | 4926 → **5315** (this channel: +389) |
| coverage, current 18,733 functions | **28.4 %** |
| coverage, original 16,649 functions | **31.9 %** |

Verification: `0x1404722c0` named `btTriangleMeshShape::getLocalScaling`
returns `*(this+0x40)+0x10` (the embedded `m_localScaling`), `0x14003b8c0`
`cLightEmitterComponent::GetComponentID` returns `0xb7134338` — the same
constant Android returns, `0x14002b390` `GroundCreepEntity::GetComponentName`
returns `"GroundCreepEntity"`.

The stale `matches.tsv` contributes nothing (only 12 of 3,185 of its functions
appear in a run), but the *live* symbol table does: 378 named functions sit in
vtable runs and 316 of them are Android vtable slots.  That difference is why
anchor voting failed in the first attempt and works now.

Ceiling: 5,311 distinct Android vtable slots exist, so vtables can name at most
~16 % of the Windows function list even with perfect identity. Scaling past 221
needs more identity sources (component registry `{name, ctor}` tables, `__FILE__`
strings next to each table, ctor/dtor chains), not better alignment.

## Seed propagation after the vtable channel (`propagate_seeded.py`)

The first pipeline run seeded S5/S6 with ~1.5k pairs.  After the vtable channel
the seed set is much larger, so propagation was re-run from the live state
(seed = every `A=` column + a name join of Windows names onto Android `q`
names): 3,398 seeds, then alternating caller-set and callee-set rounds.

**Measured precision, not assumed.**  `propagation_eval.py` hides 20% of the
verified pairs, seeds with the other 80% and scores each variant only on the
hidden slice (3,483 seeds, 729 held out):

| variant | proposals | correct | precision | recall |
|---|---|---|---|---|
| baseline (callers + callees, greedy) | 1118 | 311 | **0.278** | 0.427 |
| + IDF-weighted Jaccard | 1107 | 311 | 0.281 | 0.427 |
| + mutual-best assignment | 1100 | 303 | 0.275 | 0.416 |
| + coverage gate (min_cov 0.2 / 0.5) | 1047 / 693 | 298 / 184 | 0.285 / 0.266 | 0.409 / 0.252 |
| callees only (S5) | 752 | 168 | **0.223** | 0.230 |
| callers only (S6) | 164 | 93 | **0.567** | 0.128 |
| callers + independent evidence | 42 | 32 | **0.762** | 0.044 |
| callers + independent + strict(0.9, 3) | 14 | 6 | 0.429 | 0.008 |

Conclusions, all from the held-out slice:

* the callee direction is the bad one (0.22); the caller direction is 2.5x better;
* IDF weighting and mutual-best assignment do **not** move precision — the
  review's points 2 and 3 are theoretically sound but are not the bottleneck
  here, because the dominant error is a repeated shared helper, not a tie;
* coverage is a real problem (review point 1) but works as a *confidence
  penalty*, not as a hard threshold: `min_cov >= 0.5` loses half the recall
  without improving precision;
* the only gate that buys precision is **independent evidence** (shared string
  literals with Jaccard >= 0.5, or instruction-count ratio >= 0.9) on top of
  caller agreement: 0.76 at 0.044 recall.

Bias in this measurement: the held-out truth itself comes from the earlier
stages (precision ~0.95), so 0.76 is a floor, not a ceiling.

### Rollback

The first two propagation rounds applied 118 names under the *baseline*
configuration.  Given 0.28 precision that set was mostly wrong, and a wrong
name is worse than `FUN_`: it misleads the decompiler and can act as an anchor
for the vtable pass.  `revert_prop.tsv` cleared **102** of them (kept only
callers + independent evidence), and the vtable pass was re-run afterwards:
still 87 tables / 469 names, i.e. no table alignment had depended on them.

`propagate_seeded.py` now defaults to callers-only + independent evidence;
`--allow-callees` and `--no-independent` exist for experiments, not for
production runs.  Under those defaults the channel yields **1** further name —
it is exhausted, not "converged at 118".

| measurement | value |
|---|---|
| Windows functions named | 5,433 → **5,331** (after rollback) |
| binding-name audit | 1104 / 1105 correct |
| coverage, current 18,733 functions | **28.5 %** |
| coverage, original 16,649 functions | **32.0 %** |

## Names as evidence (`name_evidence.py`) — and a fixed extraction bug

The review proposed treating function names as a first-class evidence channel.
Before adding anything, the only objective (binary-resident) names on both sides
were audited, and that audit exposed a real bug.

### Bug: Windows `luaL_Reg` extraction was shifted

`DstExtractBindings` accepted any run whose entries were `{name, func, 0…}`, and
kept the **longest** run per function.  On the Windows image a spurious 24-byte
alignment inside an unrelated pointer array was longer than the real table, so
it won and every function received its neighbour's name:

| check | result |
|---|---|
| `SetTint` per old file | `0x1400690e0` — decompiles to `ComponentLuaProxy<cTextEditWidget>::Add` |
| `SetTint` per fixed file | `0x14006b620` — reads four `luaL_checknumber` args and sets a colour |
| old vs fixed entries agreeing | **0 of 1468** |
| Android side | correct (`SetTint → 0x7c0e9c` = `ImageWidgetProxy::SetTint(lua_State*)`) |

Fix: a run is only accepted when *every* name is a compact identifier
(`Character.isJavaIdentifierStart/Part`, length 2..48), which removes source
paths, format strings and sentence fragments that the spurious alignments
produced.  Re-extraction now yields 1523 entries, all stride 24, and
`SetTint` lands on the right function.

### Independent audit of the existing name set

With the fixed tables, 1105 of the 1242 table-resolved pairs are live
functions; comparing each one's current symbol against its binary-native binding
name gives:

| | count |
|---|---|
| name equals the binding name | **1104** |
| name differs | 1 (`0x14012b620`, fixed to `SimLuaProxy::IsBorrowed`) |

So the earlier shifted extraction left no lasting damage — those names had been
overwritten by later stages — and this is the first *independent* (not
seed-derived) precision check of the whole symbol set.

### What the name dimension can and cannot do here

| use of names | measured |
|---|---|
| compare native names on both sides | almost empty: of 963 propagation proposals, only **2** had a native name on both sides (1 of them conflicting) |
| resolve duplicate binding names via table identity | 1242 pairs, but 1105 already named → **0 new names** |
| name-based neighbour weighting | equivalent to the degree-IDF test already run: precision 0.278 → 0.281 |
| names migrated from Android | must never be evidence (circular); already excluded |

Conclusion: on this pair the Windows image has no exports, no RTTI and no PDB,
so binding tables are its *only* native-name source — and they cover exactly the
Lua surface that stage S1 already consumes.  A "name similarity" term would
have nothing to compare for the ~80 % of functions that remain unnamed; the
review's warning about circularity is therefore not just theoretical here, it
predicted precisely where the channel would be empty.

What the review got right and is already implemented: provenance tiers
(`sym:exact|high|medium|vtable`), the exclusion of channel-produced names from
its own anchors, and the rollback path (`revert_prop.tsv`, 102 names cleared).
The remaining proposal — `verified` vs `proposed` sets with dependency records
and re-scoring after a retraction — is implemented in the next section.

## Evidence-aware propagation (`evidence_propagation.py`)

Implementation of the review's structural proposal.  The flat
`dict[android, windows]` is replaced by a `Mapping` that keeps two sets and a
provenance record per pair:

```python
Match(android, windows, score, status, origin, dependencies, roots)
  status        verified | proposed      # only verified may be evidence
  origin        seed | callers | callees
  dependencies  the verified pairs that voted for this one
  roots         independent evidence ids ("binding:<name>", "strings")
```

Rules: a neighbour overlap creates a *proposal*; a pair is promoted to
`verified` only when it carries an independent root (native binding-name
agreement, or shared string literals with Jaccard >= 0.5).  `retract(key)`
removes a verified pair and re-scores its dependents, dropping the ones that no
longer have a root or enough remaining dependencies, recursively.

Measured on the same held-out slice (3,408 seeds, 714 held out):

| configuration | proposals | correct | precision | recall |
|---|---|---|---|---|
| callers, plain (no roots) | 197 | 91 | 0.462 | 0.127 |
| **callers, evidence-gated** | **21** | **19** | **0.905** | 0.027 |
| callers+callees, evidence-gated | 494 | 92 | 0.186 | 0.129 |

The gate roughly doubles caller precision; the callee direction drags it back
down because its only available root (shared literals) is too permissive — which
is the same conclusion as the earlier precision sweep, now reproduced under the
new data structure.

Error-cascade experiment (15 wrong seeds planted on *hubs*, both sides, so the
fake pair can actually generate votes):

| model | found | wrong | retraction cleans | wrong after retraction | correct lost |
|---|---|---|---|---|---|
| plain (permanent matches) | 1141 | 902 | 143 | **759** | 0 |
| evidence-aware | 424 | 351 | 0 (none needed) | 351 | 0 |

Reading: retraction cannot rescue a monotone mapping — cleaning the 15 planted
seeds removes only the 143 pairs that depended *directly* on them, while the
other 759 wrong pairs were already permanent.  The evidence-aware model never
admits them: 902 → 351 wrong with the same seed set.  Prevention beats cleanup,
which is why the gate lives at acceptance time.

Both numbers still argue for the production default already shipped in
`propagate_seeded.py`: callers-only + independent evidence.

## Auditing the live table (`audit_live.py`) — no full re-run needed

A name is a claim, and every claim symmatch writes carries its provenance in the
plate comment (`cross-arch: <tier> | <method> A=0x<android> score=…`).  That
comment, not the append-only TSV history, is the authority for re-checking the
table: later stages overwrite earlier pairings, and the binding extraction was
itself wrong until it was fixed.

`DstExportProvenance.java` dumps the comments; `audit_live.py` re-tests each
claim against the evidence class that produced it:

| provenance | count | verdict rule |
|---|---|---|
| derivation (`A=0x…`) | 3,242 | see below |
| ├ `bind` | 1,148 ok | native binding name still equal on both sides |
| ├ `string` / `jaccard` | 1,131 ok | shares a rare literal, or Jaccard >= 0.5 |
| ├ `vtable` | 363 ok, 10 fail | address still produced by the vtable pass |
| ├ `score`/`propagate`/`callers` | 101 ok, **445 fail** | needs an independent root (rare literal, or instruction-count ratio >= 0.9) |
| reviewer-confirmed (`review … same`) | 523 | manual verdict, nothing to re-derive |
| legacy note (`score size=…`, no `A=`) | 964 | not auditable (older format lost the address) |
| no provenance | 602 | early/manual |

The 455 unsupported names (445 graph + 10 vtable) were cleared on the policy
"precision beats coverage": the graph class measures ~0.5 precision without a
root, and these names double as vtable anchors, so an error propagates twice.

After the clear: 5,331 → **4,876** named functions, and the vtable pass
re-run unchanged at 87 tables / 469 names — none of the cleared names had been
load-bearing for a table alignment.

| measurement | value |
|---|---|
| Windows functions named | **4,876** |
| coverage, current 18,733 functions | **26.0 %** |
| coverage, original 16,649 functions | **29.3 %** |

Cost: about 220 of the 455 were probably correct; they are not recoverable by
re-running propagation (the same gate rejects them), only by manual review of
the preserved list `build/symmatch/audit_clear.tsv`.

## Layout evidence: order is local, and the function list was 42% short

Two structural questions were measured rather than assumed.

### Per-class order survives, global order does not

Both compilers emit a translation unit in source order, so a class should occupy
a compact run with its internal order intact.  Measured on the anchor pairs:

| scope | ascending order kept |
|---|---|
| consecutive anchors in **global address order** | 56% (44% invert) |
| classes with >= 2 anchors | 82% (20 of 110) |
| classes with >= 5 anchors | **95.7%** (45 of 47) |
| classes with >= 10 anchors | 90% (9 of 10) |

So the hypothesis holds *locally*: inside one class the Windows order matches the
Android order.  The global order does not, because the two builds link their
objects in a different order — which rules out whole-image sequence alignment.

Order as a *matcher*, however, fails:

| method | result |
|---|---|
| exact-count gaps between consecutive anchors | 96 of 2,993 gaps (3.2%) |
| positional pairing inside those gaps | precision ≈ 0.14 on the holdout |
| monotone DP inside class windows (size + immediates) | recovers 2% of held-out pairs |
| order-consistency as a gate on caller propagation | 0.571 vs 0.421 precision (real but weak) |
| order-consistency as a ranking term (`--order-weight`) | 0 usable gain |

The ABI-fixed case is the exception and is already exploited: **vtable slot
order** pins 87 classes / 469 methods without any similarity heuristic.

### The function list was 42% short (`.pdata` vs Ghidra)

`DstPdataCoverage.java` compares the exception directory with the defined
function set:

| | count |
|---|---|
| `.pdata` RUNTIME_FUNCTION entries | 25,270 |
| entries whose begin is a defined function | 14,698 |
| entries with **no** function | **10,572 (42%)** |

Those bodies are invisible to the call graph, to order reasoning and to every
structural matcher.  `DstDefinePdataFunctions.java` defines them mechanically
(no renaming): **10,510 created, 59 refused, 14,701 already present**.

The repair also exposed a second gap: the inventory only recorded `call`
instructions, so **tail calls (`jmp fn`) were missing** — and the `.pdata`-only
bodies are precisely the ones reached that way.  Recording `jmp` to a function
entry added **6,272 edges**.

| measurement | before | after |
|---|---|---|
| Windows functions (Ghidra) | 18,733 | **29,248** |
| functions in the inventory | 17,723 | **28,219** |
| call edges | 52,137 | **60,215** (+15%) |
| distinct callees | 11,482 | **16,287** |
| functions with >= 1 callee | 13,601 | **20,149** |
| of the created functions, now referenced | — | 4,811 |

Coverage must be quoted against the honest denominator from now on:
4,876 / 29,248 = **16.7%** (29.3% against the old, incomplete 16,649).

The channels were re-run against the repaired graph; see the next section for
what the extra functions and edges actually bought.

## Re-running the channels on the repaired graph (`stages_rerun.py`)

With 10.5k more functions and 8k more edges, the stages were re-run against the
new inventories (`inv_win_tail.jsonl`, `inv_android_tail.jsonl`) and the fixed
binding tables.

| stage | proposals | usable (named Android side) | applied |
|---|---|---|---|
| S2 unique string | 306 | 111 total across S2+S3 | 98 renamed + 7 folded |
| S3 set similarity | 23 | — | — |
| caller propagation (gated) | 2 | 2 | 0 (already named) |

220 of the 331 raw proposals were dropped because their Android side is
`FUN_*`: the repair makes such pairs *discoverable* but there is still no name to
transfer — the graph grew, the independent evidence did not.

Verification of the applied set (decompiled, not inferred):

* `0x140063300 AccountManagerComponent::HandleEvent` — waits for event type 6,
  pushes `OnAccountEvent`, a bool, a double and a string to Lua, then
  `cSimulation::CallLuaFunction(this, 3)`.
* `0x140082920 AddOverrideBuild` — `cAnimStateComponent::AddOverrideBuild` with a
  hashed build name and an `"ERROR: AddOverrideBuild failed to find build %s"`
  log on failure.

The vtable channel was re-scanned on the repaired program (1,306 runs, unchanged
— `.rdata` did not move) and re-run with the new names: still **87 tables / 469
names**, i.e. stable.

Audit after the re-run (`audit_live.py` against 2,804 provenance records):
**zero unsupported names** — binding 1,096, strings 1,202, graph 101, vtable 363
all pass their evidence test; the remainder are review-confirmed or legacy
records without a recorded address.

| measurement | value |
|---|---|
| Windows functions named | **4,971** |
| coverage, `.pdata` denominator 29,248 | **17.0 %** |
| coverage, old 16,649 denominator | 29.9 % |

## Per-TU block matching (`tu_blocks.py`) — complementary, but it decays with anchors

The repair left a question: can the *layout* carry matching power if the search
space is cut first?  Instead of aligning whole images (which fails, 44% of
consecutive anchors invert), cut both binaries into **segments between anchors
whose Windows addresses stay monotone**, then solve a one-to-one assignment
inside each segment on strings / immediates / size.

Held out 20% of the anchors (3,118 anchors, 714 hidden):

| score threshold | emitted | correct | precision | recall |
|---|---|---|---|---|
| >= 0.62 | 95 | 59 | 0.621 | 0.093 |
| >= 0.70 | 76 | 50 | 0.658 | 0.070 |
| >= 0.80 | 53 | 40 | 0.755 | 0.056 |
| >= 0.90 | 7 | 6 | 0.857 | 0.008 |
| >= 0.70 + rare literal + size ratio >= 0.5 | 39 | 31 | **0.795** | 0.049 |
| >= 0.80 + rare literal + size ratio >= 0.5 | 40* | 31 | 0.775 | 0.049 |

\* same configuration; the gates trade threshold for evidence quality.

**The two channels are disjoint.**  On the same holdout, block matching and
caller+root share **zero** proposals; their union is 47 proposals with 39 correct
= **0.83 precision at 5.5% recall**, versus 0.905 / 2.7% for caller+root alone.
That is the actual result of this line of work: layout gives *more* answers, not
better ones.

**It decays as anchors densify.**  With the holdout's 2,444 training anchors the
channel emits 39 usable pairs; with the live table's 3,118 anchors it emits only
10 (4 with a named Android side).  Segments shrink as more anchors are known, so
the channel is most valuable early — running it after the string stage had
already fired is why its live contribution is 2 renamed + 1 folded.

| measurement | value |
|---|---|
| Windows functions named | **4,973** |
| coverage, `.pdata` denominator 29,248 | **17.0 %** |

### Immediate sequences: measured, negative

The follow-up hypothesis was that an inlined callee inserts a *contiguous chunk*
into the caller, so the **ordered** sequence of immediates should survive where
the set does not.  `DstExportInventory` now emits `imq` (up to 64 immediates in
instruction order) and `immseq_blocks.py` scores LCS inside the same monotone
segments.

| measurement | result |
|---|---|
| block matching on LCS ratio (>= 0.7, LCS >= 6) | 202 emitted, 8 correct, **precision 0.040** |
| stricter thresholds (0.8 / 0.9) | 28 / 4 emitted, 1 / 0 correct |
| LCS ratio, **true** pairs (600 sample) | median 0.375, mean 0.406 |
| LCS ratio, **random** pairs | median 0.294, mean 0.297 |

The true/random separation is 0.08 — the signal is essentially absent, so the
channel was not applied.  The likely cause is architectural rather than
editorial: x86-64 encodes offsets as displacements (`[reg+disp8/32]`) while
AArch64 materialises them as separate `add/sub` immediates, and struct layouts
differ between the two builds, so the constant sequence is mostly encoding noise
even for identical source.

That closes the "expand evidence sources" line of work with a clear ranking of
what actually discriminates on this pair:

| evidence | status |
|---|---|
| binary-native luaL_Reg names | works (1,104 / 1,105 audited) |
| string literals | works (S2/S3: +105 names on the repaired graph) |
| vtable slot order (ABI-fixed) | works (87 classes / 469 methods) |
| ctor → base chain, caller sets with an independent root | works, low recall |
| address order / per-TU blocks | complementary but weak (0.795, decays) |
| immediate sets / sequences | **no usable signal** (0.28→0.29; LCS 0.375 vs 0.294) |
| BSim / P-code similarity (earlier) | no usable signal |

### Android boundary repair: nothing to repair, and why that matters

The `.pdata` gap on Windows left an obvious symmetry question: does the Android
`.so` also miss function starts?  `eh_frame_hdr` answers it directly — it is a
sorted table of (initial_location, fde) pairs, so parsing it gives the linker's
own function list:

| | count |
|---|---|
| `.eh_frame_hdr` FDE starts (after the +0x100000 Ghidra rebase) | 32,493 |
| already in the Android inventory | 32,317 |
| missing | 176 |
| of those 176, already defined functions in Ghidra | **176** |
| functions with no FDE (thunks / hand-written asm) | 96 |

`DstDefineFunctionsFromList.java` was written for this and reported
`created=0 existed=176`: **the Android side needs no repair**.  The 42% gap was a
Windows-analysis artefact, not a property of the pair.

### The real asymmetry is body divergence

With boundaries settled (28,219 Windows vs 32,493 Android) the remaining
difference is the code itself.  Measured on 782 known pairs:

| instruction-count ratio (win / android) | share of pairs |
|---|---|
| median | **0.667** |
| >= 0.80 | 25.1% |
| >= 0.90 | 15.0% |
| == 1.00 | 7.2% |
| Windows < 60% of Android | 35.8% |
| Windows > 160% of Android | 9.2% |

So three quarters of even the *correct* pairs differ by more than 20% in body
size.  That explains every negative result in this document at once: size gates
keep only ~25% of true pairs, immediate sets/sequences decorrelate, and BSim-style
P-code similarity collapses — while the channels that survive are exactly the
ones insensitive to body content (table names, string literals, vtable slot
order, coarse call-graph signatures).

The divergence is not uniform.  Median body ratio per class family (>= 5 pairs):

| family | median win/android body ratio | n |
|---|---|---|
| `btStaticPlaneShape`, `btConvexInternalShape` | **1.00** | 5, 5 |
| `SamplerEffect` | 0.95 | 9 |
| `btDbvtBroadphase` | 0.94 | 8 |
| `cLuaNetworkVariableType<cHashedString>` | 0.92 | 6 |
| `btGeneric6DofConstraint`, `btCollisionShape` | 0.86, 0.83 | 7, 7 |
| … | … | … |
| `cMapExplorerComponent`, `cSoundEmitterComponent` | 0.49, 0.45 | 7, 9 |
| free functions | 0.40 | 27 |
| `MapComponentBase` | 0.20 | 6 |
| `cEntityComponent` | **0.07** | 14 |

Third-party code (Bullet) compiles to near-identical bodies on both sides, while
the engine's component hierarchy diverges by an order of magnitude.  That is the
actionable split: body-sensitive matching (size, immediates, sequences, P-code)
is only meaningful inside the library families, and the engine needs the
body-insensitive channels that are already in place.

### Family-scoped body matching: measured, negative

Given the family table, the natural follow-up was: restrict body-sensitive
matching to the comparable families.  `family_blocks.py` scores unnamed
functions inside a class span by size + immediate set + basic blocks, one-to-one.

| measurement | result |
|---|---|
| holdout (3,118 anchors): emitted / correct | 340 / 16, **precision 0.047** |
| restricted to classes with median body ratio >= 0.85 (83 classes) | emitted 340 → correct 16 |
| rank of the *true* windows function under the body score, all classes | **rank 1 in 9.3%**, worse than 3rd in 79.4% |
| rank of the true function inside comparable classes only | **rank 1 in 15.1%**, worse than 3rd in 76.5% |

The rank diagnostic is the decisive number: inside a class the true counterpart
is the best body match only 9-15% of the time, i.e. roughly chance for a span of
5-10 candidates.  Siblings resemble each other more than they resemble their
cross-build counterpart — getters share size and offsets, accessors share
immediates — so no size/immediate/CFG score can separate them.  Nothing was
applied.

Final ranking of evidence on this pair, all measured in this document:

| evidence | verdict |
|---|---|
| binary-native luaL_Reg names | works (1,104 / 1,105) |
| string literals | works (+105 names after the repair) |
| vtable slot order (ABI-fixed) | works (87 classes / 469 methods) |
| ctor → base chain, caller sets + independent root | works, low recall |
| address order / per-TU blocks | complementary, weak, decays with anchors |
| immediate sets / sequences | no usable signal |
| size / CFG / P-code (BSim) similarity | no usable signal, even in comparable families |

### Expanding string attribution: one level of indirection, small net gain

The last untested source was table-driven strings: a function that references an
array of `char*` (luaL_Reg-like arrays, static name tables) owns those strings,
but the exporter only took strings whose address appeared directly in an
instruction.  `DstExportInventory` now follows one level of indirection (up to 48
qwords per data reference) and the cap rose from 96 to 256.

| measurement | before | after |
|---|---|---|
| Windows functions with >= 1 string | 4,945 | **5,067** |
| Android functions with >= 1 string | — | **7,088** |
| S2 + S3 pairs on the same used-set | 235 | **239** |
| new-only / lost pairs | — | 14 / 10 |

Net **+4 pairs**, applied (8 rows: 6 renamed, 2 folded).  The reason the gain is
so small is structural: attributing a table's strings to the referencing function
makes those strings *less unique*, and S2's power comes precisely from
uniqueness — 10 pairs that were unique before became ambiguous.  Broadening
attribution trades anchors for coverage and roughly cancels out at this density.

| measurement | value |
|---|---|
| Windows functions named | **4,981** |
| coverage, `.pdata` denominator 29,248 | **17.0 %** |
| coverage, old 16,649 denominator | 29.9 % |

### Two corrections that change earlier conclusions

**1. The precision metric was wrong in both directions.**  Proposals target
functions that are *not yet named*, so a proposal can only be "judged" when its
Windows side happens to be a held-out pair.  Every earlier table in this document
scored unjudgeable proposals as wrong, i.e. it reported a *lower bound*:

| channel | old figure (unjudgeable counted wrong) | precision on judged proposals |
|---|---|---|
| string groups (per-string assignment, IDF-weighted) | 0.34 | **11 / 11 = 1.000** |
| per-TU blocks (rare literal + size gates) | 0.795 | **19 / 19 = 1.000** |
| family body matching | 0.047 | 7 / 12 = 0.583 |

The judged subset is biased the other way (those pairs were reachable by other
channels), so the truth lies between the two numbers — the honest statement is a
wide interval, and only manual sampling of *applied* pairs settles it.

**2. 74% of the `.pdata` repair was spurious.**  Measured alignment of the
entries Ghidra did not already have:

| set | 16-byte aligned | 8 | 4 | unaligned |
|---|---|---|---|---|
| pre-existing functions | **99.6%** | 0.0% | 0.0% | 0.3% |
| created from `.pdata` | 6.7% | 6.5% | 12.4% | **74.4%** |

MSVC aligns x64 function starts to 16 bytes, so three quarters of the 10,510
created entries are EH funclets / chained-unwind fragments — interior points of
real bodies, which decompile with `unaff_` registers (verified on
`0x140290de9`).  They inflate the function count (29,248 → ~19.5k real), pollute
the graph and are unsafe naming targets.  `DstDefinePdataFunctions` now skips
unaligned entries by default.

### After the cleanup: 9,710 spurious functions removed, two more figures corrected

`DstDeleteFunctionsFromList.java` removed **9,710** of the mis-created functions
(83 kept because they already carry a name, 11 already gone).  State after:

| measurement | before cleanup | after |
|---|---|---|
| Windows functions (Ghidra) | 29,248 | **19,527** |
| functions in the inventory | 28,219 | **18,509** |
| tail-call edges | 6,272 | **270** |
| Windows functions named | 4,981 | **4,982** |
| coverage | 17.0% (wrong denominator) | **26.9%** |

Two earlier conclusions had to be withdrawn:

* the "MSVC emits 6,272 tail calls vs clang 338" asymmetry was an artefact — most
  `jmp` edges came from the spurious fragment "functions".  After cleanup both
  sides are ~270 / ~350, i.e. the call-graph extraction is fine on both sides;
* the block channel's live yield was mostly being absorbed by fragments; on the
  clean set its judged precision is **18 / 18 = 1.000** and it emits 28 pairs.

The last usable proposal — `0x1402d6670` → `cMasterServerRequest::DownloadServerMinimalDetails`
— was verified by decompilation (builds a JSON query with `__gameId`, `__token`,
`__rowId`, `region`, then `GetLobbyEndpointForRegion` + `"/lobby/read"`).

### Segment-level alignment and the real ceiling

`segment_align.py` implements the review's cascade at the block level: cut at
confirmed anchors into monotone segments, then decide each segment as a group
with four weak dimensions combined (IDF-weighted literals 0.50, size 0.25,
immediates 0.15, mapped-callee overlap 0.10), accepting a pair only if it is
mutual-best, clears the score bar and the segment is coherent (>= 2 accepted
pairs, or one pair with >= 2 specific literals).

| measurement | value |
|---|---|
| holdout proposals | 7 |
| judged proposals | 3, **all correct** |
| live proposals (3,118 anchors) | 5, of which 2 usable |
| verified by decompilation | `RakNet::PacketLogger::FormatLine` (packet-id to name table), `tServerListing::Deserialize` |

Yield is tiny for a measured reason, not a tuning one:

| reachable unnamed functions inside segments | count |
|---|---|
| android | 5,760 |
| windows | 11,309 |
| ...of which have **>= 1 string literal** | **1,024** / 1,605 |
| ...of which have >= 2 literals | 378 / 686 |

**82% of the reachable unnamed functions carry no string literal at all**, and
every other dimension has been measured non-discriminative (body size, CFG,
immediates, P-code, per-class order).  So the automated channel is bounded at
roughly the string-bearing population — ~1k candidate functions on the Android
side — and it already extracts most of what that population allows.

| measurement | value |
|---|---|
| Windows functions named | **4,983** |
| coverage, clean denominator 18,509 | **26.9 %** |
| judged precision of the last three channels | 18/18, 11/11, 3/3 |

### Unified anchors: the call-graph stage finally has enough seeds

Each stage had been reading its own history file, so propagation always started
from the ~3.1k pairs that happen to carry an `A=0x...` column.  `build_anchors.py`
merges every recorded source into one set and drops contested pairs:

| source | pairs |
|---|---|
| name join (live names onto Android qualified names) | 2,789 |
| binding tables (binary-native both sides) | 1,167 |
| vtable transfer | 438 |
| earlier stage files | 264 |
| **total** | **4,011** (107 conflicting Android claims dropped) |

With that seed set the caller stage (call-graph only, no independent-root gate)
produces **398 proposals**, of which 47 land on held-out anchors and **43 are
correct — judged precision 0.915**, flat across caller counts (2-4: 0.946,
5-9: 0.800, >=20: 2/2).  The earlier root gate had been rejecting most of these
because they carry neither string literals nor comparable body sizes — exactly
the case the review predicted: a strong dimension was being used as a hard gate
instead of as a constraint for the next one.

Applied: **56 names** (53 renamed, 3 folded), spot-checked by decompilation —
`luaL_checkinteger` (`lua_tointegerx` + `auxiliar_typeerror(L, idx, LUA_TNUMBER)`)
and `RakNet::PacketLogger::FormatLine`-class helpers all match.

| measurement | value |
|---|---|
| Windows functions named | **5,039** |
| coverage, clean denominator 18,509 | **27.2 %** |
| caller stage judged precision | 43 / 47 = **0.915** |

### The iteration loop: two productive rounds, then it converges

With the unified anchors the caller stage can be iterated (apply -> re-anchor ->
re-run).  Each round was monitored with the judgeable-precision metric:

| round | anchors at start | proposals | applied | judged precision |
|---|---|---|---|---|
| 1 | 4,011 | 398 (56 usable) | **56** | 43/47 = 0.915 |
| 2 | 4,066 | 4 (3 usable) | **3** | — |
| 3 | 4,069 | 0 | 0 | — |

Total **+59 names** from the call-graph stage, taking the table to **5,042**.
The loop converges in three rounds because the caller signature is only
informative for functions whose callers are *already* mapped, and the newly named
functions have few unmapped callers of their own.

| measurement | value |
|---|---|
| Windows functions named | **5,042** |
| coverage, clean denominator 18,509 | **27.2 %** |
| caller stage, judgeable precision | 0.915 |

### Semi-automatic review ranker: the remaining pool is 258, and it is weak

`review_ranker.py` scores every (unnamed Windows function, candidate Android
function) pair from all dimensions — mapped callers, mapped callees, IDF-weighted
literals, size — keeps the best candidate per function, and emits a ranked list
with a per-dimension breakdown for triage.

The tool works; the pool is the problem:

| unnamed Windows functions | count | share |
|---|---|---|
| total | 13,257 | 100% |
| **no evidence at all** (no shared literal, no mapped neighbour) | **12,709** | **95.9%** |
| evidence, but the Android side is itself unnamed | 290 | 2.2% |
| evidence pointing at a *named* Android function | **258** | **1.9%** |
| of those, clearing the mild bar (weighted literals >= 0.8) | 8 | — |

So the semi-automatic path can offer a human roughly **258 candidates**, and the
strongest of them rest on a single generic literal (score <= 0.25).  There is no
hidden reservoir left behind the automatic channels — the remaining functions are
not "hard to match", they are *unmatched by construction*: their counterpart in
the other binary carries no name either, or no shared evidence survives the
version gap.

Final state of this line of work:

| measurement | value |
|---|---|
| Windows functions named | **5,042** |
| coverage, clean denominator 18,509 | **27.2 %** |
| evidence-free among the remaining 13,257 | **95.9 %** |
| channels with measured judgeable precision | binding 0.999, strings ~0.95, vtable 1.00, caller 0.915, blocks 1.00, segment 1.00 |

## Known limits

- **Call edges on PIC/ELF builds are mostly PLT trampolines** (86 % on
  `libDontStarve_2.2.1.so`, because it exports every symbol). Resolve
  `Function.getThunkedFunction(true)` before building any call graph, otherwise
  every edge points at a stub, seed lookups by real entry never hit, and graph
  propagation returns exactly zero. After resolution Android edges land 100 % in
  `.text` and S5 goes from 0 to ~430 named pairs.
- Even fixed, propagation is bounded by seeds: 62 % of the seeded Android
  functions have no direct caller at all (they are invoked through `luaL_Reg`
  tables / vtables), so only ~134 unmatched functions ever qualify.
- Only functions are named; data symbols, structs and non-`lua_CFunction`
  prototypes are out of scope.
- Ghidra's function list under-covers the Windows image (`.pdata` has ~30 %
  more ranges than defined functions); funclet boundaries are not repaired.
- Strings are read from raw memory on purpose: ELF `.rodata` strings are often
  left undefined by analysis, and a defined-`Data`-only reader silently returns
  zero tables (observed on `libDontStarve_2.2.1.so`).
- Immediate sets are not normalized for AArch64 `movz/movk` splitting, so the
  immediate feature favours x86 code slightly.
- Versions must match: a 1.1.28 style pairing needs its own Windows build. The
  fingerprint + binding-name overlap is the check.

## Rejected channels (measured, do not rebuild)

Both were built and evaluated against the live pair; the numbers are the reason
they are not in the pipeline.

### 1. Unnamed↔unnamed literal pairing

Motivation: 22.4 % of `libDontStarve_2.2.1.so` (7,265 functions) has no symbol,
and that residual is exactly the statically linked third-party code, which is
also unnamed in the Windows build, so those pairs are invisible to every channel.

Measured: 147 pairs (97 at literal containment 1.00), covering json-c, libcurl,
zlib, the Lua loader and the SSL PEM paths. Every pair is third-party; **zero**
light on core types. Naming them would need an upstream library symbol source
(not a property of the binary pair), so the channel cannot produce a name.

### 2. Vtable slot-level string anchors

Motivation: identifying a class table by an already-named slot only covers 145 of
748 engine classes, because few named Windows functions are virtual. A slot whose
function references a rare literal would be an independent anchor, and one anchor
pins the whole table.

Measured on the engine tables it pinned: cross-checked against the names already
assigned by other channels, **agreement 24 vs disagreement 238**; only 2 of 19
engine tables had zero disagreement. Cause: `~dtor`/`getter`/`setter` bodies share
literals across unrelated classes, so the anchor lands on a same-literal function
of a different class. Library tables (Bullet) pin cleanly, but those are not the
target. Not applied.

### Consequence for core types

Engine functions on the Android side: 16,065 named, of which 3,580 (22.3 %) have
a Windows counterpart. Of the 12,485 unanchored engine functions, **12,031
(96.4 %) share no literal and no mapped neighbour** with the Windows image, and
only 538 of 7,426 engine vtable slots (7.2 %) are mapped. RTTI cannot rescue this:
the Windows build has 9 type descriptors in 7.7 MB (CRT + boost only), i.e. the
engine itself is compiled `/GR-`.

Evidence-only channels therefore plateau near 22–25 % for core types; going
further needs a per-class identity root supplied from outside the binary pair
(same-compiler reference build / PDB, or human-confirmed table pinning).

## Annotation export defect (fixed) and what it cost

`DstAnnotateVtables.java` wrote slot literals raw, so a string containing a
newline split the record and a string containing a comma broke the slot list.
Measured on `vt_win_annot6.tsv`: **71 of 1,306 records** were truncated (a 64-slot
table parsed as 8), which silently hid every pin that depended on the cut tail —
`cNetworkComponent` had "no candidate" for exactly this reason.

The script now maps `\t \r \n , :` to spaces/semicolons. Regenerated files:

| file | runs | slots |
|---|---|---|
| `vt_win_annot7.tsv` | 563 (ref-derived) | 14,267 |
| `vt_win_annot8.tsv` | 1,306 (pointer scan) | 6,273 |

Both agree on every per-class result in the component tree, which is the control
that the escaping fix is neutral and the truncation was the only difference.

## MSVC vtable groups (component tree, manual pass)

* Secondary-base groups are emitted **before** the primary table inside the same
  `.rdata` run, so a pin's `(run, off)` is the *primary* table and the class's
  `"out of run"` tail is usually the group at offset 0.
* Group layout: `[scalar-deleting-dtor adjustor thunk, virtuals in declaration order]`.
  The thunk is `sub rcx,<subobject offset>; jmp <deleting dtor>` and the offset
  equals the subobject offset in the Android layout — an independent check.
* Inside a group `group[g] = android idx (g + N)` with N the primary slot count.
* Android idx 2 (`PostConstruction`) exists as a 4-byte no-op in the Android
  table but has **no Windows slot**; `win = android - 2` applies from idx 3 only.
  Fifteen `cEntityComponent::PostConstruction` names were deleting dtors and were
  renamed to `<Class>::~<Class>` (see `build/symmatch/manual/fix_dtors.tsv`).

## Delta is per family, not global (measured on three families)

| family | rule |
|---|---|
| `cEntityComponent`-derived (37 classes) | `win = android − 2` from idx 3; android idx 2 `PostConstruction` has no Windows slot |
| `SceneGraphNode`-derived | tables are **14 slots**; android idx 7 `GetPrototype` has **no** Windows slot, so `− 2` only from idx 8 |
| `cResourceManager<T>` (13 instantiations) | `win = android` for slots 0..6, slot 7 = android idx 9 (`Load_LowLocking`); android idx 7/8 absent |
| `FileSystem` family | `win = android − 1`, except the two `Write` overloads (Windows adjacent 5,6; Android 6,10) |

Corollary: never carry a delta across families, and never infer the delta from the
slot *count* difference alone — the missing slot can be anywhere in the middle
(`GetPrototype`), not at the head.

## Downward propagation: call order vs call-site arguments (measured)

Asking "can the CFG tell which callee is which" splits into two different
experiments; both were run on this pair.

### A. Call-site *order* inside an anchored pair — rejected

`DstExportInventory` records `cal` in instruction order, so no export was needed.
Tokens = anchored callees; LCS over them gives blocks, and everything between two
blocks is a gap.

| measurement | value |
|---|---|
| anchored pairs with callees on both sides | 4,069 |
| gaps between anchored call blocks | 3,234 |
| gaps with equal size on both sides | 1,701 (**52.6 %**) |
| positional prediction on held-out (hidden) anchors | 538 predictions, **precision 0.481** |
| same, gap size 1 and at the head of the sequence | 48 predictions, precision 0.938 |

Gap equality is only 52.6 % because inlining removes call sites on one side, and the
anchor density (13 % of Android functions) leaves few blocks to align against.
Tool: `manual/callsite_order.py`. Not applied.

### B. Call-site *argument* fingerprint — adopted with a gate

A callee often owns no literal, but the caller passes the same constant at that
call site on both builds. `ghidra/DstExportCallSites.java` exports, per function,
the ordered call sites with the immediates and literals seen in the 16-instruction
window before each call (bounded by the previous call):

| measurement | value |
|---|---|
| exported call sites | windows 69,995 / android 156,927 |
| unique signature match inside an anchored pair | 250 |
| precision sample, ungated | 42 -> **0.881** |
| + independent gate `ni_ratio >= 0.6` | 29 -> **0.966** |
| transferable (android named, windows unnamed) after the gate | 24 (19 applied) |

The gate matters: the raw signatures are immediate-tuple collisions, the
instruction-count ratio removes them. Literal-bearing signatures are almost
nonexistent (2 samples) because strings are usually materialised several
instructions earlier or through a temporary, so the channel runs on immediates.
Tool: `manual/callsite_args.py`.

### C. Decompiler call arguments (high P-code) — adopted, precision 0.980

Variant B only sees constants in the caller's straight-line code. `DstExportCallArgs.java`
walks the decompiler's high P-code instead and resolves each CALL argument one to
three definitions deep, collecting constants, the strings they point at, and the
callee of the call that produced the argument (e.g. the `std::string` ctor).
Exported: windows 18,509 functions, android 32,407.

Counter-intuitive but measured: **string-bearing signatures are the *least*
precise** form of this channel.

| signature set | ni gate | callee pairs | precision |
|---|---|---:|---:|
| any (>=1 string or >=2 immediates) | 0.6 | 174 | 0.948 |
| any | 0.8 | 143 | 0.958 |
| any | **0.9** | **102** | **0.980** |
| string-bearing only | 0.6 | 29 | 0.621 |
| string-bearing + `via` | 0.6 | 5 | 1.000 |

Strings passed at a call site are usually generic (`"true"`, `"0"`, `"SetX"`), so they
collide across callees; immediates plus the instruction-count ratio separate better.
Applied at `ni >= 0.9`: 64 candidates, 35 new names (the rest were already named —
the merge validator rejects any row whose address carries a different live name).

## Current state (round 88)

| metric | value |
|---|---:|
| symbols in the metric universe (see note) | 4,975 |
| named on Windows, strict (class + method or exact signature) | **3,380 (67.9 %)** |
| named on Windows, legacy bare-method metric | 3,661 (73.6 %) |
| named functions in the live DB | 7,124 |
| ledger `unproven` | 239 (plus 446 `unreferenced`) |

Per-symbol status lives in `build/symmatch/manual/CORE_LEDGER.tsv`; the 811 open rows are grouped by
class with their Android address, size, callees and field offsets in
`build/symmatch/manual/UNPROVEN_WORKLIST.md`.

### Reproducing the numbers

```bash
# export the live DB's names, then recompute both views
analyzeHeadless C:/Users/fesil dst -process "dontstarve_steam_x64_live.exe" -noanalysis \
  -scriptPath C:/Users/fesil/ghidra_scripts \
  -postScript DstExportNames.java build/symmatch/vt2/win_names_live107.tsv
python tools/symmatch/manual/coverage.py build/symmatch/vt2/win_names_live107.tsv
python tools/symmatch/manual/ledger.py   build/symmatch/vt2/win_names_live107.tsv
```

Both tools normalise C++ signatures (`std::__ndk1::` -> `std::`, `basic_string<...>` -> `std::string`,
strip `_<hex>` and trailing `const`) so overloads are credited individually instead of being reported
`unproven` because the DB name carries a parameter list.

### Helper scripts (this session)

| script | role |
|---|---|
| `DumpUnnamedRange.java lo hi [all]` | decompile every function in an address range, marking named vs unnamed |
| `FindByteSwap.java` | every function containing `BSWAP`/`MOVBE` (locates endian-swapping serializers) |
| `DstFindConstants.java values.tsv out.tsv` | locate 32-bit constants in the image and report the containing function |
| `manual/calleename.py` | match an Android member to a Windows function by the names it **calls** (delta-aware, rarity-weighted) |
| `manual/callerset.py` | same by **who calls it** - the stronger signal for small members; 38 % of its raw proposals still fail body inspection |
| macOS reference | the old symbolized 32-bit macOS build is a third source: 800 open rows have a same-name twin there and its **string literals** anchor into the Windows binary (+7 names). Its inventory export needs `getDefaultPointerSize()` - the 8-byte assumption crashes on the 32-bit build. |
| proxy-callee rule | an unproven member whose method has exactly one named twin - the class's own LuaProxy - is that twin's unnamed callee; +5 names |
| audit rule | a function of <= 10 bytes whose only instruction is one call must be the member named after that callee; applied to the *whole named set* it found 2 wrong names in 17 candidates (`ResetAchievements` -> `GetPlayer`, `GetLocalBBox` -> a dtor adjustor thunk) |
| `manual/macanchor.py` | macOS-anchored matching (string + callee anchors, df filter); documents the string-ownership and immediate-collision traps |
| (note) `coverage.py --out PATH` | tests pass `--out` into a temp dir so they cannot rewrite the committed report |
| `manual/annotate_core_funcs.py` | rewrites the `未迁移` / `否定迁移` columns of `CORE_FUNCS_2.2.1.md` from the ledger (idempotent) |
| `manual/selfcall.py` | an unnamed function whose resolved callee carries the member's name is that member (forwarders); 5 of 14 raw proposals fail body inspection |
| `manual/combined.py` | scores callees + callers + size together, keeps unique winners and drops targets claimed by >1 member (generic-helper signature); 7 of 12 raw proposals in rounds 49-50 failed body inspection |

`DstFindConstants` produced the session's only *bulk-decisive* result: the twelve SHA-256 round
constants hit exactly one function in the 7.6 MB image, which named `SHA256_Klei::processBlock`, and
its callers then gave `add`, the constructor and `operator()(std::string const&)`.

### Channels measured and rejected (do not retry)

| channel | measurement |
|---|---|
| relaxed caller intersection (1 common twin instead of 2) | all 6 false positives |
| two-hop propagation through unnamed callers | 2 candidates, both rejected on body |
| callee *name-set* comparison | **now works** - the earlier "2 % resolve" measurement was wrong; the inventory uses project addresses that sit 0x100000 above the ELF VAs, and with the delta 84.1 % resolve. See `manual/calleename.py`; yielded 3 verified names in round 47 |
| class-alias assumption (`AnimNode` vs `cAnimStateComponent`) | both classes declare the methods; DB names are correct |
| field-offset signatures (triple / full set / shifted) | 126,381 and 24,756 proposals, **0** unique |
| size uniqueness inside the class span | 27 hits, none usable (4-8 B accessors, conflicting addresses) |
| `.rodata` blob fingerprint | Android `.rodata` is pointer-dominated, nothing survives relocation |
| class-span locality ("search the neighbourhood") | `cAccountManager`: 25 functions in the 4.2 KB named span, 2 unnamed, 0 matching |
| in-class field-offset **set** equality (android `imm` vs Windows `imm`, 0x40-0x1000) | 18 proposals, both opened ones wrong; 6/18 point at an address another member also claims |
| vtable slot transfer with a per-class delta | works for plain single-inheritance classes (+2 names); fails wherever the dtor count or the base ordering differs (`AnimNode`: delta -2 vs 0 within one table; RakNet replica tables: -18/-17/-14/-1) |

The 811 remaining rows need per-member decompiler judgement, or a new symbol source (a same-compiler
build with PDB, or upstream library symbol tables).
