---
name: dst-crossarch-symbol-bootstrap
description: "Migrate Android (AARCH64, symbolized) DST engine symbols onto the Windows x64 binary via anchor tables + BSim + labeled-pair calibration; use for cross-architecture symbol bootstrap, not same-arch version tracking."
---

# DST cross-architecture symbol bootstrap (ARM64 → x86-64)

Goal: give the stripped Windows `dontstarve_steam_x64.exe` names using `libDontStarve*.so` (Android, symbolized) as ground truth. Fully automatic part only; no manual renaming.

## 0. Preflight (never skip)

- Confirm which programs are actually open: `list_open_programs`. The Ghidra project is often left with an **old** exe image — check section RVAs, not the name.
- Build fingerprint = `sha256 + PE TimeDateStamp + .rdata/.data RVA + hash(sorted binding-name set)`.
  - Current Steam exe: `.rdata 0x514000`, `.data 0x61d000`, PE ts 2026-10-01.
  - Old image inside the `dst` project: `.rdata 0x14050d000`, `.data 0x140614000` — **it is a different (older) build**; do not mix labels across builds.
  - Version check: current Windows build and Android **2.2.1** both contain `BarterLoseAllDuplicateItems`, `ClearMovementPrediction`, `GetCurrentAnimationHash`, `IsSkinBuild`, `RevealEntity`; Android 1.1.28 does not.
- Script execution must be enabled: `GHIDRA_MCP_ALLOW_SCRIPTS=1` on the GhidraMCP headless process, restart it. Otherwise `run_script_inline` returns `Script execution disabled`.
- Denominators: Android `.eh_frame_hdr` FDE count (2.2.1 = 32,493) and Windows `.pdata` RUNTIME_FUNCTION count (≈25,087) — Ghidra's `function_count` under-reports Windows by ~30%.

## 1. Extract exact anchors (no similarity)

### 1a. Lua binding tables (highest value, ~100% precision)

Entry layout: `{const char* name → rodata, void* func → .text, zero padding}`.

- **Android stride 32**, tables in `.data` **and** `.data.rel.ro` (scan both; ImGui/Steam tables are separate).
- **Windows stride 24**, tables in `.data`.
- Detector must: try strides {16,24,32}; require ≥3 consecutive entries; require a `{NULL,NULL,0}` terminator; require `func` to be a defined function entry. Naive "pattern match anywhere" produces false positives like `()V`, `FTP`, `7bit` from 16-byte stride noise.
- Typical yield: Android 2.2.1 ≈ 1.6k entries / 1.53k unique names; Windows ≈ 1.45k names; shared 2.2.1↔Windows-current 1,241 → **≈1.2k 1:1 exact cross-arch pairs**, and these are also the calibration labels for the structural matcher.
- Validate an entry by decompiling: a lua_CFunction takes `lua_State*` and returns a small int (e.g. `GetPosition` returns 2 numbers).

### 1b. String anchors

- Windows: 3,529/25,087 functions (14.1%) reference ≥1 string; 1,889 (7.5%) own a string unique to them; 1,418 of those strings also exist in the Android `.rodata` (5.7%).
- Join must require uniqueness **on both sides**; use multi-string voting (Jaccard) for non-unique cases, and `.cpp`/`__FILE__` strings as TU tags for bucketing.
- Shared-string volume is the cheapest version-parity test: 2.2.1↔Windows-current 6,268; abort if < ~4,000.

## 2. Structural scoring

- Ghidra's Version Tracking has **no** cross-architecture correlator (only exact bytes/instructions/mnemonics) — unusable here.
- ghidra-mcp `bulk_fuzzy_match` / `find_similar_functions_fuzzy` are **not** cross-arch (features: callee names + mnemonic block hashes) — measured 0 hits at threshold 0.3 on a verified pair. Do not use them as the primary matcher.
- Use BSim (decompiler P-code cosine, the only arch-independent feature space) with an embedded H2 db and the size-insensitive template:
  ```
  support/bsim createdatabase file:C:\bsim\dst medium_nosize
  support/bsim generatesigs ghidra:/C:/Users/fesil/dst C:\bsim\sigs --bsim file:C:\bsim\dst
  support/bsim commitsigs file:C:\bsim\dst C:\bsim\sigs
  ```
  H2 allows one process at a time and a non-shared project is locked while Ghidra runs → run on a **copy** of the project.
- Train weights on the ≈1.2k binding pairs (5-fold CV, hold out 20%) instead of hand-tuning; add string-set Jaccard, immediate-set Jaccard (reassemble ARM64 `movz/movk` constants), size/BB/edge ratios, callee-name agreement, data-ref Jaccard, BSim cosine.
- Assign one-to-one per bucket (Hungarian) with a `top1 − top2 ≥ margin` gate; never nearest-neighbour (MC `/OPT:ICF` folds identical bodies → many-to-one).
- Iterate 2–3 rounds feeding accepted names into callee-name agreement.

## 3. Gates and write-back

- Holdout blind test: Top-1 ≥ 90%, precision ≥ 95% at the chosen threshold, otherwise produce a report and write nothing.
- Write functions only: `set_function_name` + `set_function_prototype` (`int f(lua_State*)` for bindings) + tag `sym:exact|high|medium` + plate comment with Android address, evidence, score.
- Use per-function apply tools; **`merge_program_documentation` is address-based** and therefore useless across architectures.
- Expect ≈35–45% coverage of Windows functions fully automatically (exact ~12%, structural ~25–32%); the residual is string-less leaves, platform-only code and ICF-folded bodies.

## Gotchas

- Tool outputs above ~40 KB are elided; read program memory in 4096-byte chunks from `eval` (~21 ms per MCP call), never in one big read.
- The Ghidra JSON returned by MCP tools can contain raw control characters — parse with `json.JSONDecoder(strict=False)` and strip the trailing ``` fences.
- Symbol names in the Android program are demangled and duplicated (PLT thunks, EXTERNAL space, overloads) — always pair by address, never by name alone.
- Android Ghidra `function_count` includes `.plt` thunks and EXTERNAL entries; exclude them from coverage math.
