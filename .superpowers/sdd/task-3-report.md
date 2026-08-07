# Task 3 Report: Signature body ⊆ Nucleus; target-local resolve

**Branch:** `feature/nucleus-function-body`  
**Worktree:** `C:/Users/fesil/DontStarveLuaJIT2/.worktrees/nucleus-function-body`  
**Base:** Task 2 at `8ca6ebe`  
**Date:** 2026-08-07  

## Summary

Wired Nucleus `FunctionTable` into the signature-update path so training `Function::size` comes from Nucleus spans (not next-export gaps). Constrained `Creator::scan_by_block` to `[address, address+size)` and rewrote target-side `scan_by_signature` to scan with `pattern_offset = 0`, resolve via target `FunctionTable::containing`, and store **target-local** `pattern_offset = entry - match`. No `training_body_end` / magic `0x1000` retreat remains in `Signature.cpp` (none were present; contract enforced by body clamp + table resolve).

## Acceptance

| Criterion | Status |
|-----------|--------|
| No `training_body_end` / `0x1000` magic in `Signature.cpp` | PASS (grep clean) |
| Patterns constrained to `original->size` from Nucleus | PASS (`scan_by_block` clamp + size==0 fail) |
| Target resolve uses `FunctionTable::containing` | PASS (`scan_by_signature` + update snap) |
| `nucleus_adapter` tests pass | PASS |
| Commit on feature branch | PASS (this commit) |
| Report path | PASS (this file) |

## Changes

### `ModuleSections`

- `ModuleSections::function_table` — process-VA Nucleus spans.
- `apply_nucleus_function_table(sections, image_table, image_base)` remaps preferred ImageBase spans to process load base and sets each `Function::size` from `span_containing`.

### `Signature.cpp` (`Creator`)

- **`scan_by_block`:** requires `original->size != 0`; rejects blocks outside body; clamps window to body; rejects `real_address` outside body.
- **`scan_by_signature`:**
  1. Training validate with training `signature_offset` (unique hit at original entry; match ⊆ body).
  2. Target scan with **offset 0**.
  3. `entry = target->function_table.containing(match)`; unique entry required.
  4. Store `signature_info->pattern_offset = entry - match` (target-local only).
- **`limit_signature`:** shortens using last training offset; each candidate re-resolves target-local po via `scan_by_signature`.

### `DontStarveSignature.cpp` (`update_signatures`)

- After `init_module_signature` for lua51 + game:
  - `nucleus_analyze_file(lua51_path)` / `game_path`
  - `apply_nucleus_function_table` for both (throw on failure — no silent heuristic).
- Known exports with `size == 0` after Nucleus sizing → visible error.
- Post-match snap prefers target `function_table.containing` over pdata (pdata remains optional; Nucleus wins).

## Build & test evidence

Smoke tree (Task 1–3, worktree-local, gitignored under `builds/`):

```text
cmake -S builds/nucleus-only -B builds/ninja-nucleus \
  -G "Ninja Multi-Config" \
  -DCMAKE_TOOLCHAIN_FILE=<repo>/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-windows-custom \
  -DVCPKG_INSTALLED_DIR=<master>/builds/ninja-multi-vcpkg/vcpkg_installed

cmake --build builds/ninja-nucleus --config RelWithDebInfo \
  --target function_relocation_static test_nucleus_adapter test_signature_body_link -j 8

ctest --test-dir builds/ninja-nucleus -C RelWithDebInfo --output-on-failure
```

Result:

```text
1/2 Test #1: nucleus_adapter ..................   Passed
    lua_getstack: va=0x1800090f0 entry=0x1800090f0 end=0x18000916a size=0x7a
2/2 Test #2: signature_body_link ..............   Passed
    unit remap: process sizes 0x7a / 0x100 from image spans
    lua51 nucleus spans=887 image_base=0x180000000
100% tests passed, 0 tests failed out of 2
```

Notes:

- Full product `signature_updater` needs the main multi-vcpkg tree configured for this worktree (Injector + plugins). Task 3 smoke builds `function_relocation_static` with Signature/ModuleSections/NucleusAdapter and verifies the new API link + remap unit.
- Signature JSON regen is Task 4 (skipped per assignment).

## Files touched

- Modify: `src/FunctionRelocation/ModuleSections.hpp`
- Modify: `src/FunctionRelocation/ModuleSections.cpp`
- Modify: `src/FunctionRelocation/Signature.cpp`
- Modify: `src/DontStarveInjector/plugins/plugin_core_vm/signature_load/DontStarveSignature.cpp`
- Create: `.superpowers/sdd/task-3-report.md`
- Local only (gitignored smoke): `builds/nucleus-only/CMakeLists.txt`, `builds/nucleus-only/test_signature_body_link.cpp`

## Forbidden helpers

```text
rg training_body_end|0x1000|next_export src/FunctionRelocation/Signature.cpp
# no matches
```

## Follow-ups (Task 4+)

- Rebuild full `signature_updater` against worktree sources and regenerate `signatures_*.json`.
- Verify getstack entry bytes are body prologue (`4c 8b 49 28…`), not stub.
- Optional pdata cross-check log only (do not override Nucleus).

## Fix: Important review findings

**Date:** 2026-08-07  
**Commit message:** `fix(signature): zero residual sizes; refuse LCS with FunctionTable`

### Findings fixed

| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| 1 | P1 | `apply_nucleus_function_table` left ScanCtx/next-export sizes when no Nucleus span hit | Always set `fn.size = 0` when `span_containing` misses; scan paths already refuse size 0 |
| 2 | P1 | LCS fallback could return entry while keeping training `pattern_offset` | When `target.function_table` is non-empty, refuse LCS and return null; legacy LCS (no table) forces `pattern_offset = 0` |

### Verification

```text
cmake --build builds/ninja-nucleus --config RelWithDebInfo \
  --target function_relocation_static test_nucleus_adapter test_signature_body_link -j 8
ctest --test-dir builds/ninja-nucleus -C RelWithDebInfo --output-on-failure
# 1/2 nucleus_adapter ........ Passed (getstack size=0x7a)
# 2/2 signature_body_link .... Passed (residual size cleared to 0)
```
