# Task 4 Report: signature_updater regen + critical-symbol verify

**Branch:** `feature/nucleus-function-body`  
**Worktree:** `C:/Users/fesil/DontStarveLuaJIT2/.worktrees/nucleus-function-body`  
**Base:** Task 3 at `ea0d97d`  
**Date:** 2026-08-07  

## Summary

Wired optional pdata cross-check logging into `update_signatures` (Nucleus remains sole body authority). Fixed nested-span lookup in `FunctionTable::span_containing` so exports nested inside a larger Nucleus span (e.g. `lua_resume` inside `lua_yield`) get a non-zero body size. Built `signature_updater` against worktree sources via `builds/ninja-nucleus`, regenerated client/server signatures for game version `740477`, and verified **lua_getstack** entry is the body prologue `4c 8b 49 28…` (not stub `0f b6 41 64 c3`).

## Acceptance

| Criterion | Status |
|-----------|--------|
| Update path uses Nucleus tables (Task 3) | PASS (already in `DontStarveSignature.cpp`; re-verified at runtime) |
| Optional pdata cross-check log only | PASS (`enumerate_function_ranges_win` compare ends; warn only) |
| Rebuild `signature_updater` (worktree) | PASS (`builds/ninja-nucleus` RelWithDebInfo) |
| Regen `signatures_client.json` / `signatures_server.json` | PASS (version 740477, 102 funcs) |
| getstack body entry `4c 8b 49 28…` | **PASS** |
| getinfo has `80 3a 3e` nearby | PASS |
| luaopen_io prologue `48 89 5c 24 08…` | PASS |
| Copy into `Mod/deps` | PASS |
| Report + commit | PASS (this file) |

## Changes

### `DontStarveSignature.cpp`

After `apply_nucleus_function_table` for lua51 + game:

- Windows: `enumerate_function_ranges_win(moduleMain, pdata_ranges)`
- For each Nucleus span with a unique overlapping pdata range, compare ends
- `spdlog::warn` when `|delta| >= 0x20`
- Summary: `pdata cross-check: compared=… mismatches=… (Nucleus not overridden)`
- Does **not** override Nucleus ends/sizes

### `FunctionTable.hpp` (nested containing)

Root cause of updater abort:

- Nucleus emits a large outer span for `lua_yield` `[0x18000ad60, 0x18000b5ae)` that **wholly contains** `lua_resume` export `@0x18000b4f0`
- Old `span_containing` only checked the rightmost `start <= addr` span; intermediate sibling starts (e.g. `0x18000ae30`) that do **not** contain the address made lookup return null → `func[lua_resume] has size 0`

Fix:

- Walk all spans with `start <= addr` and pick the **tightest** container (smallest `end-start`; ties keep rightmost start)
- Nested unit test + `lua_resume` live check in `test_nucleus_adapter`

### Smoke build (`builds/nucleus-only`, gitignored)

Extended Task 1–3 smoke CMake to link full `signature_updater` + `ds_signature` against worktree sources with:

- `GAMEDIR` = Steam DST install
- `LUA51_PATH` = worktree `Mod/deps/lua51.dll`
- `WORKER_DIR` = worktree `Mod`

(Full product multi-vcpkg tree not reconfigured; smoke tree is sufficient for regen.)

## Build & run evidence

```text
ninja -C builds/ninja-nucleus -f build-RelWithDebInfo.ninja \
  test_nucleus_adapter probe_exports signature_updater -j 8
# link OK

test_nucleus_adapter.exe
# lua_getstack: va=0x1800090f0 entry=0x1800090f0 end=0x18000916a size=0x7a functions=887
# lua_resume: va=0x18000b4f0 entry=0x18000ad60 end=0x18000b5ae size=0x84e
# test_nucleus_adapter: ok

# From Mod/deps with PATH including lua51.dll:
builds/ninja-nucleus/RelWithDebInfo/signature_updater.exe
# rc=0 ~19s
# pdata cross-check: compared=13701 mismatches=2401 (Nucleus not overridden)  # client PE
# pdata cross-check: compared=14765 mismatches=2582 (Nucleus not overridden)  # server PE
# update signatures to file:[.../Mod/signatures_client.json], version: 740477
# (server similarly)
```

Outputs written under `Mod/` (cwd absolute path; tool not mapping Injector/plugin deps dir). Copied to `Mod/deps/`.

## Critical symbol verification (client PE)

Game:  
`C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together/bin64/dontstarve_steam_x64.exe`  
Version: `740477`

Lua module base recovered via `luaModuleSignature` pattern (`41 B8 EE D8 FF FF…`, po `-0x37`) → RVA `0x4e8d1f`.

| Symbol | offset | pattern_offset | entry RVA | entry first bytes | Gate |
|--------|--------|----------------|-----------|-------------------|------|
| lua_getstack | 12624 (0x3150) | -61 | 0x4ebe6f | **`4c 8b 49 28`** 4c 8b d9 85… | BODY |
| lua_getinfo | 16816 (0x41b0) | -11 | 0x4ececf | `48 89 5c 24 08 48 89 6c…` | has `80 3a 3e` in first 0x200 |
| luaopen_io | 110176 (0x1ae60) | -8 | 0x503b7f | **`48 89 5c 24 08`** 48 89 74… | PASS |

Pre-Task-4 client getstack (for contrast):

- offset 12752, pattern_offset -175
- entry bytes at old offset: `48 89 5c 24 08…` (different function / not body gate)

Stub signature `0f b6 41 64 c3` appears once in the PE but is **not** the regenerated getstack entry.

Pattern uniqueness on PE (raw search):

- getstack pattern: 1 hit → unique entry `0x4ebe6f` with body bytes
- luaopen_io pattern: 1 hit → unique entry with prologue

## Nested resume note

`lua_resume` and `lua_yield` currently share the same resolved entry offset (`26480`) because Nucleus’s tightest container for the resume export is the large outer yield span (no dedicated resume span in the 887-function table). That is a Nucleus CFG granularity issue, **not** a silent heuristic override:

- Updater no longer aborts on size 0
- Target resolve still uses `function_table.containing`
- Optional later slice: improve Nucleus entry discovery for nested exports (out of Task 4 gate)

## Files touched

- Modify: `src/DontStarveInjector/plugins/plugin_core_vm/signature_load/DontStarveSignature.cpp`
- Modify: `src/FunctionRelocation/FunctionTable.hpp`
- Modify: `tests/function_relocation/test_nucleus_adapter.cpp`
- Create: `.superpowers/sdd/task-4-report.md`
- Regen (tracked if not ignored): `Mod/signatures_*.json`, `Mod/deps/signatures_*.json`
- Local only (gitignored smoke): `builds/nucleus-only/*`, `builds/ninja-nucleus/*`

## Commit

```text
fix(signature): nested FunctionTable containing; pdata log; regen JSON
```
