---
name: dst-signature-create-perf-and-parity
description: Accelerate and validate DST signature_updater create (Windows + Linux/WSL) without changing the generated DB.
---

# DST signature DB rebuild: profile, fix, verify

## When
`signature_updater create` is slow (minutes), or a mod/platform needs the signature DB regenerated and proven unchanged.

## 0. Get attribution before optimizing
- The tool already has a named logger "FunctionRelocation" created by `function_relocation::init_ctx()` (rotating file next to the **main module**, i.e. the tool exe or game bin64). Do **not** `spdlog::create` it again in main -> `spdlog_ex`, and in Debug the CRT assert dialog hangs the batch forever. Add a console sink to the existing logger instead (guard by env var).
- Per-strategy timing: `PhaseClock` RAII in `Signature.cpp` strategies (log at info only when >=100 ms). Phase timings in `DontStarveSignature.cpp` for init/nucleus/apply/scan_features/pdata.

## 1. Known hotspots (fix in this order)
1. `FunctionTable::span_containing` — old version walked from `upper_bound` back to the table head (~4e5 spans per query). Return at the first span whose `end > addr` **only when the span set is laminar** (`is_laminar()`: nested or disjoint, cached, invalidated by every mutator); otherwise run the original tightest-wins scan.
2. `FunctionTable::add` sorted-insert per span is quadratic at 4e5 spans — use `assign(vector)` (one sort). Applies to `NucleusAdapter::nucleus_analyze_file` and `apply_nucleus_function_table`.
3. `ModuleSections::find_function` linear over `std::list<Function>` — consult `address_functions` first, keep the linear fallback.
4. pdata cross-check O(spans x ranges) — sort ranges by start, build prefix max end, walk back until no earlier range reaches the span start.
5. `scan_by_short_body` needle loop scanned train+target `.text` per candidate — per module build once: 8-byte window hash (unique/multiple/absent) and 4-byte postings (sorted `(value<<32|offset)`); needle lookup = index + `memcmp`, with fallback to `MemorySignature` when the range is <4 bytes or > UINT32_MAX.
6. Build the tool **Release** (Debug `nucleus_disasm` 26.8 s vs 3.3 s).

## 2. Non-negotiable verification
- Regenerate and diff the JSON **entry by entry** (`offset`, `pattern`, `pattern_offset`). The optimization must be byte-identical; if it is not, the change altered matching semantics.
- Independent check: scan the game binary for every pattern inside `[luaModuleBase, .text end]`; require exactly one hit and `hit + pattern_offset == base + offset` for one single derived base.
- pdata cross-check numbers (`compared`, `mismatches`) must not change.

## 3. Linux end-to-end (WSL)
- Copy the repo without `builds/ .git tools/angle 3rd/angle vcpkg/{buildtrees,packages,installed}`; keep `vcpkg/downloads` to avoid re-downloading ports.
- `vcpkg/bootstrap-vcpkg.sh -disableMetrics`; `cmake --preset ninja-multi-vcpkg`; build target `signature_updater` Release.
- `cmake/GameDir.cmake` is machine-generated: write the WSL game path (Go heredoc, the apostrophe in "Don't Starve Together" breaks naive printf quoting).
- Stage `Mod/bin64/linux/lib64/{liblua51.so,lua51}` into `Mod/deps/`, back up `Mod/signatures_*.json`, then run `cmake --build <build> --config Release --target create` (the tool is LD_PRELOADed into both game binaries).
- A/B: temporarily copy the pristine files (`git show HEAD:<path>`) into the build tree, rebuild, rerun create; the JSONs must be identical. Then restore and rebuild.
- `ctest -C Release`: the only acceptable failures are the client smoke tests that need a real running client/Steam.

## Pitfalls
- `ModuleSections` `GumMemoryRange` members must be value-initialized (`{}`), otherwise `in_plt()/in_got_plt()` read stack garbage and `test_xref_pattern` aborts as soon as the struct layout changes.
- Making `ModuleSections` move-only (caches of `unique_ptr`) is fine: all uses are references/out-params, never copies.
- Don't migrate WSL-only deltas back: generated `src/missfunc.h`/`src/modinfo.hpp` (LF vs CRLF, same content), `GameLuaInjectFramework.c`, `Mod/deps/*.so`, `cmake/GameDir.cmake`, tracked `__pycache__/*.pyc` rewritten by the distro Python.
