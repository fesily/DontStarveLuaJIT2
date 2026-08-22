# Windows Function Ranges (`.pdata`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On Windows x64, build authoritative function `[start, end)` ranges from PE `.pdata` `RUNTIME_FUNCTION` entries so `Function.size` and signature snap-to-start stop relying on fragile `guess_function_size` / call-graph heuristics for pdata-covered functions.

**Architecture:** Extract pure `enumerate_function_ranges_win` (+ `find_range_containing`) into `FunctionRanges.{hpp,cpp}` with fixture unit tests (no game, no Gum). Wire `ScanCtx::pre_function` to seed `sureFunctions` and known sizes from those ranges (heuristic only fills holes). Hook signature update path to snap pattern hits to range start and rewrite `pattern_offset`. Leave `ReplaceApis` getstack/getinfo workarounds untouched.

**Tech Stack:** C++23, CMake/Ninja multi-config, Windows `RUNTIME_FUNCTION` / optional `UNWIND_INFO`, existing `ModuleSections` / `ScanCtx` / `DontStarveSignature`, assert-style CTest like `tests/plugin/test_plugin_host_graph.cpp`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-07-win-function-ranges-design.md` (approved)
- **Windows-only** authoritative path; Linux/macOS behavior unchanged this slice
- Authority = **`.pdata` `RUNTIME_FUNCTION`** (`BeginAddress`/`EndAddress`); `UNWIND_INFO` optional for chain confirm only
- Heuristic **must not overwrite** authoritative `Function.size`
- Empty/missing pdata → **warn + full legacy heuristic** (fail-soft)
- **Do not** remove `GameLua.cpp` `ReplaceApis` getstack/getinfo special cases
- Do not rewrite Karta / `fix_func_address_by_signature` core algorithm
- Public API via `FUNCTION_RELOCATION_API` when exported from the reloc library
- Unit tests must not require game install or live process modules for W1
- Commit messages English conventional; docs/comments Chinese OK in code comments if matching file style
- Build: `builds/ninja-multi-vcpkg`, config `RelWithDebInfo`

## File map

| Path | Responsibility |
|------|----------------|
| `src/FunctionRelocation/FunctionRanges.hpp` | `FuncRange`, enumerate/find API |
| `src/FunctionRelocation/FunctionRanges.cpp` | Win `.pdata` parse + chain merge; non-Win stubs |
| `src/FunctionRelocation/CMakeLists.txt` | Add sources to SHARED + STATIC targets |
| `src/FunctionRelocation/ScanCtx.cpp` | Consume ranges in `pre_function` / size limits |
| `src/FunctionRelocation/ScanCtx.hpp` | Optional: store `authoritative_sizes` map if needed |
| `src/FunctionRelocation/ModuleSections.hpp` | Optional: `find_range` helper on module if snap lives here |
| `src/DontStarveInjector/plugins/plugin_core_vm/signature_load/DontStarveSignature.cpp` | Snap target to range start after pattern/fix |
| `tests/function_relocation/test_function_ranges.cpp` | Fixture unit tests |
| `tests/CMakeLists.txt` | Wire `function_ranges` CTest |
| Spec status note (Task 4) | Mark Implemented / residual follow-ups |

---

### Task 1: `FuncRange` API + Windows enumerator + unit tests

**Files:**
- Create: `src/FunctionRelocation/FunctionRanges.hpp`
- Create: `src/FunctionRelocation/FunctionRanges.cpp`
- Modify: `src/FunctionRelocation/CMakeLists.txt` (add `FunctionRanges.cpp` to `SOURCE`)
- Create: `tests/function_relocation/test_function_ranges.cpp`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- Produces:
  ```cpp
  namespace function_relocation {
    struct FuncRange {
      uintptr_t start = 0; // VA
      uintptr_t end = 0;   // VA; PE EndAddress as absolute (exclusive end of range for in_range checks: start <= addr < end)
      enum class Source : uint8_t { Pdata, HeuristicFallback };
      Source source = Source::Pdata;
    };

    // Windows: parse m.pdata as RUNTIME_FUNCTION table.
    // Non-Windows: returns false, leaves out empty.
    // Returns false if pdata empty / no valid entries; true if out non-empty.
    FUNCTION_RELOCATION_API bool enumerate_function_ranges_win(
        const ModuleSections& m, std::vector<FuncRange>& out);

    // Binary search / linear scan: first range with start <= addr < end.
    // Returns nullptr if none.
    FUNCTION_RELOCATION_API const FuncRange* find_range_containing(
        const std::vector<FuncRange>& ranges, uintptr_t addr);
  }
  ```
- Consumes: `ModuleSections::{details.range.base_address, pdata, text, in_text}`

- [ ] **Step 1: Write failing unit tests (fixture buffer, no PE file)**

Create `tests/function_relocation/test_function_ranges.cpp`:

```cpp
#include "FunctionRanges.hpp"
#include "ModuleSections.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cstdio>

using function_relocation::FuncRange;
using function_relocation::ModuleSections;
using function_relocation::enumerate_function_ranges_win;
using function_relocation::find_range_containing;

// Minimal RUNTIME_FUNCTION: Begin, End, UnwindInfo RVA (unused in v1 merge-by-adjacent).
#pragma pack(push, 1)
struct RtFn {
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t UnwindData;
};
#pragma pack(pop)
static_assert(sizeof(RtFn) == 12);

static ModuleSections make_module(uintptr_t image_base, uintptr_t text_rva, size_t text_size,
                                  const RtFn* table, size_t count) {
    ModuleSections m{};
    m.details.range.base_address = image_base;
    m.details.range.size = text_rva + text_size + 0x1000;
    m.text.base_address = image_base + text_rva;
    m.text.size = text_size;
    m.pdata.base_address = reinterpret_cast<uintptr_t>(table);
    m.pdata.size = count * sizeof(RtFn);
    return m;
}

static void test_two_independent() {
    // image_base 0x140000000; text at rva 0x1000 size 0x5000
    const uintptr_t base = 0x140000000ull;
    RtFn table[] = {
        {0x1000, 0x1100, 0},
        {0x1200, 0x1300, 0},
        {0, 0, 0}, // terminator
    };
    auto m = make_module(base, 0x1000, 0x5000, table, 3);
    std::vector<FuncRange> out;
    assert(enumerate_function_ranges_win(m, out));
    assert(out.size() == 2);
    assert(out[0].start == base + 0x1000);
    assert(out[0].end == base + 0x1100);
    assert(out[1].start == base + 0x1200);
    assert(out[1].end == base + 0x1300);
}

static void test_chain_merge() {
    const uintptr_t base = 0x140000000ull;
    // r1.End == r2.Begin → one logical function
    RtFn table[] = {
        {0x2000, 0x2100, 0},
        {0x2100, 0x2200, 0},
        {0, 0, 0},
    };
    auto m = make_module(base, 0x1000, 0x5000, table, 3);
    std::vector<FuncRange> out;
    assert(enumerate_function_ranges_win(m, out));
    assert(out.size() == 1);
    assert(out[0].start == base + 0x2000);
    assert(out[0].end == base + 0x2200);
}

static void test_terminator() {
    const uintptr_t base = 0x140000000ull;
    RtFn table[] = {
        {0x1000, 0x1080, 0},
        {0, 0, 0},
        {0x3000, 0x3100, 0}, // must not be read
    };
    auto m = make_module(base, 0x1000, 0x5000, table, 3);
    std::vector<FuncRange> out;
    assert(enumerate_function_ranges_win(m, out));
    assert(out.size() == 1);
    assert(out[0].start == base + 0x1000);
}

static void test_empty_pdata() {
    ModuleSections m{};
    m.details.range.base_address = 0x140000000ull;
    m.details.range.size = 0x10000;
    m.text.base_address = 0x140001000ull;
    m.text.size = 0x1000;
    m.pdata = {0, 0};
    std::vector<FuncRange> out;
    assert(!enumerate_function_ranges_win(m, out));
    assert(out.empty());
}

static void test_find_containing() {
    std::vector<FuncRange> ranges = {
        {0x1000, 0x1100, FuncRange::Source::Pdata},
        {0x2000, 0x2200, FuncRange::Source::Pdata},
    };
    assert(find_range_containing(ranges, 0x1000)->start == 0x1000);
    assert(find_range_containing(ranges, 0x10FF)->start == 0x1000);
    assert(find_range_containing(ranges, 0x2100)->start == 0x2000);
    assert(find_range_containing(ranges, 0x1100) == nullptr);
    assert(find_range_containing(ranges, 0x50) == nullptr);
}

int main() {
    test_two_independent();
    test_chain_merge();
    test_terminator();
    test_empty_pdata();
    test_find_containing();
    std::puts("function_ranges: all passed");
    return 0;
}
```

- [ ] **Step 2: Wire CMake for the test (link static reloc on Windows tools path)**

In `tests/CMakeLists.txt` add (Windows only is fine for this API's real path, but compile stubs everywhere if sources are unconditional):

```cmake
if (WIN32)
  add_executable(test_function_ranges
      ${CMAKE_CURRENT_SOURCE_DIR}/function_relocation/test_function_ranges.cpp)
  target_include_directories(test_function_ranges PRIVATE
      ${FUNCTION_RELOCATION_INCLUDE_DIR})
  target_compile_features(test_function_ranges PRIVATE cxx_std_23)
  # Prefer static so the test does not delay-load Injector for gum.
  target_link_libraries(test_function_ranges PRIVATE function_relocation_static)
  # FunctionRanges.cpp must not require gum for the pure pdata path.
  # If static still pulls frida-gum via other TUs, that is OK for tools/tests.
  add_test(NAME function_ranges COMMAND test_function_ranges)
endif()
```

Also add `FunctionRanges.cpp` to `SOURCE` in `src/FunctionRelocation/CMakeLists.txt`:

```cmake
set(SOURCE
        Signature.cpp
        ModuleSections.cpp
        MemorySignature.cpp
        KartaConfig.cpp
        ctx.cpp
        disasm.h
        ScanCtx.cpp
        ExectuableSignature.cpp
        FunctionRanges.cpp
)
```

- [ ] **Step 3: Implement minimal `FunctionRanges.hpp` / `.cpp`**

`FunctionRanges.hpp`:

```cpp
#pragma once
#include "ModuleSections.hpp"
#include "export.hpp"
#include <cstdint>
#include <vector>

namespace function_relocation {
struct FuncRange {
    uintptr_t start = 0;
    uintptr_t end = 0;
    enum class Source : uint8_t { Pdata, HeuristicFallback };
    Source source = Source::Pdata;
};

FUNCTION_RELOCATION_API bool enumerate_function_ranges_win(
    const ModuleSections& m, std::vector<FuncRange>& out);

FUNCTION_RELOCATION_API const FuncRange* find_range_containing(
    const std::vector<FuncRange>& ranges, uintptr_t addr);
} // namespace function_relocation
```

`FunctionRanges.cpp` (core logic):

```cpp
#include "FunctionRanges.hpp"
#include <algorithm>
#include <spdlog/spdlog.h>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace function_relocation {

const FuncRange* find_range_containing(const std::vector<FuncRange>& ranges, uintptr_t addr) {
    for (const auto& r : ranges) {
        if (r.start <= addr && addr < r.end)
            return &r;
    }
    return nullptr;
}

bool enumerate_function_ranges_win(const ModuleSections& m, std::vector<FuncRange>& out) {
    out.clear();
#ifndef _WIN32
    (void)m;
    return false;
#else
    if (m.pdata.base_address == 0 || m.pdata.size < sizeof(RUNTIME_FUNCTION))
        return false;

    const auto image_base = m.details.range.base_address;
    auto* ptr = reinterpret_cast<const uint8_t*>(m.pdata.base_address);
    const auto* end = ptr + m.pdata.size;

    uintptr_t logical_begin = 0;
    uintptr_t logical_end = 0;
    bool open = false;

    auto flush = [&]() {
        if (!open) return;
        FuncRange r{};
        r.start = logical_begin;
        r.end = logical_end;
        r.source = FuncRange::Source::Pdata;
        out.push_back(r);
        open = false;
    };

    for (; ptr + sizeof(RUNTIME_FUNCTION) <= end; ptr += sizeof(RUNTIME_FUNCTION)) {
        const auto* rf = reinterpret_cast<const RUNTIME_FUNCTION*>(ptr);
        if (rf->BeginAddress == 0)
            break;

        const uintptr_t b = image_base + rf->BeginAddress;
        const uintptr_t e = image_base + rf->EndAddress;

        // Skip entries that do not land in text (best-effort).
        if (!m.in_text(b) || e < b) {
            continue;
        }

        if (open && b == logical_end) {
            // Adjacent chain: extend end.
            logical_end = e;
            continue;
        }

        flush();
        logical_begin = b;
        logical_end = e;
        open = true;
    }
    flush();

    std::sort(out.begin(), out.end(),
              [](const FuncRange& a, const FuncRange& b) { return a.start < b.start; });
    // Dedupe same start: keep longer end.
    std::vector<FuncRange> dedup;
    for (const auto& r : out) {
        if (!dedup.empty() && dedup.back().start == r.start) {
            dedup.back().end = std::max(dedup.back().end, r.end);
        } else {
            dedup.push_back(r);
        }
    }
    out.swap(dedup);
    return !out.empty();
#endif
}

} // namespace function_relocation
```

Notes for implementer:
- Use `RUNTIME_FUNCTION` from `<windows.h>` / `<winnt.h>` on MSVC.
- Do **not** call Gum inside this file for the pure path.
- v1 chain rule: **adjacent `End == next.Begin` only** (spec §3.2).

- [ ] **Step 4: Build and run tests**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_function_ranges -j 8
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R function_ranges --output-on-failure
```

Expected: `function_ranges` PASS; stdout contains `function_ranges: all passed`.

- [ ] **Step 5: Commit**

```bash
git add src/FunctionRelocation/FunctionRanges.hpp src/FunctionRelocation/FunctionRanges.cpp src/FunctionRelocation/CMakeLists.txt tests/function_relocation/test_function_ranges.cpp tests/CMakeLists.txt
git commit -m "feat(reloc): Windows .pdata function range enumerator + unit tests"
```

---

### Task 2: Seed `ScanCtx::pre_function` with authoritative ranges

**Files:**
- Modify: `src/FunctionRelocation/ScanCtx.cpp` (`scan_pre_text_range` pdata loop + `pre_function` + size usage)
- Modify: `src/FunctionRelocation/ScanCtx.hpp` if adding `std::unordered_map<uintptr_t, size_t> authoritative_sizes`
- Modify: `src/FunctionRelocation/ModuleSections.cpp` only if `init_module_signature` needs to pass ranges through (prefer keep inside ScanCtx)

**Interfaces:**
- Consumes: `enumerate_function_ranges_win`, `FuncRange`
- Produces: For each pdata range, `sureFunctions[start] >= kPdataWeight` and known size `end-start` used as `function_limit` instead of `guess_function_size` when available

- [ ] **Step 1: Add `authoritative_sizes` to `ScanCtx`**

In `ScanCtx.hpp`:

```cpp
std::unordered_map<uintptr_t, size_t> authoritative_sizes; // start -> size from pdata
```

- [ ] **Step 2: Replace inline pdata seed in `scan_pre_text_range` with enumerator**

In `ScanCtx.cpp` `#ifdef _WIN32` block (~lines 322–339), **remove** the hand-rolled 12-byte loop that only inserts `sureFunctions[blockBeing]=0`.

Replace with:

```cpp
#ifdef _WIN32
{
    std::vector<FuncRange> ranges;
    if (enumerate_function_ranges_win(ctx.m, ranges)) {
        constexpr size_t kPdataWeight = 2;
        for (const auto& r : ranges) {
            if (r.end <= r.start) continue;
            ctx.sureFunctions[r.start] = std::max(ctx.sureFunctions[r.start], kPdataWeight);
            ctx.authoritative_sizes[r.start] = static_cast<size_t>(r.end - r.start);
        }
    } else {
        // keep silent here; pre_function can log once if map empty after all seeds
    }
}
#else
// existing eh_frame path unchanged
#endif
```

Include `"FunctionRanges.hpp"` at top of `ScanCtx.cpp`.

Keep the existing `E8/E9` text scan **before or after** pdata seed (order: text call scan can stay first; pdata must still run). Prefer:

1. text E8/E9 scan (existing)
2. pdata / eh_frame seed (modified)
3. return maybeFunctions

- [ ] **Step 3: Prefer authoritative size over `guess_function_size`**

In `pre_function`, where `function_sizes[near_address] = guess_function_size(near_address)` (~line 513–516):

```cpp
if (!function_sizes.contains(near_address)) {
    if (auto it = authoritative_sizes.find(near_address); it != authoritative_sizes.end()) {
        function_sizes[near_address] = it->second;
    } else {
        function_sizes[near_address] = guess_function_size(near_address);
    }
}
```

In `scan()` when computing `function_limit` (~line 542):

```cpp
const auto address = functions[i];
if (authoritative_sizes.contains(address)) {
    function_limit = address + authoritative_sizes[address];
} else {
    function_limit = known_functions.contains(address) && known_functions.at(address).size != 0
        ? known_functions[address].size + address
        : (i + 1 == functions.size() ? 1 : functions[i + 1]);
}
```

When creating `Function` records later in `scan_function` / `function_end`, if `authoritative_sizes` has the start, ensure final `Function.size` matches (read `scan_function` and set size from authoritative when present — do not let disasm shorten below / invent beyond without reason; prefer **exact** pdata size).

If `scan_function` derives size only from next boundary, setting `function_limit` as above is enough for v1.

- [ ] **Step 4: Heuristic hole-only policy for maybeFuncs**

When promoting `maybeFuncs` into `sureFunctions`, **skip** candidates that already lie inside an authoritative range:

```cpp
bool inside_auth = false;
for (const auto& [start, size] : authoritative_sizes) {
    if (addr >= start && addr < start + size) { inside_auth = true; break; }
}
if (inside_auth) continue;
```

(Or build a sorted range vector once and use `find_range_containing`.)

- [ ] **Step 5: Log fallback once**

At end of Windows pdata seeding in `pre_function` (after `scan_pre_text_range`):

```cpp
if (authoritative_sizes.empty()) {
    spdlog::warn("function_ranges: fallback heuristic (no pdata ranges)");
} else {
    spdlog::info("function_ranges: {} authoritative pdata ranges", authoritative_sizes.size());
}
```

Use existing logger name if `ScanCtx` already uses a named logger; otherwise `spdlog::info/warn` is fine.

- [ ] **Step 6: Build library + unit tests**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target function_relocation function_relocation_static test_function_ranges -j 8
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R function_ranges --output-on-failure
```

Expected: both targets build; unit tests still PASS.

- [ ] **Step 7: Commit**

```bash
git add src/FunctionRelocation/ScanCtx.hpp src/FunctionRelocation/ScanCtx.cpp
git commit -m "feat(reloc): seed ScanCtx function bounds from Windows .pdata ranges"
```

---

### Task 3: Signature update snap-to-range-start

**Files:**
- Modify: `src/DontStarveInjector/plugins/plugin_core_vm/signature_load/DontStarveSignature.cpp` (loop that sets `target` / `pattern_offset`, ~238–297)
- Possibly export a thin helper on `ModuleSections` if ranges are not retained after scan — **prefer re-enumerate** from `moduleMain` at update time (pdata still mapped)

**Interfaces:**
- Consumes: `enumerate_function_ranges_win(moduleMain, ranges)`, `find_range_containing(ranges, hit)`
- Produces: When hit is inside a range, `target = range->start` and `signature.pattern_offset` recalculated from the pattern match address

- [ ] **Step 1: After a non-zero `target` is chosen, snap**

In `create_or_update` / update loop after `target` is resolved and before `new_offset` assignment (after the block that may refix via `find_function`, ~294):

```cpp
#ifdef _WIN32
{
    static thread_local std::vector<function_relocation::FuncRange> cached_ranges;
    static thread_local const function_relocation::ModuleSections* cached_mod = nullptr;
    if (cached_mod != &moduleMain) {
        cached_ranges.clear();
        (void)function_relocation::enumerate_function_ranges_win(moduleMain, cached_ranges);
        cached_mod = &moduleMain;
    }
    if (const auto* range = function_relocation::find_range_containing(cached_ranges, target)) {
        if (target != range->start) {
            // pattern may have matched mid-function or a stub still inside the range
            const auto pattern_address = target - signature.pattern_offset;
            const auto new_po = static_cast<intptr_t>(range->start) - static_cast<intptr_t>(pattern_address);
            spdlog::info("snap signature [{}] {} -> range start {} (pattern_offset {}->{})",
                         name, (void*)target, (void*)range->start,
                         signature.pattern_offset, new_po);
            signature.pattern_offset = new_po;
            target = range->start;
        }
    }
}
#endif
```

Include `FunctionRanges.hpp` in `DontStarveSignature.cpp`.

**Edge case:** If pattern hit is **outside** the true function range (wrong scan), snap must not invent — `find_range_containing` returns null → leave as today.

**Stub case:** If stub is a **separate** pdata entry (start=stub), snap keeps stub start; ReplaceApis workaround still needed until signatures regenerate against correct body. That is expected; do not add +0x20 here.

- [ ] **Step 2: Build `plugin_core_vm` / `ds_signature`**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target plugin_core_vm -j 8
```

Expected: link success.

- [ ] **Step 3: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_core_vm/signature_load/DontStarveSignature.cpp
git commit -m "feat(signature): snap Windows pattern hits to .pdata range start"
```

---

### Task 4: Docs + residual checklist (no ReplaceApis cleanup)

**Files:**
- Modify: `docs/superpowers/specs/2026-08-07-win-function-ranges-design.md` status → Implemented
- Optional short note in `docs/plugin-system.md` only if signature regeneration is operator-visible; otherwise spec footer is enough

- [ ] **Step 1: Update spec status**

At top of design doc:

```markdown
**Status:** Implemented (Win-first enumerator + ScanCtx seed + signature snap)
```

Add residual section if missing:

```markdown
## Residual (not this slice)
- Linux eh_frame size / macOS LC_FUNCTION_STARTS
- Delete GameLua ReplaceApis getstack/getinfo workarounds after regenerating signatures_client.json and smoke
- Optional UNW_FLAG_CHAININFO confirmation beyond adjacent End==Begin
```

- [ ] **Step 2: Run unit gate once more**

```bash
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R function_ranges --output-on-failure
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-08-07-win-function-ranges-design.md
git commit -m "docs(spec): mark win function ranges design implemented"
```

---

## Plan self-review

| Spec item | Task |
|-----------|------|
| `enumerate_function_ranges_win` + chain merge | Task 1 |
| Fixture unit tests (2 indep, chain, terminator, empty, find) | Task 1 |
| `pre_function` authoritative size; guess no overwrite | Task 2 |
| Heuristic hole-only | Task 2 |
| Fallback warn | Task 2 |
| Signature snap-to-start | Task 3 |
| ReplaceApis specials retained | Explicit non-goal all tasks |
| Linux/mac unchanged | `#ifdef _WIN32` only |
| Docs Implemented | Task 4 |

| Check | Result |
|-------|--------|
| Placeholders | None intentional |
| Type names | `FuncRange`, `enumerate_function_ranges_win`, `find_range_containing`, `authoritative_sizes` consistent |
| TDD | Task 1 tests first; Task 2–3 reuse Task 1 API |

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-07-win-function-ranges.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?
