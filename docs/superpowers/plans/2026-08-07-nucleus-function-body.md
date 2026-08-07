# Nucleus Function Body Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make VUSec Nucleus (vendored, engineering-surface patches only) the sole authority for function start/end/body used by signature generation and target-side match→entry resolve—so patterns stay inside real bodies and `pattern_offset` is never training-module geometry.

**Architecture:** Vendor Nucleus under `3rd/nucleus` at a pinned revision. Build `nucleus_static` via CMake; on Windows fill Nucleus `Binary`/`Section` from PE mapping (pe-parse / existing section walk)—do **not** rewrite `cfg.cc` function-finding. Expose `FunctionTable` + `NucleusAdapter::analyze`. Signature path consumes only table bodies for pattern bytes and only target-table `containing()` for entry resolve. Optional pdata cross-check logs only.

**Tech Stack:** C++23, CMake/Ninja multi-config, vendored Nucleus (BSD-3), Capstone (coordinate with Frida Gum), pe-parse (Windows PE fill), existing `FunctionRelocation` / `ds_signature` / `signature_updater`, assert-style CTest.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-07-function-body-cfg-design.md` (**Approved**)
- **Algorithm ownership:** Nucleus CFG / function partition (`make_cfg`, `find_functions`, expand, …)—do not replace with a parallel in-house finder
- **Product form:** vendor in-tree (`3rd/nucleus` fixed revision), **not** black-box package dependency
- **Engineering surface only:** loader, CMake, export API, Capstone coexistence, recorded patches under `3rd/nucleus/patches/`
- **Forbidden as authority:** next-export size, first-ret body end, magic distances (`0x20`/`0x1000`), per-symbol hardcoding (`lua_getstack`), training `pattern_offset` as cross-module retreat
- **Signature:** pattern ⊆ Nucleus body; target match → target `containing` → target-local `pattern_offset`
- **pdata:** cross-check / warn only; Nucleus wins on conflict
- **No silent heuristic fallback** when Nucleus analysis fails (errors must be visible)
- **Do not** remove `GameLua` `ReplaceApis` getstack/getinfo workarounds in this plan (optional later slice after green regen)
- Build: `builds/ninja-multi-vcpkg`, `RelWithDebInfo`
- Commits: English conventional; Chinese OK in design comments

## File map

| Path | Responsibility |
|------|----------------|
| `3rd/nucleus/` | Vendored upstream + LICENSE; engineering patches |
| `3rd/nucleus/patches/` | Documented engineering/bugfix patches |
| `cmake/Nucleus.cmake` or `3rd/nucleus/CMakeLists.txt` | `nucleus_static` target |
| `src/FunctionRelocation/FunctionTable.hpp` | Portable span table + `containing` |
| `src/FunctionRelocation/NucleusAdapter.hpp/.cpp` | Run Nucleus → `FunctionTable` |
| `src/FunctionRelocation/Signature.cpp` | Pattern ⊆ body; target resolve only |
| `src/FunctionRelocation/ScanCtx.cpp` / `ModuleSections.*` | Stop using next-export / pure heuristic as body authority where Nucleus table is available |
| `src/FunctionRelocation/CMakeLists.txt` | Link `nucleus_static` |
| `tests/function_relocation/test_nucleus_adapter.cpp` | lua51.dll getstack span / containing |
| `tests/CMakeLists.txt` | Wire tests |
| Spec status | Implemented when N4 done |

### Shared interfaces (all later tasks)

```cpp
// FunctionTable.hpp — produced by Task 2
namespace function_relocation {
struct FunctionSpan {
  uint64_t start = 0;  // entry / function start VA
  uint64_t end = 0;    // exclusive end VA (Nucleus Function::end semantics as mapped)
};

class FunctionTable {
public:
  void clear();
  void add(FunctionSpan span);           // keep sorted by start; merge policy: no overlap preferred
  // Returns start of function containing addr, or 0 if none.
  uint64_t containing(uint64_t addr) const;
  const FunctionSpan *span_containing(uint64_t addr) const;
  const std::vector<FunctionSpan> &spans() const;
  bool empty() const;
private:
  std::vector<FunctionSpan> spans_; // sorted by start
};

// NucleusAdapter.hpp
struct NucleusAnalyzeOptions {
  // When true, log pdata mismatches if caller also passes pdata spans (optional).
  bool log_pdata_crosscheck = false;
};

// Analyze a PE/ELF file on disk. On failure returns error string; table cleared.
FUNCTION_RELOCATION_API
std::expected<FunctionTable, std::string>
nucleus_analyze_file(const std::filesystem::path &path,
                     const NucleusAnalyzeOptions &opt = {});
}
```

Map Nucleus `Function::start`/`end` → `FunctionSpan` (document whether `end` is exclusive; normalize once in adapter so `start <= addr < end`).

---

### Task 1: Vendor Nucleus + `nucleus_static` (engineering surface)

**Files:**
- Create: `3rd/nucleus/` (vendor tree from pinned upstream)
- Create: `3rd/nucleus/CMakeLists.txt` (or `cmake/Nucleus.cmake` included from root)
- Create: `3rd/nucleus/VENDOR.md` (revision URL, date, LICENSE note, engineering-surface policy)
- Create: `3rd/nucleus/patches/README.md` (how to apply patches)
- Modify: root/`src/FunctionRelocation/CMakeLists.txt` or top-level CMake to `add_subdirectory` nucleus
- Modify as needed: Nucleus `loader.cc` / `loader.h` **engineering only** for Windows PE fill without libbfd

**Interfaces:**
- Produces: CMake target `nucleus_static` that compiles Nucleus CFG stack and exposes headers for Adapter
- Consumes: Capstone (system/vcpkg or Frida-compatible); on Windows **no hard requirement on libbfd** if PE fill path is used

- [ ] **Step 1: Pin and vendor source**

```bash
# From repo root — pin a specific commit of a Nucleus mirror (wilvk or bitbucket vusec).
# Record the commit SHA in 3rd/nucleus/VENDOR.md.
# Preferred: git submodule OR copy snapshot + LICENSE.
# Example submodule (adjust URL/SHA after verifying clone works):
# git submodule add https://github.com/wilvk/nucleus.git 3rd/nucleus
# cd 3rd/nucleus && git checkout <PINNED_SHA>
```

`3rd/nucleus/VENDOR.md` must contain:

```markdown
# Nucleus vendor

- Upstream: https://bitbucket.org/vusec/nucleus (mirror used: …)
- Pinned revision: <full sha>
- License: BSD-3-Clause (see LICENSE)
- Policy: algorithm surface (cfg/function finding) not rewritten;
  engineering surface (loader/cmake/export) may be patched; patches in patches/
```

- [ ] **Step 2: CMake library (no CLI required for our link)**

Create `3rd/nucleus/CMakeLists.txt` that:

1. Lists Nucleus sources needed for CFG (exclude or optional `nucleus.cc` CLI if it pulls options hard).
2. Defines `add_library(nucleus_static STATIC …)`.
3. `target_include_directories(nucleus_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})`.
4. Links Capstone:
   - Prefer existing project Capstone if already available; else `find_package` / vcpkg.
5. On **non-Windows**, may link `bfd` if keeping stock loader.
6. On **Windows**, define `NUCLEUS_LOADER_PE_PARSE=1` (or similar) and **do not** require libbfd for the default path.
7. `target_compile_features(nucleus_static PUBLIC cxx_std_17)` minimum (Nucleus is C++11-era; OK under C++23 consumer).
8. Suppress noisy warnings as needed without `-Wno-error` hiding real breaks.

Wire from `src/FunctionRelocation/CMakeLists.txt`:

```cmake
add_subdirectory(${CMAKE_SOURCE_DIR}/3rd/nucleus ${CMAKE_BINARY_DIR}/3rd/nucleus)
# after nucleus_static exists:
# target_link_libraries(function_relocation_static PUBLIC nucleus_static)  # or PRIVATE + include
# same for SHARED function_relocation on Windows
```

Use **PRIVATE** link if headers are only used in Adapter TU; **PUBLIC** include only for Adapter headers that don’t leak Nucleus types (prefer **not** leaking Nucleus types outside Adapter).

- [ ] **Step 3: Windows PE loader fill (engineering surface)**

Implement a path that constructs Nucleus `Binary` without BFD:

1. Open file bytes.
2. Parse PE (reuse **pe-parse** already in FunctionRelocation, or minimal section walk).
3. Fill:
   - `binary.filename`, `type = BIN_TYPE_PE`, `arch = ARCH_X86`, `bits = 64` (DST paths are x64)
   - For each executable section: `Section` with `vma`, `size`, `bytes` pointer into a **stable buffer owned by adapter** (must outlive `make_cfg`)
   - Symbols: optional; if PE exports available, fill `Symbol` with `SYM_TYPE_FUNC` for exports (helps naming later, not required for partition)
4. Keep stock Linux BFD path behind `#ifndef _WIN32` or `#ifndef NUCLEUS_LOADER_PE_PARSE`.

**Do not** change `CFG::make_cfg` logic in this task beyond what is required to compile.

- [ ] **Step 4: Build smoke**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target nucleus_static -j 8
```

Expected: link succeeds.

- [ ] **Step 5: Commit**

```bash
git add 3rd/nucleus cmake src/FunctionRelocation/CMakeLists.txt CMakeLists.txt
git commit -m "build(nucleus): vendor Nucleus and add nucleus_static CMake target"
```

---

### Task 2: `FunctionTable` + `NucleusAdapter` + lua51 regression test

**Files:**
- Create: `src/FunctionRelocation/FunctionTable.hpp` (header-only OK if small)
- Create: `src/FunctionRelocation/FunctionTable.cpp` if non-header
- Create: `src/FunctionRelocation/NucleusAdapter.hpp`
- Create: `src/FunctionRelocation/NucleusAdapter.cpp`
- Modify: `src/FunctionRelocation/CMakeLists.txt` — add sources; link `nucleus_static` to static/shared reloc targets as appropriate
- Create: `tests/function_relocation/test_nucleus_adapter.cpp`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- Consumes: `nucleus_static`, PE file path
- Produces: `nucleus_analyze_file` → `FunctionTable` with `containing`

- [ ] **Step 1: Write failing tests first**

`tests/function_relocation/test_nucleus_adapter.cpp`:

```cpp
#include "NucleusAdapter.hpp"
#include "FunctionTable.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#endif

using function_relocation::FunctionTable;
using function_relocation::nucleus_analyze_file;

static std::filesystem::path repo_lua51() {
  // Prefer Mod/deps/lua51.dll relative to cwd or executable.
  std::filesystem::path p = "Mod/deps/lua51.dll";
  if (std::filesystem::exists(p)) return p;
  p = std::filesystem::path{".."} / "Mod" / "deps" / "lua51.dll";
  return p;
}

// Minimal PE export RVA lookup for "lua_getstack" (or skip if helper exists).
static uint32_t pe_export_rva(const std::filesystem::path &path, const char *name);

static void test_table_containing_unit() {
  FunctionTable t;
  t.add({0x1000, 0x1100});
  t.add({0x2000, 0x2200});
  assert(t.containing(0x1000) == 0x1000);
  assert(t.containing(0x10ff) == 0x1000);
  assert(t.containing(0x1100) == 0);
  assert(t.containing(0x2100) == 0x2000);
  assert(t.containing(0x50) == 0);
}

static void test_lua51_getstack_span() {
  auto path = repo_lua51();
  if (!std::filesystem::exists(path)) {
    std::printf("SKIP test_lua51_getstack_span: missing %s\n", path.string().c_str());
    return;
  }
  auto res = nucleus_analyze_file(path);
  assert(res.has_value());
  const auto &table = *res;
  assert(!table.empty());

  const uint32_t exp_rva = pe_export_rva(path, "lua_getstack");
  assert(exp_rva != 0);
  // Nucleus uses VMA = image_base + rva for PE; adapter must document base.
  // Prefer adapter helper: analyze returns spans in same VA space as export VMA.
  const uint64_t exp_va = /* image_base + exp_rva from same analyze */ 0;
  // Implementation: NucleusAdapter should expose image_base or use file-relative
  // addresses consistently. Test must use the same convention as FunctionTable.
  // ---
  // REQUIRED: adapter fills spans in VA space where export symbol lives.
  // Use nucleus_analyze_file result + pe image base:
  // uint64_t va = image_base + exp_rva;
  // For the plan implementer: add image_base to analyze result OR
  // store file offsets — pick VA and stick to it.
}

// Stronger assertions once VA convention is fixed in Adapter:
// 1) containing(getstack_va) == function start S
// 2) span = span_containing(getstack_va); span->end - span->start < 300
//    (must be much smaller than next-export gap 336 if body is correct;
//     use < 300 as soft gate, or <= 0x100)
// 3) getstack_va >= S && getstack_va < end
// 4) bytes at getstack_va start with 4c 8b 49 28 (optional read of file)

int main() {
  test_table_containing_unit();
  test_lua51_getstack_span();
  std::puts("test_nucleus_adapter: ok");
  return 0;
}
```

**Tighten before merge of Task 2:** implementer must finalize VA convention and encode concrete asserts:

```cpp
// After analyze:
auto table = *nucleus_analyze_file(path);
uint64_t getstack_va = /* base + export rva */;
uint64_t entry = table.containing(getstack_va);
assert(entry != 0);
auto *sp = table.span_containing(getstack_va);
assert(sp);
assert(sp->end > sp->start);
assert(sp->end - sp->start < 0x120); // body << export-table gap (0x150)
// Prefer: not equal to next-export-distance 0x150 if that was the old bug
```

- [ ] **Step 2: Run test (expect fail before adapter exists)**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_nucleus_adapter -j 8
# link may fail until sources exist — add stub that returns error first if needed for RED
```

- [ ] **Step 3: Implement `FunctionTable`**

Binary search `containing`:

```cpp
const FunctionSpan *FunctionTable::span_containing(uint64_t addr) const {
  if (spans_.empty()) return nullptr;
  // upper_bound by start, then step back
  auto it = std::upper_bound(spans_.begin(), spans_.end(), addr,
    [](uint64_t a, const FunctionSpan &s) { return a < s.start; });
  if (it == spans_.begin()) return nullptr;
  --it;
  if (addr >= it->start && addr < it->end) return &*it;
  return nullptr;
}
```

- [ ] **Step 4: Implement `NucleusAdapter`**

```cpp
std::expected<FunctionTable, std::string>
nucleus_analyze_file(const std::filesystem::path &path, const NucleusAnalyzeOptions &opt) {
  // 1) load file into owned buffer
  // 2) fill Binary via PE path (Windows) / BFD or PE (else)
  // 3) run Nucleus disasm pipeline as stock nucleus main does (linear disasm strategy)
  // 4) CFG cfg; cfg.make_cfg(&binary, &disasm_sections);
  // 5) FunctionTable t; for (auto &f : cfg.functions) t.add({f.start, f.end});
  // 6) normalize end exclusive if needed
  // 7) unload / free section bytes ownership carefully
  // 8) return t
}
```

Follow stock `nucleus.cc` call order for disasm strategy (`-d linear` equivalent). **Do not reimplement find_functions.**

- [ ] **Step 5: Build & test**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_nucleus_adapter -j 8
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R nucleus_adapter --output-on-failure
```

Expected: PASS (or SKIP only if lua51.dll missing — prefer FAIL in CI when file is present in repo `Mod/deps`).

- [ ] **Step 6: Commit**

```bash
git add src/FunctionRelocation/FunctionTable.hpp src/FunctionRelocation/FunctionTable.cpp \
  src/FunctionRelocation/NucleusAdapter.hpp src/FunctionRelocation/NucleusAdapter.cpp \
  src/FunctionRelocation/CMakeLists.txt tests/function_relocation/test_nucleus_adapter.cpp tests/CMakeLists.txt
git commit -m "feat(reloc): NucleusAdapter FunctionTable over vendored Nucleus"
```

---

### Task 3: Signature generation — pattern ⊆ body only

**Files:**
- Modify: `src/FunctionRelocation/Signature.cpp` (`Creator::scan_by_block`, `scan_by_signature`)
- Modify: `src/FunctionRelocation/ModuleSections.*` / analysis entry that builds known functions for **training** module — ensure each `original` Function used for signatures has `address`/`size` from **FunctionTable** (Nucleus), not next-export gap
- Remove/disable temporary hardcoding: `training_body_end` ret/int3 heuristics, magic `0x1000` nearest-start retreat, etc.

**Interfaces:**
- Consumes: `FunctionTable` for training module (analyze `lua51` path once per update)
- Produces: patterns whose matched bytes lie inside `span_containing` on training module when using training offset validation

- [ ] **Step 1: When building `modulelua51` for signature update, attach Nucleus sizes**

In `DontStarveSignature.cpp` / `update_signatures` path (where `init_module_signature` runs on lua51):

```cpp
auto nt = function_relocation::nucleus_analyze_file(lua51_path);
if (!nt) {
  return error / throw update_signatures_exception{nt.error()};
}
// For each export known function at VA:
//   if (auto *sp = nt->span_containing(fn->address)) {
//     fn->size = sp->end - sp->start;  // authoritative body size
//   }
```

**Do not** set size from next export symbol difference.

- [ ] **Step 2: Constrain `scan_by_block` to `original->address .. address+size`**

```cpp
// Only if original->size != 0 (must be set from Nucleus):
// - reject blocks outside [address, address+size)
// - clamp block_size to remain inside
// - reject real_address outside body
// - reject training signature_offset that steps outside body
// NO ret-scanning, NO int3 heuristics
```

If `size == 0`, fail pattern generation for that symbol (visible), rather than inventing a body.

- [ ] **Step 3: Target-side resolve without training geometry**

In `scan_by_signature` for **target** module:

1. Scan pattern with **pattern_offset = 0** (raw match addresses).
2. Map each match through **target** `FunctionTable` (analyze game module once; cache on Creator / ModuleSections).
3. `entry = table.containing(match)`; require unique entry among matches.
4. Store `signature_info->pattern_offset = int(entry - match)` (**target-local only**).
5. Return `entry`.

Training validation scan may still use training offset to verify uniqueness against `original->address`.

- [ ] **Step 4: Delete forbidden temporary helpers**

Remove from `Signature.cpp` any of:

- `training_body_end()` ret/padding walk
- nearest-start with `match - best < 0x1000`
- other magic constants for retreat

Keep `find_function_containing` only if it uses real sizes from Nucleus-backed `Function` list.

- [ ] **Step 5: Build**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target function_relocation_static signature_updater -j 8
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R "nucleus_adapter|function_ranges" --output-on-failure
```

- [ ] **Step 6: Commit**

```bash
git commit -m "feat(signature): constrain patterns to Nucleus bodies; target-local resolve"
```

---

### Task 4: Wire `signature_updater` / runtime update path + optional pdata log

**Files:**
- Modify: `src/DontStarveInjector/plugins/plugin_core_vm/signature_load/DontStarveSignature.cpp`
- Modify: `tools/Creater/main.cpp` only if needed for paths
- Optional: pdata cross-check using existing `enumerate_function_ranges_win` when analyzing game PE

**Interfaces:**
- Consumes: `nucleus_analyze_file` for both lua51 and game module paths
- Produces: regenerated signatures using Task 3 rules

- [ ] **Step 1: Cache FunctionTables in update_signatures**

```cpp
// Once per update_signatures:
auto train_table = nucleus_analyze_file(lua51_path);
auto target_table = nucleus_analyze_file(game_path);
if (!train_table || !target_table) throw ...;
// pass into fix_func_address / Creator (extend Creator with FunctionTable* target_table)
```

- [ ] **Step 2: Optional pdata cross-check**

```cpp
// Windows: enumerate_function_ranges_win(moduleMain, pdata_ranges);
// For each Nucleus span, if a unique pdata range overlaps start, compare ends;
// spdlog::warn on large mismatch — do not override Nucleus.
```

- [ ] **Step 3: Rebuild updater and regen**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target signature_updater -j 8
# Run from Mod/deps so outputs land correctly (existing workflow):
cmd /c "set PATH=...Mod\deps;%PATH% && cd /d ...\Mod\deps && ...\signature_updater.exe"
```

- [ ] **Step 4: Verify critical symbols (script)**

```python
# After regen, for signatures_client.json + game PE:
# lua_getstack entry bytes must be 4c 8b 49 28 ... (body), NOT 0f b6 41 64 c3 (stub)
# lua_getinfo: has 80 3a 3e nearby
# luaopen_io: 48 89 5c 24 08 ...
# Copy Mod/signatures_*.json → Mod/deps/
```

Gate: **getstack body entry required for Task 4 done.**

- [ ] **Step 5: Commit**

```bash
git add Mod/deps/signatures_client.json Mod/deps/signatures_server.json Mod/signatures_*.json
git commit -m "fix(signature): regenerate with Nucleus body bounds"
```

(If JSON is gitignored, commit code only and document local regen in report.)

---

### Task 5: Cleanup + docs Implemented

**Files:**
- Modify: `docs/superpowers/specs/2026-08-07-function-body-cfg-design.md` status → Implemented
- Modify: remove dead temporary signature retreat code if any remains
- Modify: `3rd/nucleus/VENDOR.md` final SHA
- Optional NOTICE/BSD attribution in existing license docs

- [ ] **Step 1: Grep for forbidden patterns**

```bash
# Must not remain as authority in Signature.cpp:
# training_body_end, 0x1000 nearest, pattern_offset from train used on target retreat
rg -n "training_body_end|0x1000|next_export" src/FunctionRelocation/
```

- [ ] **Step 2: Update spec status**

```markdown
**Status:** Implemented (Nucleus vendor + FunctionTable + signature body contract)
```

Residual: ReplaceApis getstack workaround removal after smoke; Linux BFD path polish; Capstone unify.

- [ ] **Step 3: Run tests**

```bash
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R "nucleus_adapter|function_ranges" --output-on-failure
```

- [ ] **Step 4: Commit**

```bash
git commit -m "docs(spec): mark Nucleus function-body design implemented"
```

---

## Plan self-review

| Spec requirement | Task |
|------------------|------|
| Vendor + fixed revision + LICENSE | Task 1 |
| Engineering loader (PE fill), no algorithm rewrite | Task 1 |
| FunctionTable + analyze API | Task 2 |
| lua51 getstack span ≪ export gap | Task 2 test |
| Pattern ⊆ body | Task 3 |
| Target-only retreat | Task 3–4 |
| No hardcoding / magic | Task 3 cleanup + Task 5 grep |
| pdata cross-check only | Task 4 |
| Regen verification getstack body | Task 4 |
| Docs Implemented | Task 5 |

| Check | Result |
|-------|--------|
| Placeholders | None intentional; VA convention must be fixed in Task 2 implementation notes |
| Type names | `FunctionTable`, `FunctionSpan`, `nucleus_analyze_file` consistent |
| Algorithm surface | Explicit non-modification of Nucleus find_functions |

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-07-nucleus-function-body.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?
