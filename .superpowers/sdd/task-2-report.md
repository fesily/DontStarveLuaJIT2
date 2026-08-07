# Task 2 Report: FunctionTable + NucleusAdapter + lua51 regression

**Branch:** `feature/nucleus-function-body`  
**Worktree:** `C:/Users/fesil/DontStarveLuaJIT2/.worktrees/nucleus-function-body`  
**Base:** Task 1 at `4d0d9ad`  
**Date:** 2026-08-07  

## Summary

Implemented portable `FunctionTable` with binary-search `containing` / `span_containing`, and `NucleusAdapter` that runs the stock Nucleus pipeline (`load_binary` → `nucleus_disasm` linear strategy → `CFG::make_cfg`) and maps `Function::{start,end}` into half-open image-VA spans. Wired `nucleus_static` PRIVATE into FunctionRelocation targets. Regression test on `Mod/deps/lua51.dll` asserts non-empty table and that `lua_getstack` body span is `0x7a` (≪ `0x120` and ≪ next-export gap `0x150`).

## Acceptance

| Criterion | Status |
|-----------|--------|
| `nucleus_analyze_file(Mod/deps/lua51.dll)` non-empty | PASS (887 functions) |
| `containing(getstack_va)` works | PASS (`entry == 0x1800090f0`) |
| span size `< 0x120` | PASS (`size = 0x7a`) |
| `ctest -R nucleus_adapter` | PASS |
| Commit on feature branch | PASS (this commit) |
| Report path | PASS (this file) |

## VA convention (locked)

- Spans and export lookups use **image VA** = preferred PE **ImageBase + RVA** (not process load address).
- Nucleus PE loader already fills section `vma` / export `Symbol::addr` as image VAs (`pe-parse` IterSec / IterExpVA).
- `FunctionSpan::{start,end}`: **half-open** `[start, end)` — Nucleus `Function::end` / `BB::end` are exclusive (first byte past last non-NOP insn).
- `NucleusAnalyzeResult` carries both `table` and `image_base` so callers can form `export_va = image_base + export_rva` without re-parsing PE.
- Convenience: `nucleus_analyze_file_table(...)` returns only `FunctionTable` (plan-shaped); `pe_image_base(path)` for standalone base reads.

## API surface

```cpp
// FunctionTable.hpp
struct FunctionSpan { uint64_t start; uint64_t end; }; // [start,end)
class FunctionTable {
  void clear();
  void add(FunctionSpan);
  uint64_t containing(uint64_t) const;                 // start or 0
  const FunctionSpan *span_containing(uint64_t) const;
  const std::vector<FunctionSpan> &spans() const;
  bool empty() const;
};

// NucleusAdapter.hpp
struct NucleusAnalyzeOptions { bool log_pdata_crosscheck = false; };
struct NucleusAnalyzeResult { FunctionTable table; uint64_t image_base; };
std::expected<NucleusAnalyzeResult, std::string>
  nucleus_analyze_file(path, opt = {});
std::expected<FunctionTable, std::string>
  nucleus_analyze_file_table(path, opt = {});
std::expected<uint64_t, std::string> pe_image_base(path);
```

No Nucleus types leak outside `NucleusAdapter.cpp`.

## Adapter pipeline

1. `gum_init_embedded()` + `cs_arch_register_x86()` once (Frida Gum modular Capstone; same pattern as `function_relocation::init_ctx`).
2. Ensure `options.strategy_function.name = "linear"` (defaults from `options_defaults.cc`).
3. `load_binary(fname, &bin, BIN_TYPE_AUTO)` — Windows PE path via pe-parse (Task 1).
4. `nucleus_disasm(&bin, &disasm)` — stock linear strategy (no CFG rewrite).
5. `cfg.make_cfg(&bin, &disasm)`.
6. For each `cfg.functions`: `table.add({f.start, f.end})` if `end > start`.
7. `unload_binary(&bin)`; empty table → error string (no silent success).

## CMake

- `src/FunctionRelocation/CMakeLists.txt`: add `NucleusAdapter.cpp`; `target_link_libraries(... PRIVATE nucleus_static)` in common config (SHARED + STATIC).
- `3rd/nucleus/CMakeLists.txt`: promote Capstone shim include to **PUBLIC** so consumers of Nucleus headers (`insn.h` → `<capstone/capstone.h>`) compile without private shim.
- `tests/CMakeLists.txt` (WIN32): `test_nucleus_adapter` → `function_relocation_static` + Frida Gum; ctest name `nucleus_adapter`, `WORKING_DIRECTORY` = source root so `Mod/deps/lua51.dll` resolves.
- Smoke build (isolated, same as Task 1): `builds/nucleus-only` extended with `nucleus_adapter_smoke` + `test_nucleus_adapter` under `builds/ninja-nucleus` (gitignored under `builds/`).

## Build & test evidence

```text
cmake -S builds/nucleus-only -B builds/ninja-nucleus \
  -G "Ninja Multi-Config" \
  -DCMAKE_TOOLCHAIN_FILE=<repo>/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-windows-custom \
  -DVCPKG_INSTALLED_DIR=<master>/builds/ninja-multi-vcpkg/vcpkg_installed

cmake --build builds/ninja-nucleus --config RelWithDebInfo --target test_nucleus_adapter -j 8
ctest --test-dir builds/ninja-nucleus -C RelWithDebInfo -R nucleus_adapter --output-on-failure
```

Result:

```text
lua_getstack: va=0x1800090f0 entry=0x1800090f0 end=0x18000916a size=0x7a
              functions=887 image_base=0x180000000
test_nucleus_adapter: ok

1/1 Test #1: nucleus_adapter ..................   Passed
100% tests passed, 0 tests failed out of 1
```

Unit checks on synthetic spans also pass (`containing` boundaries / exclusive end).

## Files touched

- Create: `src/FunctionRelocation/FunctionTable.hpp`
- Create: `src/FunctionRelocation/NucleusAdapter.hpp`
- Create: `src/FunctionRelocation/NucleusAdapter.cpp`
- Create: `tests/function_relocation/test_nucleus_adapter.cpp`
- Modify: `src/FunctionRelocation/CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`
- Modify: `3rd/nucleus/CMakeLists.txt` (PUBLIC capstone shim)
- Create: `.superpowers/sdd/task-2-report.md`
- Local only (gitignored): `builds/nucleus-only/CMakeLists.txt` smoke extension

## Notes / follow-ups

- Capstone via Frida Gum requires **arch registration** before `cs_open`; without `cs_arch_register_x86()` Nucleus disasm fails with `failed to initialize libcapstone`.
- SHARED `function_relocation` still delay-loads Injector for gum; NucleusAdapter symbols resolve through that import surface at process runtime. Tools/tests use static + direct gum (verified path for this task).
- Task 3+: consume `FunctionTable` in Signature / ScanCtx; no signature path changes in this task.
- No per-symbol hardcoding; getstack is only a regression oracle via PE export name lookup in the test.

## Fix: Important finding — second frida-gum via nucleus_static

**Date:** 2026-08-07  
**Commit message:** `fix(nucleus): do not link frida-gum into nucleus_static`

### Finding

`nucleus_static` used `target_link_libraries(... PRIVATE ${FRIDA_GUM_LIBRARIES})`.
For **STATIC** libraries, CMake still propagates PRIVATE link deps into every
final link unit that consumes the archive. Linking `nucleus_static` into SHARED
`function_relocation` therefore re-pulled `frida-gum.lib` beside the intentional
Injector gum import path (`InjectorGumImport.lib` + `/NODEFAULTLIB:frida-gum.lib`).

### Fix

- `3rd/nucleus/CMakeLists.txt`: keep Frida Gum / Capstone as **headers + `GUM_STATIC` only** on `nucleus_static`; remove `target_link_libraries` of `frida-gum` / Capstone.
- Document ownership: final link units resolve gum (SHARED → Injector import; tools/tests → explicit `${FRIDA_GUM_LIBRARIES}`).
- Comment on FunctionRelocation common config accordingly.

### Verification

```text
cmake --build builds/ninja-nucleus --config RelWithDebInfo --target nucleus_static test_nucleus_adapter -j 8
ctest --test-dir builds/ninja-nucleus -C RelWithDebInfo -R nucleus_adapter --output-on-failure
```

- `nucleus_adapter` **PASS**
- Smoke test final `LINK_LIBRARIES` has **one** `frida-gum.lib` token (explicit tools link only); no second copy propagated from `nucleus_static` (was two tokens before).
- SHARED product path: `nucleus_static` no longer carries gum in its link interface, so SHARED reloc keeps Injector import + `/NODEFAULTLIB:frida-gum.lib` as sole gum resolution (product tree on master lacks this branch's nucleus link; policy encoded in CMake).

### Files touched (fix)

- `3rd/nucleus/CMakeLists.txt`
- `3rd/nucleus/VENDOR.md`
- `3rd/nucleus/patches/README.md`
- `src/FunctionRelocation/CMakeLists.txt`
- `.superpowers/sdd/task-2-report.md` (this appendix)
