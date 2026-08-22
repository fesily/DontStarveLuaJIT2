# Task 3 Report: `function_relocation` STATIC → SHARED

**Status:** DONE  
**Date:** 2026-08-06  
**Base:** `a861b87`  
**Commit:** `12de38c9649276680b7166904d5143c2d2064ced` — `feat(reloc): build function_relocation as SHARED without Gum`

## Summary

`function_relocation` is now a SHARED library with `FUNCTION_RELOCATION_API` exports. It still does **not** link `frida-gum`; gum/cs symbols import from Injector (FridaGum.def re-export surface) via a generated import lib + `/DELAYLOAD:Injector.dll`.

## Changes

### 1. Export surface
- New `src/FunctionRelocation/export.hpp` (`FUNCTION_RELOCATION_BUILD` → dllexport/dllimport)
- Applied to cross-DLL APIs:
  - `MemorySignature::scan`
  - `init_ctx` / `deinit_ctx` / `get_ctx`
  - `get_module_sections` / `init_module_signature`
  - `ModuleSections::try_fix_func_address`
  - `Function::{get_block,consts_count,calls_count,const_count,const_offset_count}`
  - `Signature::{to_string,operator==}` / `release_signature_cache`
  - `FileSignature::{create_file_signature,read_file_signature,FileData::fix_ptr}`

### 2. CMake SHARED
- `add_library(function_relocation SHARED …)`
- `FUNCTION_RELOCATION_BUILD` private define
- Still only **includes** gum headers; **no** `frida-gum` link
- MSVC:
  - Generates `InjectorGumImport.lib` from `FridaGum.def` with `LIBRARY Injector`
  - Links that import lib + `delayimp`
  - `/DELAYLOAD:Injector.dll` (breaks hard circular load with Injector)
  - `/NODEFAULTLIB:frida-gum.lib` (frida-gum.h always `#pragma comment(lib,"frida-gum.lib")`)
- Win: pe-parse private; non-Win: keystone + libdwarf as before
- Build-tree output: **next to Injector** (`$<TARGET_FILE_DIR:Injector>`) so OS resolves the import when mapping Injector
- Install: `RUNTIME/LIBRARY/ARCHIVE → deps` COMPONENT `deps`

### 3. Other code fixes for SHARED
- `ModuleSections.cpp`: load `dbghelp.dll` via `LoadLibraryA` (no Injector `loadlib` circular import)
- `Signature.cpp`: keystone/`AsmX86` gated to `__linux__` only (usage already Linux-only)
- `ds_signature`: still PUBLIC-links `function_relocation` (now SHARED import, not static absorption)
- Plugin comments updated for shared/refcounted ctx

## Build-tree layout (documented)

```
builds/.../src/DontStarveInjector/RelWithDebInfo/
  Injector.dll
  function_relocation.dll   # colocated for import resolution
  plugins/plugin_*.dll
```

Package install stages `function_relocation` to `deps/` (runtime search via Task 2 `mod/deps`).

## Verification (Windows RelWithDebInfo)

```text
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target Injector function_relocation plugin_core_vm plugin_network_rpc \
           plugin_debug_profiler plugin_fps_render -j 4
→ EXIT:0
```

Artifacts:
- `function_relocation.dll` produced
- Plugins + Injector link successfully

Dependents (`dumpbin /dependents`):
| Module | imports `function_relocation.dll` | imports frida-gum |
|--------|-----------------------------------|-------------------|
| Injector.dll | yes | no |
| function_relocation.dll | — | **no** (delay-imports Injector for gum/cs) |
| plugin_core_vm / network_rpc / debug_profiler / fps_render | yes | no |

Exports present: `init_ctx`, `scan`, `get_module_sections`, `release_signature_cache`, etc. (19 C++ exports).

## Non-goals / deferred
- Full package install + `mod/deps` runtime staging of third-party DLLs (Task 4+)
- Linux/macOS SHARED not exercised on this host
- Gum remains static inside Injector only

## Concerns
- Circular dependency Injector ↔ function_relocation is intentional: function_relocation **delay-loads** Injector for gum; Injector **imports** function_relocation normally (side-by-side in build tree).
- Runtime packaging must ensure `function_relocation.dll` is findable with Injector (build tree: same dir; package: `mod/deps` + early DLL search from Task 2 / later install tasks).

## Files committed
- `src/FunctionRelocation/export.hpp` (new)
- `src/FunctionRelocation/CMakeLists.txt`
- `src/FunctionRelocation/{MemorySignature,ctx,Signature,ModuleSections,ExectuableSignature}.hpp`
- `src/FunctionRelocation/{ModuleSections,Signature}.cpp`
- `src/DontStarveInjector/plugins/plugin_core_vm/signature_load/CMakeLists.txt`
- `src/DontStarveInjector/plugins/plugin_core_vm/plugin_core_vm.cpp`
- `src/DontStarveInjector/plugins/plugin_network_rpc/plugin_network_rpc.cpp`

## Fix: Important review findings (gum resolution)

**Date:** 2026-08-06  
**Commit message:** `fix(reloc): resolve gum for SHARED reloc without breaking tools`
### Finding 1 — Non-Windows SHARED gum
**Fix A (chosen):** Windows-only SHARED. Non-Windows keeps STATIC `function_relocation` with an explicit CMake branch + comment that ELF/Mach-O Injector gum re-export is still unimplemented (same residual as gum plugin skip). Avoids undefined `gum_*` under `-z,defs` / `-undefined,error` without embedding a second frida-gum.

### Finding 2 — Tools delay-load Injector
**Fix:** Dual targets on Windows:
- `function_relocation` SHARED — Injector + plugins; gum via Injector import lib + `/DELAYLOAD`
- `function_relocation_static` STATIC — `signature_updater` / `signature_checker`; tools keep their own frida-gum; no Injector dependency

Non-Windows: `function_relocation_static` is an ALIAS of the STATIC `function_relocation`.

`ds_signature` no longer PUBLIC-links reloc (headers only); final link unit chooses SHARED vs STATIC. Consumer `FUNCTION_RELOCATION_API` is empty (no dllimport) so the same STATIC `ds_signature` objects work with either.

### Verification (Windows RelWithDebInfo)
```text
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target Injector function_relocation function_relocation_static \
           plugin_core_vm plugin_network_rpc plugin_debug_profiler plugin_fps_render \
           signature_updater signature_checker -j 4
→ EXIT:0
```

| Module | function_relocation.dll | Injector.dll | notes |
|--------|-------------------------|--------------|-------|
| Injector.dll | yes | — | |
| function_relocation.dll | — | delay-load | no frida-gum |
| plugin_core_vm / network_rpc / debug_profiler / fps_render | yes | yes | |
| signature_updater.exe | **no** | **no** | static reloc + frida-gum |
| signature_checker.exe | **no** | **no** | static reloc + frida-gum |

### Residual
- Non-Windows dynamic reloc (SHARED + Injector gum re-export) still unimplemented.

### Files
- `src/FunctionRelocation/CMakeLists.txt`
- `src/FunctionRelocation/export.hpp`
- `src/DontStarveInjector/plugins/plugin_core_vm/signature_load/CMakeLists.txt`
- `tools/Creater/CMakeLists.txt`
- `tools/Checker/CMakeLists.txt`
- `.superpowers/sdd/vcpkg-dyn-task-3-report.md`
