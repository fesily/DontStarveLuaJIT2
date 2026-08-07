# Task 1 Report: Vendor Nucleus + nucleus_static

**Branch:** `feature/nucleus-function-body`  
**Worktree:** `C:/Users/fesil/DontStarveLuaJIT2/.worktrees/nucleus-function-body`  
**Base:** `68bd695`  
**Date:** 2026-08-07  

## Summary

Vendored VUSec Nucleus (wilvk mirror) under `3rd/nucleus` at a pinned SHA, added CMake target `nucleus_static`, and implemented a Windows PE loader path via pe-parse so libbfd is not required. Capstone is consumed through the project Frida Gum surface (include shim). CFG / function-finding algorithm sources were not rewritten.

## Acceptance

| Criterion | Status |
|-----------|--------|
| `3rd/nucleus` present with LICENSE + VENDOR.md pinned SHA | PASS |
| `nucleus_static` builds RelWithDebInfo | PASS |
| No algorithm rewrite of `find_functions` / `make_cfg` | PASS |
| Commit on feature branch | PASS (this commit) |
| Report path set | PASS (this file) |

## Vendor pin

- Upstream: https://bitbucket.org/vusec/nucleus
- Mirror: https://github.com/wilvk/nucleus.git
- **Pinned revision:** `95a38b7a04810757eb1cceb642fb6bdfce16b506`
- License: BSD-3-Clause (`3rd/nucleus/LICENSE`)
- Recorded in: `3rd/nucleus/VENDOR.md`

Empty nested `capstone/` placeholder and nested `.git` were removed from the vendor snapshot (Capstone comes from Frida Gum).

## CMake

- `3rd/nucleus/CMakeLists.txt` defines `add_library(nucleus_static STATIC …)` and alias `Nucleus::nucleus_static`.
- Sources: CFG stack + disasm + strategy + loader + util; **excludes** CLI (`nucleus.cc`), getopt (`options.cc`), export, exception.
- `options_defaults.cc` provides library defaults (`strategy=linear`, etc.) without CLI.
- Capstone: private include of `cmake/capstone_shim` so `#include <capstone/capstone.h>` maps to `frida-gum.h`; links `${FRIDA_GUM_LIBRARIES}` when Frida Gum is available.
- Windows: `NUCLEUS_LOADER_PE_PARSE=1` + `pe-parse::pe-parse`.
- Non-Windows: optional libbfd; `NUCLEUS_LOADER_NO_BFD` if missing.
- Wired from `src/FunctionRelocation/CMakeLists.txt` via `add_subdirectory(... 3rd/nucleus ...)` when target missing. **No** `target_link_libraries` to function_relocation yet (Task 2).

## Engineering surface patches (not algorithm)

Documented in `3rd/nucleus/patches/README.md`:

1. **loader.cc** — PE fill with pe-parse: `Binary` type/arch/bits/entry, executable+data sections with owned `bytes` buffers, optional export symbols as `SYM_TYPE_FUNC`. Stock BFD path retained behind `#elif !NUCLEUS_LOADER_NO_BFD`.
2. **util.cc** — MSVC-safe path helpers (`GetFullPathNameA`) instead of POSIX `realpath`/`libgen`.
3. **endian.cc** — host LE detection without `__BYTE_ORDER__` on MSVC.
4. **insn.h** — Capstone enum-typed zero-init for MSVC (reg fields).
5. **CMake + Capstone shim + options_defaults** — packaging / coexistence only.

**Not modified (algorithm):** `cfg.cc` / `find_functions` / `make_cfg` / strategy scoring logic.

## Build smoke

Isolated worktree build (avoids fighting master concurrent builds):

```text
cmake -S builds/nucleus-only -B builds/ninja-nucleus \
  -G "Ninja Multi-Config" \
  -DCMAKE_TOOLCHAIN_FILE=<repo>/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-windows-custom \
  -DVCPKG_INSTALLED_DIR=<master>/builds/ninja-multi-vcpkg/vcpkg_installed

cmake --build builds/ninja-nucleus --config RelWithDebInfo --target nucleus_static -j 8
```

Result: **success** — produced  
`builds/ninja-nucleus/nucleus/RelWithDebInfo/nucleus_static.lib` (~4.7 MB).

Notes:
- `builds/nucleus-only` is a thin standalone CMake root used only for Task 1 smoke (not product install path). Product integration remains via FunctionRelocation `add_subdirectory`.
- Warnings only (C4819 on frida-gum.h codepage; unused vars / empty switches in experimental arch disasm). No algorithm changes to silence them.

## Follow-ups (out of Task 1 scope)

- Task 2: `FunctionTable` + `NucleusAdapter` + link `nucleus_static` into reloc targets.
- Optional: drop unused arch disasm TUs if product is x86-only; keep for now to match upstream CFG multi-arch surface.
- Full root preset configure (`ninja-multi-vcpkg`) not required for this task smoke.

## Files touched

- Create: `3rd/nucleus/**` (vendor + CMake + patches + engineering edits)
- Create: `builds/nucleus-only/CMakeLists.txt` (local smoke only; gitignored under `builds/`)
- Modify: `src/FunctionRelocation/CMakeLists.txt`
- Create: `.superpowers/sdd/task-1-report.md`
