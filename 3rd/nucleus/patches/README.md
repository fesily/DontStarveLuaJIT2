# Nucleus engineering patches

Patches in this directory (and in-tree edits under `3rd/nucleus/`) are **engineering
surface only**. Do not use this directory for algorithm forks of `CFG::make_cfg`,
`find_functions`, expand, or strategy scoring.

## How to re-apply after re-vendoring

1. Check out the pinned SHA recorded in `../VENDOR.md`.
2. Copy the tree into `3rd/nucleus` (no nested `.git`).
3. Re-apply each listed change below (or `git apply` if a `.patch` file is present).
4. Rebuild `nucleus_static`.

## Current engineering changes (in-tree at pin time)

| Area | File(s) | Why (not algorithm) |
|------|---------|---------------------|
| CMake library | `CMakeLists.txt` | Produce `nucleus_static` without CLI/getopt/BFD on Windows |
| Capstone shim | `cmake/capstone_shim/capstone/capstone.h` | Map `<capstone/capstone.h>` → Frida Gum Capstone surface |
| Options defaults | `options_defaults.cc` | Library consumers need defaults without CLI `getopt` |
| PE loader | `loader.cc` / `loader.h` | Fill `Binary`/`Section` via pe-parse; no libbfd on Windows |
| util portability | `util.cc` | Replace POSIX `realpath`/`libgen` for MSVC |
| insn.h enum init | `insn.h` | MSVC requires enum-typed zero for Capstone reg fields |
| endian MSVC | `endian.cc` | `__BYTE_ORDER__` not available on MSVC; force LE on Windows |

If a future upstream fix belongs in algorithm surface, stop and discuss — do not
silently rewrite function partition.
