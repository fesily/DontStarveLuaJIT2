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
| CMake library | `CMakeLists.txt` | Produce `nucleus_static` without CLI/getopt/BFD on Windows; Frida Gum / Capstone are **headers-only** on this archive (no `target_link_libraries` of `frida-gum`/`capstone`) so STATIC PRIVATE deps cannot re-pull a second gum into SHARED `function_relocation`; tools/tests link gum on the final unit |
| Capstone shim | `cmake/capstone_shim/capstone/capstone.h` | Map `<capstone/capstone.h>` → Frida Gum Capstone surface |
| Options defaults | `options_defaults.cc` | Library consumers need defaults without CLI `getopt` |
| PE loader | `loader.cc` / `loader.h` | Fill `Binary`/`Section` via pe-parse; no libbfd on Windows |
| PE pdata starts | `loader.cc` `pe_load_pdata_symbols` | x64 `.pdata` RUNTIME_FUNCTION BeginAddress → `SYM_TYPE_FUNC` (skip `UNW_FLAG_CHAININFO`). Windows analogue of ELF FUNC / eh_frame; existing `split_at_known_entries` consumes these. Not a CFG algorithm fork |
| ELF eh_frame starts | `loader.cc` `elf_load_eh_frame_symbols` | GNU `.eh_frame_hdr` FDE `initial_location` → `SYM_TYPE_FUNC`. Linux analogue of PE pdata; stripped DST ELF has no lua FUNC dynsyms. Not a CFG algorithm fork |
| BFD section API | `loader.cc` `load_sections_bfd` | binutils 2.34+ single-arg `bfd_section_{flags,vma,size,name}(sec)`; keep `bfd_get_section_flags` ifdef for older hosts |
| endian linkage | `endian.h` | `extern "C"` wrappers so defs match cfg calls after frida-gum open `extern "C"` regions |
| util portability | `util.cc` | Replace POSIX `realpath`/`libgen` for MSVC; keep upstream-like `xorshift128plus` seed via `rand64()`/`random_device` |
| insn.h enum init | `insn.h` | MSVC requires enum-typed zero for Capstone reg fields |
| make_cfg empty-BB guard | `cfg.cc` | Skip `invalid` / empty-`insns` BBs in the link loop so MSVC Debug CRT does not abort on `std::list::back()`; first pass already excludes them from `start2bb` |
| endian MSVC | `endian.cc` | `__BYTE_ORDER__` not available on MSVC; force LE on Windows |

### PE section bytes (Windows pe-parse path)

`pe_section_cb` allocates **VirtualSize** (falling back to `SizeOfRawData` when VS is 0), copies `min(raw, VS)` from pe-parse's section buffer, and **zero-fills** the remainder when `VirtualSize > SizeOfRawData` / raw length. `sec->size` is the virtual size. BSS-like sections with VS > 0 and no raw bytes get a zero-filled buffer.

### BFD `load_dynrelocs_bfd` (non-Windows path) — intentional deviation

Upstream (pin `95a38b7`) **applies** dynamic relocations into section bytes (howto mask + `bfd_put_*`). The in-tree BFD path instead **names** existing symbols from dynamic reloc entries (`addr2sym` + `sym_ptr_ptr->name`) and does **not** patch section data.

**Rationale (engineering, not CFG algorithm):** product CFG authority is Windows PE via pe-parse; the BFD path is retained only for optional non-Windows builds. Applying full reloc rewrite requires careful BFD API surface that varies by host binutils and is unused on the product path. Symbol naming from dynrelocs is enough for optional Linux smoke. Do **not** reintroduce apply-reloc without a dedicated non-Windows test matrix.

If a future upstream fix belongs in algorithm surface, stop and discuss — do not
silently rewrite function partition.
