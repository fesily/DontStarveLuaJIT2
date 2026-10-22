# Nucleus vendor

- Upstream: https://bitbucket.org/vusec/nucleus
- Mirror used: https://github.com/wilvk/nucleus.git
- Pinned revision: 95a38b7a04810757eb1cceb642fb6bdfce16b506
- Vendored date: 2026-08-07
- License: BSD-3-Clause (see LICENSE)
- Policy: algorithm surface (cfg / function finding / disasm strategy) is **not** rewritten;
  engineering surface (loader, CMake, Capstone coexistence, MSVC portability, export glue)
  may be patched; every patch is recorded under `patches/` with rationale.

## Capstone

`nucleus_static` compiles against Capstone through the project Frida Gum surface
(`frida-gum.h` + include shim). A thin include shim under
`cmake/capstone_shim/capstone/capstone.h` satisfies Nucleus's
`#include <capstone/capstone.h>` without a second Capstone copy.

**Link policy:** `nucleus_static` does **not** link `frida-gum.lib` / Capstone.
CMake would propagate that PRIVATE STATIC dependency into every consumer,
including SHARED `function_relocation`, which must import gum only from
Injector. Final link units own gum resolution:
- SHARED reloc / plugins → Injector import lib + `/NODEFAULTLIB:frida-gum.lib`
- tools / tests / STATIC reloc consumers → explicit `${FRIDA_GUM_LIBRARIES}`

## Windows loader

On Windows, `NUCLEUS_LOADER_PE_PARSE=1` enables a pe-parse based PE fill path
so `libbfd` is not required.

## Linux loader

Linux builds define `NUCLEUS_LOADER_NATIVE_ELF=1` and use the native ELF64
reader in `loader.cc` (sections, `STT_FUNC` symbols, `.eh_frame_hdr` seeds);
`libbfd` is neither linked nor needed. Rationale: the release CI image has no
`binutils-dev`, and the old `find_library(bfd)` fallback silently produced a
`NUCLEUS_LOADER_NO_BFD` build whose `load_binary()` always failed, so every
Linux `nucleus_analyze_file()` call aborted signature generation at boot. The
native path reproduces the BFD view exactly (verified span-for-span against the
BFD builds of `liblua51.so`, the `lua51DS`/`lua51Original` VMs, and both DST game
executables).

macOS keeps the stock BFD loader when BFD is available.
