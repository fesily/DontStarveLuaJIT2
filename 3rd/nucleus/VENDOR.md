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
so `libbfd` is not required. Non-Windows keeps the stock BFD loader when BFD is
available.
