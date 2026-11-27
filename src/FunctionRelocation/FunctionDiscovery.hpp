#pragma once

#include "FunctionTable.hpp"
#include "ModuleSections.hpp"
#include "export.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace function_relocation {
    // Platform entry discovery (declared here, dispatched from FunctionRanges.cpp
    // discover_module_functions).
    namespace detail {

        // Install a discovered entry table (process VA) on a module: rebuilds the
        // Function objects, the address/name indexes, and drops every derived
        // feature cache. An empty span table is an error and leaves the module
        // without functions.
        FUNCTION_RELOCATION_API bool install_function_spans(ModuleSections &sections,
                                                            std::vector<FunctionSpan> spans,
                                                            std::vector<FunctionFragment> fragments);

        // PE x64: `.pdata` primaries + chained merge, export/entry/TLS seeds,
        // block-scoped recursive descent, direct-call adoption
        // (docs/function-enumeration-without-pdb.md §2-§4).
        // `spans` holds process-VA entries (one per function entry), `fragments`
        // the code that belongs to an entry without starting one.
        FUNCTION_RELOCATION_API bool discover_pe_x64(const ModuleSections &module,
                                                     std::vector<FunctionSpan> &spans,
                                                     std::vector<FunctionFragment> &fragments);

        // Shared Mach-O LC_FUNCTION_STARTS decoder: ULEB128 deltas accumulated
        // from the loaded image base, entries filtered to the __text range.
        // Used by the production Mach-O path and by the CTest that cannot rely on
        // the host toolchain emitting a function-starts command.
        FUNCTION_RELOCATION_API bool decode_macho_function_starts(uintptr_t image_base,
                                                                  GumMemoryRange text,
                                                                  std::span<const uint8_t> blob,
                                                                  std::vector<FunctionSpan> &spans);

        // Resolve a PE entry thunk (`E9 rel32` / `FF 25 [rip+disp32]`) to the real
        // body with an already allocated capstone instruction (discovery seam).
        // Returns 0 when the target is not in the module, cannot be decoded, or
        // the chain is cyclic / too long.
        FUNCTION_RELOCATION_API uintptr_t resolve_pe_discovery_target(const ModuleSections &module,
                                                                     uintptr_t target,
                                                                     cs_insn &insn);
    }// namespace detail
}// namespace function_relocation
