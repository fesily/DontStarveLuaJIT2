#pragma once

#include "export.hpp"

#include <cstdint>

namespace function_relocation {
    struct ModuleSections;

    // Windows: resolve a PE entry thunk (`E9 rel32` / `FF 25 [rip+disp32]`) to
    // the real body, following up to eight hops. Returns the target itself when
    // it is already a real body and 0 when it is outside the module, cannot be
    // decoded, or the chain is cyclic. No-op (0) on other platforms.
    FUNCTION_RELOCATION_API uintptr_t resolve_pe_discovery_target(const ModuleSections &module,
                                                                 uintptr_t target);

    namespace detail {
        // Resolve PLT/GOT thunks without snapping real entries to function
        // parents. Unknown or unbound thunks keep their original target.
        uintptr_t resolve_call_target(const ModuleSections &module, uintptr_t target);
    }
}// namespace function_relocation
