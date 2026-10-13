#pragma once

#include <cstdint>

namespace function_relocation {
    struct ModuleSections;

    namespace detail {
        // Resolve PLT/GOT thunks without snapping real entries to FunctionTable
        // parents. Unknown or unbound thunks keep their original target.
        uintptr_t resolve_call_target(const ModuleSections &module, uintptr_t target);
    }
}// namespace function_relocation
