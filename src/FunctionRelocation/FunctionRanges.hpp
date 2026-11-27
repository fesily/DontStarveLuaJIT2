#pragma once
#include "ModuleSections.hpp"
#include "export.hpp"
#include <cstdint>
#include <vector>

namespace function_relocation {
struct FuncRange {
    uintptr_t start = 0;
    uintptr_t end = 0;
};

// Platform entry discovery. Installs the module's function table (PE x64
// `.pdata` + seeds + recursive descent, ELF `.eh_frame` FDE extents, Mach-O
// LC_FUNCTION_STARTS) and returns false when no entry survives.
FUNCTION_RELOCATION_API bool discover_module_functions(ModuleSections &module);

// Exact ELF FDE ranges, remapped using the ELF load bias (including PIE main
// executables). Used for hook entries.
FUNCTION_RELOCATION_API bool enumerate_function_ranges_elf(
        const ModuleSections &m, std::vector<FuncRange> &out);

FUNCTION_RELOCATION_API uintptr_t resolve_function_entry(
        const ModuleSections &m, uintptr_t instruction_address);

// Input ranges are sorted by start. An exact start always wins; an interior
// address resolves to the shortest containing range (ties: later start).
FUNCTION_RELOCATION_API const FuncRange* find_range_containing(
    const std::vector<FuncRange>& ranges, uintptr_t addr);
} // namespace function_relocation
