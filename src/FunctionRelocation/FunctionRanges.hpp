#pragma once
#include "ModuleSections.hpp"
#include "export.hpp"
#include <cstdint>
#include <vector>

namespace function_relocation {
struct FuncRange {
    uintptr_t start = 0;
    uintptr_t end = 0;
    enum class Source : uint8_t { Pdata,
                                  EhFrame,
                                  HeuristicFallback };
    Source source = Source::Pdata;
};

FUNCTION_RELOCATION_API bool enumerate_function_ranges_win(
    const ModuleSections& m, std::vector<FuncRange>& out);

// Exact ELF FDE ranges, remapped using the ELF load bias (including PIE main
// executables). Used for hook entries and native extent refinement in the
// Nucleus adapter.
FUNCTION_RELOCATION_API bool enumerate_function_ranges_elf(
        const ModuleSections &m, std::vector<FuncRange> &out);

FUNCTION_RELOCATION_API uintptr_t resolve_function_entry(
        const ModuleSections &m, uintptr_t instruction_address);

// Input ranges are sorted and non-overlapping, as returned by the enumerators.
FUNCTION_RELOCATION_API const FuncRange* find_range_containing(
    const std::vector<FuncRange>& ranges, uintptr_t addr);
} // namespace function_relocation
