#pragma once
#include "ModuleSections.hpp"
#include "export.hpp"
#include <cstdint>
#include <vector>

namespace function_relocation {
struct FuncRange {
    uintptr_t start = 0;
    uintptr_t end = 0;
    enum class Source : uint8_t { Pdata, HeuristicFallback };
    Source source = Source::Pdata;
};

FUNCTION_RELOCATION_API bool enumerate_function_ranges_win(
    const ModuleSections& m, std::vector<FuncRange>& out);

FUNCTION_RELOCATION_API const FuncRange* find_range_containing(
    const std::vector<FuncRange>& ranges, uintptr_t addr);
} // namespace function_relocation
