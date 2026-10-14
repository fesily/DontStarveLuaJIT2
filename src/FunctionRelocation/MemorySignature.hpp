#pragma once
#include <cstdint>
#include <vector>
#include "export.hpp"

namespace function_relocation
{
    struct MemorySignature {
        const char* pattern;
        int pattern_offset;
        bool only_one = true;
        bool log = true;
        uint32_t prot_flag = 4; //GUM_PAGE_EXECUTE
        uintptr_t target_address = 0;
        std::vector<uintptr_t> targets;
        FUNCTION_RELOCATION_API uintptr_t scan(const char* m);
        FUNCTION_RELOCATION_API uintptr_t scan(uintptr_t address, size_t size);
        // Resolve raw pattern hits through exact ELF FDE ranges. This policy is
        // per call so the legacy data layout and scan() ABI remain unchanged.
        // pattern_offset applies to scan(); scan_function() returns the entry.
        FUNCTION_RELOCATION_API uintptr_t scan_function(const char *m);
    };
}
