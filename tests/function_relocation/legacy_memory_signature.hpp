#pragma once

#include <cstdint>
#include <vector>
#include "export.hpp"

// Frozen pre-cbe1602 header. The consumer test intentionally compiles against
// the old declaration and links the current shared library.
namespace function_relocation {
    struct MemorySignature {
        const char *pattern;
        int pattern_offset;
        bool only_one = true;
        bool log = true;
        uint32_t prot_flag = 4;
        uintptr_t target_address = 0;
        std::vector<uintptr_t> targets;
        FUNCTION_RELOCATION_API uintptr_t scan(const char *module_name);
        FUNCTION_RELOCATION_API uintptr_t scan(uintptr_t address, size_t size);
    };
}// namespace function_relocation
