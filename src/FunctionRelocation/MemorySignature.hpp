#pragma once
#include <cstdint>
#include <vector>

namespace function_relocation
{
    struct MemorySignature {
        const char* pattern;
        int pattern_offset;
        bool only_one = true;
        uintptr_t target_address = 0;
        std::vector<uintptr_t> targets;


        uintptr_t scan(const char* m);
    };
}
