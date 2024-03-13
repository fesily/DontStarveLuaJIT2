#pragma once
#include <cstdint>
namespace function_relocation
{
    struct MemorySignature {
        const char* pattern;
        int pattern_offset;
        uintptr_t target_address = 0;

        MemorySignature(const char* p, int offset) : pattern{ p }, pattern_offset{ offset } {}

        uintptr_t scan(const char* m);
    };
}
