#include <Windows.h>
#include <cassert>
#include "inlinehook.hpp"
#include <format>
#include <memory>
#include <memory_resource>

#ifndef NDEBUG
#include <unordered_set>
static std::unordered_set<uint8_t*> hooked;
#endif

#define GUM_X86_JMP_MAX_DISTANCE (MAXINT32 - 16384)

#define GUM_INTERCEPTOR_FULL_REDIRECT_SIZE 7

#define GUM_INTERCEPTOR_NEAR_REDIRECT_SIZE 5

bool HookByReg(uint8_t *from, uint8_t *to)
{
    assert(!hooked.contains(from));
    auto code = std::to_array<uint8_t>({0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0});
    *(uint64_t *)(code.data() + 2) = (uint64_t)to;

    HookWriteCode(from, code);
#ifndef NDEBUG
    hooked.emplace(from);
#endif
    return true;
}

bool Hook(uint8_t *from, uint8_t *to)
{
    if (*from == 0xe9)
    { // jmp
        from = (uint8_t *)((uint64_t)from + *(uint32_t *)(from + 1) + 5);
    }
    OutputDebugStringA(std::format("Hook {} to {}\n", (void *)from, (void *)to).c_str());
    assert(to != 0);
#if 0
    auto offset = (uint64_t)to - (uint64_t)from - 6;
    if (offset > GUM_X86_JMP_MAX_DISTANCE)
    {
        return HookByReg(from, to);
    }
    // prepare inline hook
    auto code = std::to_array<uint8_t>({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});
    *(uint32_t *)(code.data() + 3) = offset;
    HookWriteCode(from, code);
    return true;
#else
    return HookByReg(from, to);
#endif
}