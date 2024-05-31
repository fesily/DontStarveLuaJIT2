#ifdef _WIN32
#include <Windows.h>
#else

#include <sys/mman.h>
#include <unistd.h>

#endif

#include <cassert>
#include <cstring>
#include <format>
#include <memory>
#include <memory_resource>
#include <unordered_map>

#include "inlinehook.hpp"

static auto& hooked() {
    static std::unordered_map<void *, std::string> hooked;
    return hooked;
}

#define GUM_X86_JMP_MAX_DISTANCE (MAXINT32 - 16384)

#define GUM_INTERCEPTOR_FULL_REDIRECT_SIZE 7

#define GUM_INTERCEPTOR_NEAR_REDIRECT_SIZE 5

bool HookWriteCode(void *from, const void *code, size_t len) {
#ifdef _WIN32
    DWORD oldProtect = 0;
    ::VirtualProtect(from, len, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!(oldProtect & 0xf0))
        return false;
    assert(oldProtect & PAGE_EXECUTE_READ);
    memcpy(from, code, len);
    return ::VirtualProtect(from, len, PAGE_EXECUTE_READ, &oldProtect);
#else
#ifndef _SC_PAGE_SIZE
#define  PAGE_SIZE_MACRO _SC_PAGESIZE
#else
#define PAGE_SIZE_MACRO _SC_PAGE_SIZE
#endif
    static auto page_size = sysconf(PAGE_SIZE_MACRO);
    auto aligned_address = (void *) (uintptr_t(from) & ~(page_size - 1));
    auto aligned_size = (1 + (((uintptr_t) from + len - 1 - (uintptr_t) aligned_address) / page_size)) * page_size;
    if (mprotect(aligned_address, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return false;
    }
    memcpy(from, code, len);
    return mprotect(aligned_address, aligned_size, PROT_READ | PROT_EXEC) == 0;
#endif
}

bool HookByReg(uint8_t *from, uint8_t *to) {
    assert(!hooked().contains(from));
    auto code = std::to_array<uint8_t>({0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0});
    *(uint64_t *) (code.data() + 2) = (uint64_t) to;
    auto old_content = std::string((char*)from, code.size());

    if (HookWriteCode(from, code.data(), code.size())) {
        hooked()[from] = old_content;
        return true;
    }
    return false;
}

inline auto format_address(uint8_t *from) {
    return *from == 0xe9 ? (uint8_t *) ((uint64_t) from + *(int32_t *) (from + 1) + 5) : from;
}

void ResetHook(uint8_t *from) {
    from = format_address(from);
    auto node = hooked().extract(from);
    if (node) {
        auto &original = node.mapped();
        HookWriteCode(from, original.c_str(), original.size());
    }
}

bool Hook(uint8_t *from, uint8_t *to) {
    from = format_address(from);
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