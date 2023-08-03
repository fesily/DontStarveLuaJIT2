#pragma once
#include <cstdint>
#include <array>
#include <cassert>

template <typename T, size_t len>
inline void HookWriteCode(uint8_t *from, std::array<T, len> code)
{
    DWORD oldProtect = 0;
    ::VirtualProtect(from, len, PAGE_EXECUTE_READWRITE, &oldProtect);
    assert(oldProtect & PAGE_EXECUTE_READ);
    memcpy(from, code.data(), len);
    ::VirtualProtect(from, len, PAGE_EXECUTE_READ, &oldProtect);
}

bool HookByReg(uint8_t *from, uint8_t *to);
bool Hook(uint8_t *from, uint8_t *to);