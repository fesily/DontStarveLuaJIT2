#pragma once
#include "platform.hpp"

#include <cstdint>
#include <array>
#include <cassert>
#include <stddef.h>


inline auto format_address(uint8_t *from) {
    return *from == 0xe9 ? (uint8_t *) ((uint64_t) from + *(int32_t *) (from + 1) + 5) : from;
}

DS_PLATFORM_API bool HookWriteCode(void *from, const void *code, size_t len);

DS_PLATFORM_API void ResetHook(uint8_t *from);

DS_PLATFORM_API bool HookByReg(uint8_t *from, uint8_t *to);

DS_PLATFORM_API bool Hook(uint8_t *from, uint8_t *to);