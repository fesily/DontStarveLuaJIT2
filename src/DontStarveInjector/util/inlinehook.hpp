#pragma once

#include <cstdint>
#include <array>
#include <cassert>
#include <stddef.h>


inline auto format_address(uint8_t *from) {
    return *from == 0xe9 ? (uint8_t *) ((uint64_t) from + *(int32_t *) (from + 1) + 5) : from;
}

bool HookWriteCode(void *from, const void *code, size_t len);

void ResetHook(uint8_t *from);

bool HookByReg(uint8_t *from, uint8_t *to);

bool Hook(uint8_t *from, uint8_t *to);