#pragma once
#include <cstdint>
#include <array>
#include <cassert>

bool HookWriteCode(void *from, const void *code, size_t len);
void ResetHook(uint8_t *from);
bool HookByReg(uint8_t *from, uint8_t *to);
bool Hook(uint8_t *from, uint8_t *to);