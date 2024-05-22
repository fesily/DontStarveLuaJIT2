#pragma once

#include "frida-gum.h"
#include "MemorySignature.hpp"

static function_relocation::MemorySignature luaModuleSignature{
#ifdef _WIN32
        "41 B8 EE D8 FF FF 41 3B D0 74 64 81 FA EF D8 FF FF 74 3B", -0x37
#else
        "81 FE F1 D8 FF FF 7D 60 81 FE EF D8 FF FF 74 78 81 FE F0 D8 FF FF", -0x28
#endif
};

static function_relocation::MemorySignature luaRegisterDebugGetsizeSignature
        {
#ifdef _WIN32
                "4C 8B 5B 18 48 8B CB 49 8B",
#else
                "48 8B 43 18 48 89 DF 48 8B 40 10",
#endif
#if DEBUG_GETSIZE_PATCH == 1
                0x7
#else
#ifdef _WIN32
                -0x27
#else
                -0x1f
#endif
#endif
        };
