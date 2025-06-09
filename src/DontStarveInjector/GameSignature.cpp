#pragma once

#include "GameSignature.hpp"
#include <frida-gum.h>

function_relocation::MemorySignature luaModuleSignature{
#ifdef _WIN32
        "41 B8 EE D8 FF FF 41 3B D0 74 64 81 FA EF D8 FF FF 74 3B", -0x37
#elif defined(__linux__)
        "81 FE F1 D8 FF FF 7D 60 81 FE EF D8 FF FF 74 78 81 FE F0 D8 FF FF", -0x28
#elif defined(__APPLE__)
        "89 48 08 48 83 47 10 10 C3", -0xD, // luaA_pushobject
        //"3D EE D8 FF FF 74 18", -0x34     // index2adr
#else
#error "not support"
#endif
};

function_relocation::MemorySignature luaRegisterDebugGetsizeSignature
        {
#ifdef _WIN32
                "4C 8B 5B 18 48 8B CB 49 8B",
#elif defined(__linux__)
                "48 8B 43 18 48 89 DF 48 8B 40 10",
#elif defined(__APPLE__)
                "48 8B 43 18 48 8B 40 10 48 8B 70 20",
#else
#error "not support"
#endif
#if DEBUG_GETSIZE_PATCH == 1
                0x7
#else
#ifdef _WIN32
                -0x27
#elif defined(__linux__)
                -0x1f
#elif defined(__APPLE__)
                0x4
#else
#error "not support"
#endif
#endif
        };
