#pragma once

#include "frida-gum.h"
#include "util/Signature.hpp"

static MemorySignature luaModuleSignature{
#ifdef _WIN32
    "41 B8 EE D8 FF FF 41 3B D0 74 64 81 FA EF D8 FF FF 74 3B", -0x37
#else
    "81 FE F1 D8 FF FF 7D 60 81 FE EF D8 FF FF 74 78 81 FE F0 D8 FF FF", -0x28
#endif
};

static MemorySignature luaRegisterDebugGetsizeSignature
{
    "4C 8B 5B 18 48 8B CB 49 8B",
#if DEBUG_GETSIZE_PATCH == 1
        0x7
#else
        -0x27
#endif
};

#if REPLACE_IO
static MemorySignature GameIOfopenSignature{"F3 A6 48 8d 4c 24 20 75 16", -0x28};

static MemorySignature GameIOfcloseSignature{"48 83 BB 58 01 00 00 00 74 10", -0x21};
#endif
