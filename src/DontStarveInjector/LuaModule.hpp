#pragma once

#include "frida-gum.h"
#include "Signature.hpp"

static MemorySignature luaModuleSignature{"41 B8 EE D8 FF FF 41 3B D0 74 64 81 FA EF D8 FF FF 74 3B", -0x37};

#if DEBUG_GETSIZE_PATCH

#if DEBUG_GETSIZE_PATCH == 1
static MemorySignature luaRegisterDebugGetsizeSignature{"4C 8B 5B 18 48 8B CB 49 8B", 0x7};
#else
static MemorySignature luaRegisterDebugGetsizeSignature{"4C 8B 5B 18 48 8B CB 49 8B", -0x27};
#endif

#endif

#if REPLACE_IO
static MemorySignature GameIOfopenSignature{"F3 A6 48 8d 4c 24 20 75 16", -0x28};

static MemorySignature GameIOfcloseSignature{"48 83 BB 58 01 00 00 00 74 10", -0x21};
#endif