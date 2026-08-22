#include "config/InjectorHostConfig.hpp"
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

// Targets debug_getsize entry (via mid-body match + offset on Win/Linux; entry
// bytes on macOS x86_64). HotfixApis writes `ret` there so later GC-layout
// loads never run under LuaJIT.
function_relocation::MemorySignature luaRegisterDebugGetsizeSignature
        {
#ifdef _WIN32
                "4C 8B 5B 18 48 8B CB 49 8B",
                -0x27
#elif defined(__linux__)
                "48 8B 43 18 48 89 DF 48 8B 40 10",
                -0x1f
#elif defined(__APPLE__)
                "53 48 8B 47 18 8B 48 08 FF C9 83 F9 08",
                0
#else
#error "not support"
#endif
        };
