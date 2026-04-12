#pragma once
#include <cstdint>

void InstallRenderHooks();

#ifdef _WIN32
namespace render_hook {
    void SetRenderHookGlFunctionsWithNew();
}
#else
inline void InstallRenderHooks() {}
#endif
