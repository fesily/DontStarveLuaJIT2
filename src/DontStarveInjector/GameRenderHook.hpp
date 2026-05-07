#pragma once
#include <cstdint>
#ifdef _WIN32
namespace render_hook {
    void SetRenderHookGlFunctionsWithNew();
}
#else
#endif
