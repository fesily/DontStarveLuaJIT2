#pragma once
#include <cstdint>
// HWBuffer pool for plugin_render_vbpool (this directory).
#ifdef _WIN32
namespace render_hook {
    void SetRenderHookGlFunctionsWithNew();
}
#endif
