#pragma once

// Static ANGLE IAT resolvers (ResolveStaticEglSymbol / ResolveStaticGlesSymbol)
// were removed when plugin_render_angle switched to shared libGLESv2/libEGL.
// Runtime resolution is LoadLibrary + GetProcAddress in GameOpenGl.cpp
// (EnsureAngleDllsLoaded / ResolveGameEglSymbol / ResolveGameGlesSymbol).
//
// Do not reintroduce hard references to egl*/gl* symbols here: the plugin is
// headers-only w.r.t. ANGLE and must not link import libs.

#ifdef _WIN32

#include <Windows.h>

namespace angle_iat_generated {

// Thin helper kept for any future call sites that already hold a module handle.
inline FARPROC ResolveExport(HMODULE mod, const char *name) {
    if (!mod || !name || name[0] == '\0') {
        return nullptr;
    }
    return GetProcAddress(mod, name);
}

} // namespace angle_iat_generated

#endif
