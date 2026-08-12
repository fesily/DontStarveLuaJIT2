#pragma once

// Thin wrappers for the Frida-gum interceptor API used by this project.
// Requires the staged header from 3rd/frida-gum-src (submodule) builds:
//   attach(self, target, listener, const GumAttachOptions*)
//   replace(self, target, replacement, original**, const GumReplaceOptions*)
//   replace_fast(self, target, replacement, original**, const GumInterceptorOptions*)
//
// Do not support legacy amalgamations that used GumAttachFlags / 4-arg
// replace_fast. Rebuild stage: DS_FRIDA_GUM_FORCE_MESON=1 tools/setup_frida_gum.py

#include <frida-gum.h>

namespace ds::gum {

inline GumAttachReturn attach(GumInterceptor *interceptor, gpointer target, GumInvocationListener *listener,
                              gpointer listener_function_data = nullptr) {
    if (listener_function_data != nullptr) {
        GumAttachOptions opts{};
        opts.listener_function_data = listener_function_data;
        return gum_interceptor_attach(interceptor, target, listener, &opts);
    }
    return gum_interceptor_attach(interceptor, target, listener, nullptr);
}

inline GumReplaceReturn replace(GumInterceptor *interceptor, gpointer target, gpointer replacement,
                                gpointer *original) {
    return gum_interceptor_replace(interceptor, target, replacement, original, nullptr);
}

inline GumReplaceReturn replace_fast(GumInterceptor *interceptor, gpointer target, gpointer replacement,
                                     gpointer *original) {
    return gum_interceptor_replace_fast(interceptor, target, replacement, original, nullptr);
}

} // namespace ds::gum
