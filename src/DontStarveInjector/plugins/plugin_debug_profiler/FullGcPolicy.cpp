// plugin_debug_profiler — FullGC state + policy (moved from plugin_core_vm/gameio).
#include "FullGcPolicy.hpp"

#ifndef DISABLE_TRACY_FUTURE
#include <tracy/Tracy.hpp>
#else
#define ZoneScopedN(...)
#endif

namespace ds::profiler {
namespace {

bool g_fullgc_deferred_enabled = false;
int g_fullgc_deferred = 0; /* 0=idle, 1=phase1, 2=phase2 */

} // namespace

void set_fullgc_deferred_enabled(bool enable) {
    g_fullgc_deferred_enabled = enable;
}

bool fullgc_deferred_enabled() {
    return g_fullgc_deferred_enabled;
}

int fullgc_deferred_get() {
    return g_fullgc_deferred;
}

void fullgc_deferred_set(int v) {
    g_fullgc_deferred = v;
}

int fullgc_deferred_inc() {
    return ++g_fullgc_deferred;
}

} // namespace ds::profiler
DS_PROFILER_C_API void lj_gc_fullgc_external(void *L, void (*oldfn)(void *L)) {
    if (!ds::profiler::fullgc_deferred_enabled()) {
        ZoneScopedN("lua_full_gc");
        if (oldfn) {
            oldfn(L);
        }
    } else {
        ds::profiler::fullgc_deferred_set(1);
    }
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_disable_fullgc(bool enable) {
    ds::profiler::set_fullgc_deferred_enabled(enable);
}
