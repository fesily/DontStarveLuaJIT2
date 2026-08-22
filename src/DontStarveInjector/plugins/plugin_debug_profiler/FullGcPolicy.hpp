#pragma once
// plugin_debug_profiler — FullGC deferral policy ownership (Task 3).
#include "config/InjectorHostConfig.hpp"

namespace ds::profiler {

void set_fullgc_deferred_enabled(bool enable);
bool fullgc_deferred_enabled();
int fullgc_deferred_get();
void fullgc_deferred_set(int v);
int fullgc_deferred_inc();

} // namespace ds::profiler

// C exports: core.vm forwards lj_gc_fullgc_external here; GameLuaModule trampolines disable_fullgc.
#if defined(_WIN32)
#  define DS_PROFILER_C_API extern "C" __declspec(dllexport)
#else
#  define DS_PROFILER_C_API extern "C" __attribute__((visibility("default")))
#endif
DS_PROFILER_C_API void lj_gc_fullgc_external(void *L, void (*oldfn)(void *L));
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_disable_fullgc(bool enable);
