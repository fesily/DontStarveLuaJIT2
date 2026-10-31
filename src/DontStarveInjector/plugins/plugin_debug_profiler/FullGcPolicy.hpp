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

// C exports: core.vm forwards the fullgc service here; GameLuaModule trampolines disable_fullgc.
//
// Do NOT name this callback `lj_gc_fullgc_external`. LuaJIT exports a *data* symbol with that
// exact name (`LUA_DATA_API void (*lj_gc_fullgc_external)(lua_State*, void* oldfn)`, lj_api.c),
// and liblua51DS keeps that variable in its export table with default visibility, so its own
// reference goes through a preemptible GOT entry. This module is dlopen'd with RTLD_GLOBAL (in
// practice before the VM is mapped), so a global C function of the same name wins that lookup:
// `lua_gc` loads the GOT (our code address), dereferences it as a function pointer (reading our
// prologue's first 8 bytes, f3 0f 1e fa 41 57 41 56) and `call`s that -> SIGSEGV at a
// non-canonical address on every LUA_GCCOLLECT, i.e. on every full GC. The name must therefore
// never be reused, whatever the load order. The service key stays "lj_gc_fullgc_external"
// because core.vm looks it up by string. See CHANGELOG.
#if defined(_WIN32)
#  define DS_PROFILER_C_API extern "C" __declspec(dllexport)
#else
#  define DS_PROFILER_C_API extern "C" __attribute__((visibility("default")))
#endif
DS_PROFILER_C_API void ds_profiler_lj_gc_fullgc_cb(void *L, void (*oldfn)(void *L));
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_disable_fullgc(bool enable);
