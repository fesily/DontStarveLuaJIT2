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
// Do NOT name this callback (or any other export of this module) after a symbol the game,
// LuaJIT or the host also exports. LuaJIT defines a *data* symbol `lj_gc_fullgc_external`
// (`LUA_DATA_API void (*lj_gc_fullgc_external)(lua_State*, void* oldfn)`, lj_api.c); while its
// own reference went through a preemptible GOT slot, a module loaded RTLD_GLOBAL before the VM
// could take that symbol over and `lua_gc` would then load our code address, dereference it as a
// function pointer (reading our prologue's first 8 bytes, f3 0f 1e fa 41 57 41 56) and `call`
// that -> SIGSEGV at a non-canonical address on every LUA_GCCOLLECT (DontStarveLuaJIT2#51).
// Two independent guards now exist: the VM's host-patched data symbols are PROTECTED in the ELF
// dynamic scope (luajit submodule), and plugins are loaded RTLD_LOCAL, so neither the load order
// nor a stray export can recreate it. The service key stays "lj_gc_fullgc_external" because
// core.vm looks it up by string. See CHANGELOG.
#if defined(_WIN32)
#  define DS_PROFILER_C_API extern "C" __declspec(dllexport)
#else
#  define DS_PROFILER_C_API extern "C" __attribute__((visibility("default")))
#endif
DS_PROFILER_C_API void ds_profiler_lj_gc_fullgc_cb(void *L, void (*oldfn)(void *L));
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_disable_fullgc(bool enable);
