#pragma once
// Resolve GetGameLuaContext from optional plugin_core_vm without hard-linking the symbol.
// Used by L0 (GameProfilerHook) and feature plugins (sim.lagcomp) when core.vm is optional.
#include "config.hpp"
#include <atomic>
#include <cstdio>

#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#else
#  include <dlfcn.h>
#endif

// Forward-declare only; full type lives in GameLua.hpp (plugin_core_vm).
class GameLuaContext;

namespace ds::core_vm {

using GetGameLuaContextFn = GameLuaContext &(*)();

inline GetGameLuaContextFn ResolveGetGameLuaContext() {
    static std::atomic<GetGameLuaContextFn> cached{nullptr};
    if (auto *fn = cached.load(std::memory_order_acquire)) {
        return fn;
    }
#if defined(_WIN32)
    HMODULE h = GetModuleHandleA("plugin_core_vm.dll");
    if (!h) {
        return nullptr;
    }
    // MSVC C++ export decoration for GameLuaContext &GetGameLuaContext(void)
    // Prefer undecorated if /EXPORT or .def; also try GetProcAddress with mangled?
    // GameLua.hpp uses DS_INJECTOR_CXX_API without extern "C", so name is mangled.
    // Export via extern "C" wrapper from plugin for stable ABI.
    auto *fn = reinterpret_cast<GetGameLuaContextFn>(GetProcAddress(h, "ds_core_vm_get_game_lua_context"));
#else
    void *h = dlopen("plugin_core_vm.so", RTLD_NOLOAD | RTLD_LAZY);
#if defined(__APPLE__)
    if (!h) h = dlopen("plugin_core_vm.dylib", RTLD_NOLOAD | RTLD_LAZY);
#endif
    if (!h) {
        // Already mapped? try default
        auto *fn = reinterpret_cast<GetGameLuaContextFn>(dlsym(RTLD_DEFAULT, "ds_core_vm_get_game_lua_context"));
        if (fn) {
            cached.store(fn, std::memory_order_release);
        }
        return fn;
    }
    auto *fn = reinterpret_cast<GetGameLuaContextFn>(dlsym(h, "ds_core_vm_get_game_lua_context"));
#endif
    if (fn) {
        cached.store(fn, std::memory_order_release);
    }
    return fn;
}

inline GameLuaContext *TryGetGameLuaContext() {
    auto *fn = ResolveGetGameLuaContext();
    if (!fn) {
        return nullptr;
    }
    return &fn();
}

} // namespace ds::core_vm
