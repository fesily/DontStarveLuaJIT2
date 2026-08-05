#pragma once
// core.vm service discovery helpers for peer plugins.
// Prefer PluginContext.services (Host DI at load). Hot paths may cache that
// pointer or fall back to ds_host_lookup_service — never hardcode DLL names.
#include "GameLua.hpp"
#include "core/PluginServices.hpp"
#include "core/PluginTypes.hpp"

#include <atomic>

namespace ds::core_vm {

// Stable service name registered by plugin_core_vm in ds_plugin_module_init.
inline constexpr const char *kGetGameLuaContextService = "ds_core_vm_get_game_lua_context";

using GetGameLuaContextFn = GameLuaContext &(*)();

// Process-wide cache filled by BindGameLuaContextService (typically plugin load()).
inline std::atomic<GetGameLuaContextFn> &game_lua_context_fn_cache() {
    static std::atomic<GetGameLuaContextFn> cached{nullptr};
    return cached;
}

// Prefer injected ctx.services; else lookup. Stores into process cache when found.
// Returns false if service unavailable.
inline bool BindGameLuaContextService(const ds::plugin::PluginContext *ctx = nullptr) {
    if (auto *fn = game_lua_context_fn_cache().load(std::memory_order_acquire)) {
        (void) fn;
        return true;
    }
    void *raw = nullptr;
    if (ctx) {
        auto it = ctx->services.find(kGetGameLuaContextService);
        if (it != ctx->services.end()) {
            raw = it->second;
        }
    }
    if (!raw) {
        raw = ds_host_lookup_service(kGetGameLuaContextService);
    }
    if (!raw) {
        return false;
    }
    game_lua_context_fn_cache().store(reinterpret_cast<GetGameLuaContextFn>(raw),
                                      std::memory_order_release);
    return true;
}

// nullptr when core.vm is missing / not registered (optional module).
inline GameLuaContext *TryGetGameLuaContext() {
    auto *fn = game_lua_context_fn_cache().load(std::memory_order_acquire);
    if (!fn) {
        if (!BindGameLuaContextService(nullptr)) {
            return nullptr;
        }
        fn = game_lua_context_fn_cache().load(std::memory_order_acquire);
    }
    return fn ? &fn() : nullptr;
}

} // namespace ds::core_vm
