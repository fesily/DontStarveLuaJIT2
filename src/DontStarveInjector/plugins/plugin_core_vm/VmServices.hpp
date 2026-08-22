#pragma once
// core.vm service discovery helpers for peer plugins.
// Prefer PluginContext.services (Host DI at load). Hot paths may cache that
// pointer or fall back to typed request_service — never hardcode DLL names.
#include "GameLua.hpp"
#include "core/PluginServices.hpp"
#include "core/PluginTypes.hpp"

#include <atomic>

namespace ds::core_vm {

inline constexpr const char *kGetGameLuaContextService = "ds_core_vm_get_game_lua_context";

// Schema must match plugin_core_vm registration (LightUserdata = pointer-sized return).
inline constexpr ds::plugin::ServiceDesc<GameLuaContext &(*)()>
    kGetGameLuaContext{kGetGameLuaContextService};

using GetGameLuaContextFn = GameLuaContext &(*)();

inline std::atomic<GetGameLuaContextFn> &game_lua_context_fn_cache() {
    static std::atomic<GetGameLuaContextFn> cached{nullptr};
    return cached;
}

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
        raw = reinterpret_cast<void *>(kGetGameLuaContext.request());
    }
    if (!raw) {
        return false;
    }
    game_lua_context_fn_cache().store(reinterpret_cast<GetGameLuaContextFn>(raw),
                                      std::memory_order_release);
    return true;
}

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
