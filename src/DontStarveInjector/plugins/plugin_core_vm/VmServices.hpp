#pragma once
// core.vm service discovery helpers for peer plugins.
// Uses host PluginServices (ds_host_lookup_service) — never hardcodes DLL names.
#include "GameLua.hpp"
#include "core/PluginServices.hpp"

#include <atomic>

namespace ds::core_vm {

// Stable service name registered by plugin_core_vm in ds_plugin_module_init.
inline constexpr const char *kGetGameLuaContextService = "ds_core_vm_get_game_lua_context";

using GetGameLuaContextFn = GameLuaContext &(*)();

// nullptr when core.vm is missing / not registered (optional module).
inline GameLuaContext *TryGetGameLuaContext() {
    static std::atomic<GetGameLuaContextFn> cached{nullptr};
    if (auto *fn = cached.load(std::memory_order_acquire)) {
        return &fn();
    }
    auto *raw = ds_host_lookup_service(kGetGameLuaContextService);
    if (!raw) {
        return nullptr;
    }
    auto *fn = reinterpret_cast<GetGameLuaContextFn>(raw);
    cached.store(fn, std::memory_order_release);
    return &fn();
}

} // namespace ds::core_vm
