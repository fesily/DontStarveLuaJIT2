#pragma once
// Plugin helper: declare GameInjector Lua exports without touching Lua/sol.
#include "PluginHost.hpp"
#include "GameInjectorLuaRegistry.hpp"

namespace ds::plugin {

template <size_t N>
inline bool gi_export(PluginHost *host, const char *name, const GiType (&types)[N], void *fn) {
    return host && host->register_game_injector_export(name, types, N, fn);
}

// DS_GI_EXPORT(host, DS_LUAJIT_foo, GiType::Void, GiType::Bool)
#define DS_GI_EXPORT(host, c_fn, ...) \
    ::ds::plugin::gi_export( \
        (host), #c_fn, \
        ::ds::plugin::GiType[]{__VA_ARGS__}, \
        reinterpret_cast<void *>(&(c_fn)))

} // namespace ds::plugin
