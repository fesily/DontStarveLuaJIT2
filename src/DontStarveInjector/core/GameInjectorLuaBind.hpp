#pragma once
// Plugin helper: declare GameInjector Lua exports without touching Lua/sol.
#include "PluginHost.hpp"
#include "GameInjectorLuaRegistry.hpp"

namespace ds::plugin {

inline bool gi_export(PluginHost *host, const char *name, GiSig sig, void *fn) {
    return host && host->register_game_injector_export(name, sig, fn);
}

// Convenience: export under the same name as a C identifier string.
#define DS_GI_EXPORT(host, c_fn, sig) \
    ::ds::plugin::gi_export((host), #c_fn, ::ds::plugin::GiSig::sig, reinterpret_cast<void *>(&(c_fn)))

} // namespace ds::plugin
