#pragma once
// Plugin helper macros — schema auto-deduced from the function pointer.
#include "PluginHost.hpp"

namespace ds::plugin {

// host->register_game_injector_export("DS_LUAJIT_foo", &DS_LUAJIT_foo);
// or:
#define DS_GI_EXPORT(host, c_fn) \
    (host)->register_game_injector_export(#c_fn, &c_fn)

#define DS_SVC_REGISTER(host, c_fn) \
    (host)->register_service(#c_fn, &c_fn)

} // namespace ds::plugin
