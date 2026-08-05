#pragma once
// Process-wide named C-function service table (plugin service discovery).
// Write path: PluginHost::register_service during module_init registration window only.
// Read path:  ds_host_lookup_service / ds::plugin::lookup_service (always).
// Plugins MUST NOT register via a free export — Host enforces the registration point.

#include "config/InjectorHostConfig.hpp"

#include <string_view>

namespace ds::plugin {

// Internal write used by PluginHost only (and DS_PLUGIN_HOST_STATIC tests via Host).
bool register_service(std::string_view name, void *fn);

// Lookup by name; nullptr if missing.
void *lookup_service(std::string_view name);

} // namespace ds::plugin

// Cross-DLL read-only lookup for hot paths outside load() injection.
DONTSTARVEINJECTOR_API void *ds_host_lookup_service(const char *name);
