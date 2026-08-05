#pragma once
// Process-wide named C-function service table.
// Plugins register exports by stable name; core.vm / other plugins look up
// without hardcoding peer DLL names.

#include "config/InjectorHostConfig.hpp"

#include <string_view>

namespace ds::plugin {

// Register a named service. Fails (false) on null name/fn or duplicate name.
// Pointer is non-owning; caller keeps the function alive (DLL sticky is fine).
bool register_service(std::string_view name, void *fn);

// Lookup by name; nullptr if missing.
void *lookup_service(std::string_view name);

} // namespace ds::plugin

// C ABI for cross-DLL consumers (core.vm, feature plugins).
DONTSTARVEINJECTOR_API bool ds_host_register_service(const char *name, void *fn);
DONTSTARVEINJECTOR_API void *ds_host_lookup_service(const char *name);
