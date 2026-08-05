#pragma once
// Config cascade session: schema seed, resolve cache, current(), refresh after plugins.

#include "ResolvedConfig.hpp"
#include "ConfigSchema.hpp"

namespace ds::config {

// current() — null until first resolve/refresh.
// ensure_resolved() — run cascade once if needed; returns current().
DS_INJECTOR_CXX_API const ResolvedConfig *ensure_resolved();

// refresh_cascade_after_plugins — declared on ResolvedConfig.hpp

} // namespace ds::config
