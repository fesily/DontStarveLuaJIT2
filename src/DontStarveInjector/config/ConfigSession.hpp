#pragma once
// Config cascade session: schema seed, resolve cache, current(), refresh after plugins.
// GAME_API fps/network/update live in GameRuntimeApis.cpp (not here).

#include "ResolvedConfig.hpp"
#include "ConfigSchema.hpp"

namespace ds::config {

// Declared in ResolvedConfig.hpp:
//   const ResolvedConfig *current();
//   void refresh_cascade_after_plugins(const ds::plugin::ConfigSchemaRegistry &);

} // namespace ds::config
