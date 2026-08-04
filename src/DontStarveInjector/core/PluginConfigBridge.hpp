#pragma once

#include "ConfigSchema.hpp"
#include "PluginTypes.hpp"
#include "gameModConfig.hpp"

namespace ds::plugin {

// Merge order (C-S3):
//   1. schema defaults for each registered entry
//   2. business overlay (save/overrides/env extras; or core.business_options when
//      the third argument is default-empty and core carries them)
//   3. core GameJitModConfig fields always written
// Temporary NetworkOpt=true only when schema did not register that key.
ConfigView BuildConfigView(const ConfigSchemaRegistry &schema,
                           const GameJitModConfig &core,
                           const ConfigView &business = {});

// Compatibility: empty schema + legacy NetworkOpt=true (via BuildConfigView fallback).
// Prefer BuildConfigView with the host schema after plugins load.
ConfigView FromGameJitModConfig(const GameJitModConfig &config);

} // namespace ds::plugin
