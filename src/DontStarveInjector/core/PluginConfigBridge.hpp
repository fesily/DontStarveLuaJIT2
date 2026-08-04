#pragma once

#include "ConfigSchema.hpp"
#include "PluginTypes.hpp"
#include "gameModConfig.hpp"

namespace ds::plugin {

// Merge order (C-S3 / C-S4):
//   1. schema defaults for each registered entry
//   2. business overlay (save/overrides/env extras; or core.business_options when
//      the third argument is default-empty and core carries them)
//   3. core GameJitModConfig fields always written
// NetworkOpt / EnableNetSim come from schema defaults and business_options only —
// no hardcoded NetworkOpt=true.
ConfigView BuildConfigView(const ConfigSchemaRegistry &schema,
                           const GameJitModConfig &core,
                           const ConfigView &business = {});

// Compatibility: empty schema + core/business only (no invented NetworkOpt).
// Prefer BuildConfigView with the host schema after plugins load.
ConfigView FromGameJitModConfig(const GameJitModConfig &config);

} // namespace ds::plugin
