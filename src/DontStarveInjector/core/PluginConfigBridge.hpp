#pragma once

#include "ConfigSchema.hpp"
#include "PluginTypes.hpp"
#include "gameModConfig.hpp"

namespace ds::plugin {

// ConfigView SSOT merge for PluginHost::resolve (EarlyNative).
// Merge order:
//   1. schema defaults for each registered entry
//   2. business overlay (core.business_options, then optional extras arg)
//   3. core GameJitModConfig fields always written last
// Business keys (NetworkOpt, EnableNetSim, EnableVBPool, AngleBackend, …)
// come only from schema defaults + business_options — never invented here.
ConfigView BuildConfigView(const ConfigSchemaRegistry &schema,
                           const GameJitModConfig &core,
                           const ConfigView &business = {});

// Compatibility helper: empty schema + core/business only.
// Prefer BuildConfigView(host.option_schema(), …) after plugins load.
ConfigView FromGameJitModConfig(const GameJitModConfig &config);

} // namespace ds::plugin
