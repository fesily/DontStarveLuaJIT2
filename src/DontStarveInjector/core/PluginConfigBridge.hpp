#pragma once

#include "ConfigSchema.hpp"
#include "PluginTypes.hpp"
#include "gameModConfig.hpp"

namespace ds::plugin {

// Dual-write ConfigView: schema defaults first, then overlay fields still present
// on GameJitModConfig (core + EnableVBPool / AngleBackend). Temporary NetworkOpt=true
// is applied only when the schema did not register that key.
ConfigView BuildConfigView(const ConfigSchemaRegistry &schema,
                           const GameJitModConfig &config);

// Compatibility: empty schema + legacy NetworkOpt=true (via BuildConfigView fallback).
// Prefer BuildConfigView with the host schema after plugins load.
ConfigView FromGameJitModConfig(const GameJitModConfig &config);

} // namespace ds::plugin
