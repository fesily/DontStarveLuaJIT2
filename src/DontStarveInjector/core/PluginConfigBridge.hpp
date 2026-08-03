#pragma once

#include "PluginTypes.hpp"
#include "gameModConfig.hpp"

namespace ds::plugin {

// Build an in-memory ConfigView from already-resolved GameJitModConfig.
// Early-native option keys used by plugins (M1+): EnableVBPool, AngleBackend,
// AlwaysEnableMod, plus NetworkOpt (modinfo default until native cascade owns it).
ConfigView FromGameJitModConfig(const GameJitModConfig &config);

} // namespace ds::plugin
