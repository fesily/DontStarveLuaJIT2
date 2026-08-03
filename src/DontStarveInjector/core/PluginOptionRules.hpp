#pragma once

#include "PluginTypes.hpp"

namespace ds::plugin {

// Returns true if the option rule considers the plugin option-enabled.
// Missing keys: bool defaults false; string defaults empty; number defaults 0.
bool EvaluateOptionRule(const OptionRule &rule, const ConfigView &config);

} // namespace ds::plugin
