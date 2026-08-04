#pragma once
#include "ConfigSource.hpp"
#include "IConfigSource.hpp"
#include "core/PluginTypes.hpp"

#include <string>
#include <unordered_map>

namespace ds::config {

struct ResolvedConfig {
    ds::plugin::ConfigView view;
    std::unordered_map<std::string, ConfigSource> source_of;
    CascadeContext ctx; // identity snapshot
};

// L0 cascade cache filled by GameJitModConfig::instance() load path.
// Null before first resolve. Host consumes current()->view (CF-S4).
const ResolvedConfig *current();

} // namespace ds::config
