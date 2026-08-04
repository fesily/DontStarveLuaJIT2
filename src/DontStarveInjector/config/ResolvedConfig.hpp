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

} // namespace ds::config
