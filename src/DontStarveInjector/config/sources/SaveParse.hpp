#pragma once
#include "core/ConfigSchema.hpp"
#include "core/PluginTypes.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace ds::config::save_parse {

// Parse client modconfiguration table into a ConfigView of coerced schema keys.
// Returns false if the file cannot be loaded/parsed as a table.
bool read_save_file(const std::filesystem::path &path,
                    const ds::plugin::ConfigSchemaRegistry &schema,
                    ds::plugin::ConfigView &out);

// Parse server modoverrides.lua for the first matching alias.
// Returns false if file missing/unreadable or no mod entry found.
// Returns true with possibly-empty out when entry has no configuration_options.
bool read_modoverrides(const std::filesystem::path &path,
                       const std::vector<std::string> &aliases,
                       const ds::plugin::ConfigSchemaRegistry &schema,
                       ds::plugin::ConfigView &out);

} // namespace ds::config::save_parse
