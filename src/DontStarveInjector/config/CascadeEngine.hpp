#pragma once
#include "ConfigSource.hpp"
#include "core/ConfigSchema.hpp"
#include "core/PluginTypes.hpp"
#include <unordered_map>
#include <string>

namespace ds::config {
struct ApplyStats {
    size_t applied = 0;
    size_t ignored_unknown = 0;
    size_t ignored_source = 0;
    size_t rejected_value = 0;
};

// Merge partial into view with whitelist + type coerce via schema.
// Coerce helpers: reuse ds::plugin::TryCoerceSaved* by converting ConfigValue,
// or accept only already-typed ConfigValue and validate type match.
ApplyStats apply_partial(
    const ds::plugin::ConfigSchemaRegistry &schema,
    ConfigSource source,
    const ds::plugin::ConfigView &partial,
    ds::plugin::ConfigView &view,
    std::unordered_map<std::string, ConfigSource> &source_of);
}
