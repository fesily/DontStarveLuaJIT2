#include "CascadeEngine.hpp"

#include <algorithm>
#include <spdlog/spdlog.h>


namespace ds::config {
namespace {

bool string_value_allowed(const ds::plugin::OptionSchemaEntry &entry,
                          const ds::plugin::ConfigValue &value) {
    if (entry.allowed.empty()) {
        return true;
    }
    return std::find(entry.allowed.begin(), entry.allowed.end(), value.s) !=
           entry.allowed.end();
}

bool value_matches_schema(const ds::plugin::OptionSchemaEntry &entry,
                          const ds::plugin::ConfigValue &value) {
    if (value.type != entry.type) {
        return false;
    }
    if (value.type == ds::plugin::ConfigValueType::String &&
        !string_value_allowed(entry, value)) {
        return false;
    }
    return true;
}

} // namespace

ApplyStats apply_partial(
    const ds::plugin::ConfigSchemaRegistry &schema,
    ConfigSource source,
    const ds::plugin::ConfigView &partial,
    ds::plugin::ConfigView &view,
    std::unordered_map<std::string, ConfigSource> &source_of) {
    ApplyStats stats;
    for (const auto &[key, value] : partial) {
        const auto *entry = schema.find(key);
        if (!entry) {
            ++stats.ignored_unknown;
            continue;
        }
        if (!source_allowed(entry->allowed_sources, source)) {
            spdlog::debug("config: ignoring key '{}' from source {} (not in allowed_sources)",
                          key, static_cast<unsigned>(source));
            ++stats.ignored_source;
            continue;
        }
        if (!value_matches_schema(*entry, value)) {
            ++stats.rejected_value;
            continue;
        }
        view[key] = value;
        source_of[key] = source;
        ++stats.applied;
    }
    return stats;
}

} // namespace ds::config
