#include "ConfigSources.hpp"

namespace ds::config {

ModinfoDefaultSource::ModinfoDefaultSource(const ds::plugin::ConfigSchemaRegistry &schema)
    : schema_(schema) {}

ConfigSource ModinfoDefaultSource::id() const {
    return ConfigSource::ModinfoDefault;
}

ConfigPartial ModinfoDefaultSource::read(CascadeContext &) const {
    ConfigPartial partial;
    for (const auto *entry : schema_.all()) {
        if (entry == nullptr) {
            continue;
        }
        partial.values[entry->key] = entry->default_value;
    }
    return partial;
}

} // namespace ds::config
