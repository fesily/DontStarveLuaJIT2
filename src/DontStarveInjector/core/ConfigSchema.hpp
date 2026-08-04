#pragma once
#include "PluginTypes.hpp"
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ds::plugin {

struct OptionSchemaEntry {
    std::string key;
    ConfigValueType type = ConfigValueType::None;
    ConfigValue default_value{};
    std::vector<std::string> allowed; // empty = any
};

class ConfigSchemaRegistry {
public:
    // returns false on conflict (same key, different type/default/allowed)
    bool add(OptionSchemaEntry e);
    const OptionSchemaEntry *find(std::string_view key) const;
    std::vector<const OptionSchemaEntry *> all() const;
    size_t size() const { return entries_.size(); }

private:
    std::unordered_map<std::string, OptionSchemaEntry> entries_;
};

} // namespace ds::plugin
