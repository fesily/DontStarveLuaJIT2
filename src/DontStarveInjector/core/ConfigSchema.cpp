#include "ConfigSchema.hpp"

#include <algorithm>

namespace ds::plugin {
namespace {

bool config_value_equal(const ConfigValue &a, const ConfigValue &b) {
    if (a.type != b.type) {
        return false;
    }
    switch (a.type) {
    case ConfigValueType::None:
        return true;
    case ConfigValueType::Bool:
        return a.b == b.b;
    case ConfigValueType::Number:
        return a.n == b.n;
    case ConfigValueType::String:
        return a.s == b.s;
    }
    return false;
}

bool allowed_equal(std::vector<std::string> a, std::vector<std::string> b) {
    if (a.size() != b.size()) {
        return false;
    }
    std::sort(a.begin(), a.end());
    std::sort(b.begin(), b.end());
    return a == b;
}

bool entry_equal(const OptionSchemaEntry &a, const OptionSchemaEntry &b) {
    return a.type == b.type && config_value_equal(a.default_value, b.default_value) &&
           allowed_equal(a.allowed, b.allowed);
}

} // namespace

bool ConfigSchemaRegistry::add(OptionSchemaEntry e) {
    auto it = entries_.find(e.key);
    if (it == entries_.end()) {
        entries_.emplace(e.key, std::move(e));
        return true;
    }
    return entry_equal(it->second, e);
}

const OptionSchemaEntry *ConfigSchemaRegistry::find(std::string_view key) const {
    auto it = entries_.find(std::string(key));
    if (it == entries_.end()) {
        return nullptr;
    }
    return &it->second;
}

std::vector<const OptionSchemaEntry *> ConfigSchemaRegistry::all() const {
    std::vector<const OptionSchemaEntry *> out;
    out.reserve(entries_.size());
    for (const auto &kv : entries_) {
        out.push_back(&kv.second);
    }
    return out;
}

} // namespace ds::plugin
