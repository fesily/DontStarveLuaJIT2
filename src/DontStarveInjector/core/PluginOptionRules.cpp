#include "PluginOptionRules.hpp"

namespace ds::plugin {
namespace {

bool is_bool_on(const ConfigView &config, const std::string &key) {
    auto it = config.find(key);
    if (it == config.end()) {
        return false;
    }
    const auto &v = it->second;
    if (v.type == ConfigValueType::Bool) {
        return v.b;
    }
    if (v.type == ConfigValueType::Number) {
        return v.n != 0.0;
    }
    if (v.type == ConfigValueType::String) {
        return !v.s.empty() && v.s != "off" && v.s != "false" && v.s != "0";
    }
    return false;
}

std::string get_string(const ConfigView &config, const std::string &key) {
    auto it = config.find(key);
    if (it == config.end()) {
        return {};
    }
    const auto &v = it->second;
    if (v.type == ConfigValueType::String) {
        return v.s;
    }
    if (v.type == ConfigValueType::Bool) {
        return v.b ? "true" : "false";
    }
    if (v.type == ConfigValueType::Number) {
        return std::to_string(v.n);
    }
    return {};
}

} // namespace

bool EvaluateOptionRule(const OptionRule &rule, const ConfigView &config) {
    switch (rule.kind) {
    case OptionRuleKind::AlwaysOn:
        return true;
    case OptionRuleKind::AllOf:
        if (rule.keys.empty()) {
            return true;
        }
        for (const auto &k : rule.keys) {
            if (!is_bool_on(config, k)) {
                return false;
            }
        }
        return true;
    case OptionRuleKind::AnyOf: {
        if (rule.keys.empty()) {
            return false;
        }
        for (const auto &k : rule.keys) {
            if (is_bool_on(config, k)) {
                return true;
            }
        }
        return false;
    }
    case OptionRuleKind::StringNeq:
        return get_string(config, rule.pred_key) != rule.pred_expected;
    case OptionRuleKind::StringEq:
        return get_string(config, rule.pred_key) == rule.pred_expected;
    }
    return false;
}

} // namespace ds::plugin
