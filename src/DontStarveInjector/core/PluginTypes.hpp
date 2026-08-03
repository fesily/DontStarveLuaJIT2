#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ds::plugin {

enum class PluginPhase : uint32_t {
    None           = 0,
    EarlyNative    = 1u << 0,
    AfterLuaBridge = 1u << 1,
    AfterModMain   = 1u << 2,
    OnDemand       = 1u << 3,
};

inline constexpr PluginPhase operator|(PluginPhase a, PluginPhase b) {
    return static_cast<PluginPhase>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline constexpr PluginPhase operator&(PluginPhase a, PluginPhase b) {
    return static_cast<PluginPhase>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}
inline constexpr bool has_phase(PluginPhase set, PluginPhase bit) {
    return (static_cast<uint32_t>(set) & static_cast<uint32_t>(bit)) != 0;
}

enum class PluginStatus : uint8_t {
    Registered = 0,
    Disabled,
    Failed,
    Loaded,
};

enum class PluginFailReason : uint8_t {
    None = 0,
    MissingHardDep,
    Conflict,
    Cycle,
    LoadThrew,
};

struct PluginEvent {
    std::string plugin_id;
    PluginPhase phase = PluginPhase::None;
    PluginStatus status = PluginStatus::Registered;
    PluginFailReason reason = PluginFailReason::None;
    std::string detail;
};

enum class ConfigValueType : uint8_t {
    None = 0,
    Bool,
    String,
    Number,
};

struct ConfigValue {
    ConfigValueType type = ConfigValueType::None;
    bool b = false;
    double n = 0;
    std::string s;

    static ConfigValue boolean(bool v) {
        ConfigValue c;
        c.type = ConfigValueType::Bool;
        c.b = v;
        return c;
    }
    static ConfigValue string(std::string v) {
        ConfigValue c;
        c.type = ConfigValueType::String;
        c.s = std::move(v);
        return c;
    }
    static ConfigValue number(double v) {
        ConfigValue c;
        c.type = ConfigValueType::Number;
        c.n = v;
        return c;
    }
};

using ConfigView = std::unordered_map<std::string, ConfigValue>;

enum class OptionRuleKind : uint8_t {
    AlwaysOn = 0, // no options gate (still subject to can_load)
    AllOf,
    AnyOf,
    StringNeq, // key != expected
    StringEq,  // key == expected
};

struct OptionRule {
    OptionRuleKind kind = OptionRuleKind::AlwaysOn;
    std::vector<std::string> keys; // AllOf / AnyOf
    std::string pred_key;          // StringNeq / StringEq
    std::string pred_expected;
};

struct PluginContext {
    void *injector = nullptr;
    bool is_client = true;
    const ConfigView *config = nullptr;
};

struct PluginManifest {
    std::string id;
    std::string version;
    std::vector<std::string> depends;
    std::vector<std::string> soft_depends;
    std::vector<std::string> conflicts;
    PluginPhase phases = PluginPhase::AfterModMain;
    bool support_reload = false;
    int priority = 100; // lower first within phase when topo-tied
    OptionRule options{};
};

struct IPlugin {
    virtual ~IPlugin() = default;
    virtual const PluginManifest &manifest() const = 0;
    virtual bool can_load(const PluginContext &) const = 0;
    virtual void load(PluginContext &) = 0;
    virtual void unload(PluginContext &) = 0;
};

} // namespace ds::plugin
