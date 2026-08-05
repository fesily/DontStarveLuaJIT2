#include "ConfigSchema.hpp"
#include "BaseOptionKeys.hpp"
#include "plugins/plugin_core_vm/VmOptionKeys.hpp"
#include "../../modinfo.hpp"


#include <algorithm>
#include <cmath>

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
           allowed_equal(a.allowed, b.allowed) &&
           ds::config::effective_sources(a.allowed_sources) ==
               ds::config::effective_sources(b.allowed_sources);
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

bool TryCoerceSavedBool(bool raw, const OptionSchemaEntry &schema, ConfigValue &out) {
    if (schema.type != ConfigValueType::Bool) {
        return false;
    }
    out = ConfigValue::boolean(raw);
    return true;
}

bool TryCoerceSavedNumber(double raw, const OptionSchemaEntry &schema, ConfigValue &out) {
    if (schema.type == ConfigValueType::Number) {
        out = ConfigValue::number(raw);
        return true;
    }
    // Bool: accept 0/1-ish numeric (save files sometimes store 0/1).
    if (schema.type == ConfigValueType::Bool) {
        out = ConfigValue::boolean(std::fabs(raw) > 0.5);
        return true;
    }
    return false;
}

bool TryCoerceSavedString(std::string_view raw, const OptionSchemaEntry &schema, ConfigValue &out) {
    if (schema.type == ConfigValueType::String) {
        if (!schema.allowed.empty()) {
            bool ok = false;
            for (const auto &a : schema.allowed) {
                if (a == raw) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                return false;
            }
        }
        out = ConfigValue::string(std::string{raw});
        return true;
    }
    // Bool: accept "true"/"false"/"0"/"1" from save/overrides.
    if (schema.type == ConfigValueType::Bool) {
        if (raw == "true" || raw == "1") {
            out = ConfigValue::boolean(true);
            return true;
        }
        if (raw == "false" || raw == "0") {
            out = ConfigValue::boolean(false);
            return true;
        }
        return false;
    }
    return false;
}

void RegisterCoreOptionSchema(ConfigSchemaRegistry &r) {
    constexpr auto kLuajitOnly =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::LuajitConfig);
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kAlwaysEnableMod};
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(ModConfigurationOptions::AlwaysEnableMod.default_value);
        e.allowed_sources = ds::config::kConfigSourceAll;
        (void) r.add(std::move(e));
    }
    // D7 identity keys — path/name identity owned by L0, tight sources.
    // VM keys (LuaVmType / EnabledGenGC / DisableJITWhenServer) are owned by
    // plugin_core_vm via RegisterCoreVmOptionSchema (OB-S2).
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kModmainPath};
        e.type = ConfigValueType::String;
        e.default_value = ConfigValue::string("");
        e.allowed_sources = kLuajitOnly;
        (void) r.add(std::move(e));
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kModname};
        e.type = ConfigValueType::String;
        e.default_value = ConfigValue::string("");
        e.allowed_sources = kLuajitOnly;
        (void) r.add(std::move(e));
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kModid};
        e.type = ConfigValueType::String;
        e.default_value = ConfigValue::string("");
        e.allowed_sources = kLuajitOnly;
        (void) r.add(std::move(e));
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kSaveFile};
        e.type = ConfigValueType::String;
        e.default_value = ConfigValue::string("");
        // Save path is discovered by the SaveFile layer (client) after identity.
        e.allowed_sources =
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile);
        (void) r.add(std::move(e));
    }
}

void RegisterCoreVmOptionSchema(ConfigSchemaRegistry &r) {
    constexpr auto kDefaultSaveEnv =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kDisableJITWhenServer};
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(ModConfigurationOptions::DisableJITWhenServer.default_value);
        e.allowed_sources = ds::config::kConfigSourceAll;
        (void) r.add(std::move(e));
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kLuaVmType};
        e.type = ConfigValueType::String;
        e.default_value = ConfigValue::string(std::string{ModConfigurationOptions::LuaVmType.default_value});
        // modinfo UI options are jit/game; env/cmd also accepts historical aliases
        // that GameLuaTypeFromString understands (lua51/51/5.1/_51/jit_gen).
        for (const auto &opt : ModConfigurationOptions::LuaVmType.options) {
            e.allowed.emplace_back(opt);
        }
        for (const char *alias : {"lua51", "51", "5.1", "_51", "jit_gen"}) {
            e.allowed.emplace_back(alias);
        }
        e.allowed_sources = ds::config::kConfigSourceAll;
        (void) r.add(std::move(e));
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kEnabledGenGC};
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(ModConfigurationOptions::EnabledGenGC.default_value);
        // Spec §2.2 / CF-S5: not from LuajitConfig file.
        e.allowed_sources = kDefaultSaveEnv;
        (void) r.add(std::move(e));
    }
}


void RegisterBuiltinBusinessOptionSchema(ConfigSchemaRegistry &r) {
    constexpr auto kDefaultSaveEnv =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    {
        OptionSchemaEntry e;
        e.key = std::string{ModConfigurationOptions::AngleBackend.name};
        e.type = ConfigValueType::String;
        e.default_value = ConfigValue::string(std::string{ModConfigurationOptions::AngleBackend.default_value});
        for (const auto &opt : ModConfigurationOptions::AngleBackend.options) {
            e.allowed.emplace_back(opt);
        }
        e.allowed_sources = kDefaultSaveEnv;
        (void) r.add(std::move(e));
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ModConfigurationOptions::EnableVBPool.name};
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(ModConfigurationOptions::EnableVBPool.default_value);
        e.allowed_sources = kDefaultSaveEnv;
        (void) r.add(std::move(e));
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ModConfigurationOptions::NetworkOpt.name};
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(ModConfigurationOptions::NetworkOpt.default_value);
        e.allowed_sources = kDefaultSaveEnv;
        (void) r.add(std::move(e));
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ModConfigurationOptions::EnableNetSim.name};
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(ModConfigurationOptions::EnableNetSim.default_value);
        e.allowed_sources = kDefaultSaveEnv;
        (void) r.add(std::move(e));
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ModConfigurationOptions::EnableForkSave.name};
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(ModConfigurationOptions::EnableForkSave.default_value);
        e.allowed_sources = kDefaultSaveEnv;
        (void) r.add(std::move(e));
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ModConfigurationOptions::EnableLagCompensation.name};
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(ModConfigurationOptions::EnableLagCompensation.default_value);
        e.allowed_sources = kDefaultSaveEnv;
        (void) r.add(std::move(e));
    }
}


} // namespace ds::plugin
