#pragma once
#include "core/PluginTypes.hpp"
#include "config/ConfigSource.hpp"

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
    ds::config::ConfigSourceMask allowed_sources = ds::config::kConfigSourceAll;
};

// Forward-declared; defined below.
class ConfigSchemaRegistry;

// Pure coerce of a typed raw value into ConfigValue per schema (C-S6).
// Bool accepts bool or 0/1 number; String checks allowed when non-empty;
// Number accepts number. Returns false without writing on failure.
bool TryCoerceSavedBool(bool raw, const OptionSchemaEntry &schema, ConfigValue &out);
bool TryCoerceSavedNumber(double raw, const OptionSchemaEntry &schema, ConfigValue &out);
bool TryCoerceSavedString(std::string_view raw, const OptionSchemaEntry &schema, ConfigValue &out);

// Register L0 core option schema (AlwaysEnableMod, DisableJITWhenServer,
// LuaVmType, EnabledGenGC) plus identity string keys (modmain_path, modname,
// modid, save_file) with normative allowed_sources. Idempotent on
// conflict-free re-add.
void RegisterCoreOptionSchema(ConfigSchemaRegistry &r);

// Business keys owned by plugins (AngleBackend, EnableVBPool, NetworkOpt,
// EnableNetSim, EnableForkSave, EnableLagCompensation) with modinfo defaults —
// used by cascade save/overrides parse before Host plugins load. Masks exclude
// LuajitConfig. Plugins re-register the same entries on Host.
void RegisterBuiltinBusinessOptionSchema(ConfigSchemaRegistry &r);

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
