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

// Register L0 base option schema: identity string keys
// (modmain_path, modname, modid, save_file) with normative allowed_sources.
// L0 identity only. Idempotent on conflict-free re-add.
void RegisterCoreOptionSchema(ConfigSchemaRegistry &r);

// L0 seed of the VM domain keys (LuaVmType, EnabledGenGC, DisableJITWhenServer).
// Seeded into the cascade schema up front (ConfigSession.cpp) so a resolve that
// happens before plugin_core_vm's ds_plugin_module_init — or on a start where
// that module was skipped — still sees the keys: apply_partial() drops unknown
// keys, which used to lose `lua_vm_type` / modinfo default / modoverrides and
// leave the VM unresolved. plugin_core_vm registers the identical entries, so
// ConfigSchemaRegistry::add() stays idempotent.
void RegisterCoreVmOptionSchema(ConfigSchemaRegistry &r);

// Business keys (AngleBackend, EnableVBPool, NetworkOpt, EnableNetSim,
// EnableForkSave, EnableLagCompensation) are owned by their plugins'
// ds_plugin_module_init. Cascade merges them via refresh_cascade_after_plugins
// after DynamicPluginLoader; L0 does not seed business schema (OB-S4).

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
