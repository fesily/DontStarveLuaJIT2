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
// plugin_core_vm registers the identical entries in ds_plugin_module_init; they
// are seeded here as well because that module can be skipped — see
// BuildCascadeSchema().
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

// Cascade schema for ds::config::resolve(): L0 identity keys plus the VM trio.
// The VM keys must be present even when plugin_core_vm's ds_plugin_module_init
// never runs: DynamicPluginLoader can skip that module (load_failed /
// abi_mismatch / missing_init / init_failed / duplicate_stem) while
// CoreVmBootstrap still maps the DLL by path and calls only
// ds_core_vm_run_signature_and_replace. apply_partial() drops unknown keys, so
// without the seed LuaVmType is lost from the `lua_vm_type` env/cmd, the modinfo
// default and modoverrides alike; get_lua_vm_type() then returns
// GameLuaType::unknown, no VM library can be picked, the injector degrades to the
// game VM and the mod asks for a restart — one extra full vanilla-Lua boot.
// plugin_core_vm re-registers the identical entries (add() compares entries), and
// refresh_cascade_after_plugins() logs any divergence instead of ignoring it.
ConfigSchemaRegistry BuildCascadeSchema();

} // namespace ds::plugin
