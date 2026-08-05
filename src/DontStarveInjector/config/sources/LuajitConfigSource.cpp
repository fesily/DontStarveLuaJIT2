#include "ConfigSources.hpp"
#include "config/BaseOptionKeys.hpp"
#include "config/path/ConfigPaths.hpp"
#include "config/sources/LuajitConfigFile.hpp"
#include "plugins/plugin_core_vm/VmOptionKeys.hpp"

namespace ds::config {

ConfigSource LuajitConfigSource::id() const {
    return ConfigSource::LuajitConfig;
}

ConfigPartial LuajitConfigSource::read(CascadeContext &ctx) const {
    ConfigPartial partial;

    auto identity = path::build_mod_identity();
    if (ctx.modname.empty()) {
        ctx.modname = identity.modname;
    }
    if (ctx.modid.empty()) {
        ctx.modid = identity.modid;
    }
    if (ctx.aliases.empty()) {
        ctx.aliases = identity.aliases;
    }

    const auto config = luajit_config::read_from_file();
    if (!config) {
        // Still publish identity derived from defaults / pre-pass so view has keys
        // when schema allows LuajitConfig (empty file → no override of defaults).
        if (!ctx.modname.empty()) {
            partial.values[std::string{keys::kModname}] =
                ds::plugin::ConfigValue::string(ctx.modname);
        }
        if (!ctx.modid.empty()) {
            partial.values[std::string{keys::kModid}] =
                ds::plugin::ConfigValue::string(ctx.modid);
        }
        if (!ctx.modmain_path.empty()) {
            partial.values[std::string{keys::kModmainPath}] =
                ds::plugin::ConfigValue::string(ctx.modmain_path);
        }
        return partial;
    }

    if (!config->modmain_path.empty()) {
        ctx.modmain_path = config->modmain_path;
        // build_mod_identity already applied modmain_path into modname/modid/aliases
        ctx.modname = identity.modname;
        ctx.modid = identity.modid;
        if (ctx.aliases.empty()) {
            ctx.aliases = identity.aliases;
        }
        partial.values[std::string{keys::kModmainPath}] =
            ds::plugin::ConfigValue::string(config->modmain_path);
    }
    if (!ctx.modname.empty()) {
        partial.values[std::string{keys::kModname}] =
            ds::plugin::ConfigValue::string(ctx.modname);
    }
    if (!ctx.modid.empty()) {
        partial.values[std::string{keys::kModid}] =
            ds::plugin::ConfigValue::string(ctx.modid);
    }

    partial.values[std::string{keys::kAlwaysEnableMod}] =
        ds::plugin::ConfigValue::boolean(config->always_enable_mod);
    partial.values[std::string{keys::kDisableJITWhenServer}] =
        ds::plugin::ConfigValue::boolean(config->server_disable_luajit);
    return partial;
}


} // namespace ds::config
