#include "ConfigSources.hpp"
#include "config/ConfigPathAccess.hpp"
#include "luajit_config.hpp"

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
    }

    partial.values["AlwaysEnableMod"] =
        ds::plugin::ConfigValue::boolean(config->always_enable_mod);
    partial.values["DisableJITWhenServer"] =
        ds::plugin::ConfigValue::boolean(config->server_disable_luajit);
    return partial;
}

} // namespace ds::config
