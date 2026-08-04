#include "ConfigSources.hpp"
#include "SaveParse.hpp"
#include "config/ConfigPathAccess.hpp"

#include <spdlog/spdlog.h>

namespace ds::config {

SaveFileSource::SaveFileSource(const ds::plugin::ConfigSchemaRegistry &schema)
    : schema_(schema) {}

ConfigSource SaveFileSource::id() const {
    return ConfigSource::SaveFile;
}

ConfigPartial SaveFileSource::read(CascadeContext &ctx) const {
    ConfigPartial partial;
    if (!ctx.is_client) {
        return partial;
    }

    auto identity = path::build_mod_identity();
    if (ctx.aliases.empty()) {
        ctx.aliases = identity.aliases;
    }
    if (ctx.modname.empty()) {
        ctx.modname = identity.modname;
    }
    if (ctx.modid.empty()) {
        ctx.modid = identity.modid;
    }

    const auto ownid = std::to_string(ctx.steam_account_id);
    auto mod_config_data = path::GetModConfigDataDir(ownid);
    auto canonical_save_path =
        mod_config_data / path::GetModConfigDataFileName(identity.canonical_modname);
    spdlog::info("resolved client mod config data dir to {}", mod_config_data.string());
    spdlog::info("resolved canonical mod config save path to {}", canonical_save_path.string());
    ctx.save_file = canonical_save_path.string();

    for (const auto &alias : ctx.aliases) {
        auto candidate = mod_config_data / path::GetModConfigDataFileName(alias);
        spdlog::info("checking client mod config candidate {}", candidate.string());
        if (!std::filesystem::exists(candidate)) {
            continue;
        }
        spdlog::info("try load mod configuration from {}", candidate.string());
        ds::plugin::ConfigView values;
        if (save_parse::read_save_file(candidate, schema_, values)) {
            partial.values = std::move(values);
            break;
        }
    }
    return partial;
}

} // namespace ds::config
