#include "ConfigSources.hpp"
#include "SaveParse.hpp"
#include "config/ConfigPathAccess.hpp"

#include <spdlog/spdlog.h>

namespace ds::config {

ModOverridesSource::ModOverridesSource(const ds::plugin::ConfigSchemaRegistry &schema)
    : schema_(schema) {}

ConfigSource ModOverridesSource::id() const {
    return ConfigSource::SaveFile;
}

ConfigPartial ModOverridesSource::read(CascadeContext &ctx) const {
    ConfigPartial partial;
    if (ctx.is_client) {
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

    if (!ctx.ownerdir_hint || ctx.ownerdir_hint->empty()) {
        if (ctx.steam_account_id != 0) {
            ctx.ownerdir_hint = std::to_string(ctx.steam_account_id);
        } else {
            const auto ownerdir_value = path::read_env_or_cmd_value("ownerdir");
            if (!ownerdir_value.empty()) {
                ctx.ownerdir_hint = ownerdir_value;
            }
        }
    }
    // Prefer explicit env ownerdir over steam id when present.
    if (auto ownerdir_value = path::read_env_or_cmd_value("ownerdir"); !ownerdir_value.empty()) {
        ctx.ownerdir_hint = ownerdir_value;
    }

    const auto game_info = path::GetServerGameInfo();
    spdlog::info(
        "resolved server game storage config: persist_root='{}', config_dir='{}', cluster='{}', shard='{}'",
        game_info.persist_root, game_info.config_dir, game_info.cluster_name, game_info.shared_name);
    if (ctx.ownerdir_hint && !ctx.ownerdir_hint->empty()) {
        spdlog::info("using server ownerdir hint '{}'", *ctx.ownerdir_hint);
    }

    const auto candidates = path::GetServerModOverridesPaths(game_info, ctx.ownerdir_hint);
    for (const auto &candidate : candidates) {
        spdlog::info("checking server mod overrides candidate {}", candidate.string());
        if (!std::filesystem::exists(candidate)) {
            continue;
        }
        spdlog::info("try load server mod overrides from {}", candidate.string());
        ds::plugin::ConfigView values;
        if (save_parse::read_modoverrides(candidate, ctx.aliases, schema_, values)) {
            partial.values = std::move(values);
            break;
        }
    }
    return partial;
}

} // namespace ds::config
