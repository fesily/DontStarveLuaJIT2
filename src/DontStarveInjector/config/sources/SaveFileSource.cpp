#include "ConfigSources.hpp"
#include "SaveParse.hpp"
#include "config/BaseOptionKeys.hpp"
#include "config/path/ConfigPaths.hpp"
#include "util/PathText.hpp"

#include <exception>
#include <spdlog/fmt/std.h>
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
    spdlog::info("resolved client mod config data dir to {}", mod_config_data);
    spdlog::info("resolved canonical mod config save path to {}",
                 canonical_save_path);
    // The save-file key is consumed by narrow filesystem APIs: keep ANSI when it
    // maps and fall back to UTF-8 instead of throwing.
    const auto save_file = util::path_to_native_lossy(canonical_save_path);
    ctx.save_file = save_file;
    partial.values[std::string{keys::kSaveFile}] = ds::plugin::ConfigValue::string(save_file);

    for (const auto &alias : ctx.aliases) {
        auto candidate = mod_config_data / path::GetModConfigDataFileName(alias);
        try {
            spdlog::info("checking client mod config candidate {}", candidate);
            if (!std::filesystem::exists(candidate)) {
                continue;
            }
            spdlog::info("try load mod configuration from {}", candidate);
            ds::plugin::ConfigView values;
            if (save_parse::read_save_file(candidate, schema_, values)) {
                // Preserve discovered path; merge save contents on top without dropping it.
                partial.values = std::move(values);
                partial.values[std::string{keys::kSaveFile}] =
                    ds::plugin::ConfigValue::string(save_file);
                break;
            }
        } catch (const std::exception &e) {
            // Unrepresentable save-folder names must not abort the cascade.
            spdlog::warn("client mod config candidate {} skipped: {}",
                         candidate, e.what());
        }
    }
    return partial;
}


} // namespace ds::config
