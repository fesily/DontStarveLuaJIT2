#include "ConfigSources.hpp"
#include "SaveParse.hpp"
#include "config/BaseOptionKeys.hpp"
#include "config/path/ConfigPaths.hpp"

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

    // Fallback: when the account id is unknown (steam hook captured nothing yet) or
    // the resolved directory simply does not exist, scan sibling user directories
    // under DoNotStarveTogether for one that already holds a saved configuration for
    // this mod, preferring the most recently modified file. This keeps per-mod
    // settings (e.g. AngleBackend) working even when the primary lookup misses.
    if (ctx.steam_account_id == 0 || !std::filesystem::is_directory(mod_config_data)) {
        std::filesystem::path best_dir;
        std::filesystem::file_time_type best_mtime{};
        const auto dst_root = path::GetKleiSaveDataDir("");
        std::error_code ec;
        if (std::filesystem::is_directory(dst_root, ec)) {
            for (const auto &entry : std::filesystem::directory_iterator(dst_root, ec)) {
                if (!entry.is_directory()) {
                    continue;
                }
                const auto candidate_dir =
                    entry.path() / "client_save" / "mod_config_data";
                if (!std::filesystem::is_directory(candidate_dir)) {
                    continue;
                }
                for (const auto &alias : ctx.aliases) {
                    const auto candidate =
                        candidate_dir / path::GetModConfigDataFileName(alias);
                    auto mtime = std::filesystem::last_write_time(candidate, ec);
                    if (ec || !std::filesystem::exists(candidate)) {
                        continue;
                    }
                    if (best_dir.empty() || mtime > best_mtime) {
                        best_dir = candidate_dir;
                        best_mtime = mtime;
                    }
                }
            }
        }
        if (!best_dir.empty()) {
            spdlog::info(
                "client mod config data dir '{}' not usable; falling back to scanned dir '{}'",
                mod_config_data.string(), best_dir.string());
            mod_config_data = best_dir;
        }
    }

    auto canonical_save_path =
        mod_config_data / path::GetModConfigDataFileName(identity.canonical_modname);
    spdlog::info("resolved client mod config data dir to {}", mod_config_data.string());
    spdlog::info("resolved canonical mod config save path to {}", canonical_save_path.string());
    ctx.save_file = canonical_save_path.string();
    partial.values[std::string{keys::kSaveFile}] =
        ds::plugin::ConfigValue::string(canonical_save_path.string());

    for (const auto &alias : ctx.aliases) {
        auto candidate = mod_config_data / path::GetModConfigDataFileName(alias);
        spdlog::info("checking client mod config candidate {}", candidate.string());
        if (!std::filesystem::exists(candidate)) {
            continue;
        }
        spdlog::info("try load mod configuration from {}", candidate.string());
        ds::plugin::ConfigView values;
        if (save_parse::read_save_file(candidate, schema_, values)) {
            // Preserve discovered path; merge save contents on top without dropping it.
            partial.values = std::move(values);
            partial.values[std::string{keys::kSaveFile}] =
                ds::plugin::ConfigValue::string(canonical_save_path.string());
            break;
        }
    }
    return partial;
}


} // namespace ds::config
