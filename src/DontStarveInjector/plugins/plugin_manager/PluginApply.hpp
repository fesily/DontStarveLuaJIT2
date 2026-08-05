#pragma once
// Fetch manifest + download/verify/extract apply pipeline for plugin.manager.

#include "PluginPinConfig.hpp"
#include "PluginLocalInventory.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ds::plugin_manager {

// Runtime platform key used in plugins-manifest platforms{}: windows|linux|macos.
std::string current_platform_key();

// Resolve release tag: explicit arg > cfg.release_tag > GitHub /releases/latest when follow_latest.
// Network via http_get_with_proxy. On failure returns nullopt and sets *err.
std::optional<std::string> resolve_release_tag(const ds::plugin::PluginPinConfig &cfg,
                                               const char *release_tag_or_null, std::string *err);

// GET plugins-manifest.json for tag; returns parsed JSON or nullopt.
std::optional<nlohmann::json> fetch_plugins_manifest(const ds::plugin::PluginPinConfig &cfg,
                                                     std::string_view release_tag, std::string *err);

// Fill channel_cache from manifest plugins[].id → version.
ds::plugin::ChannelVersionCache channel_cache_from_manifest(const nlohmann::json &manifest);

// Platform slot for plugin id from manifest (platforms[current] or first available).
// Returns {asset, sha256, module, files, version} or nullopt.
struct ManifestPluginAsset {
    std::string id;
    std::string version;
    std::string asset;
    std::string sha256; // module sha256 from manifest (verify module file after extract)
    std::string module;
    std::vector<std::string> files;
};

std::optional<ManifestPluginAsset> lookup_manifest_asset(const nlohmann::json &manifest,
                                                         std::string_view plugin_id,
                                                         std::string_view platform_key,
                                                         std::string *err);

// Download asset zip, sha256-verify module, extract allowlisted files into plugins_dir
// (or update_pending on lock). Writes/overwrites meta.json from package when present.
// Sets *needs_restart when any file lands in update_pending or replaces an existing module.
// Returns true if this plugin action fully succeeded.
bool apply_one_plugin(const ds::plugin::PluginPinConfig &cfg, const nlohmann::json &manifest,
                      const ManifestPluginAsset &asset, const std::filesystem::path &plugins_dir,
                      bool *needs_restart, std::string *err);

// Apply plan actions (id filter optional). Uses g-level helpers in Api for cache/manifest.
// Pure-ish entry for testing with injected http + temp plugins_dir.
struct ApplyResult {
    size_t attempted = 0;
    size_t succeeded = 0;
    bool needs_restart = false;
    std::string last_error;
};

ApplyResult apply_plan(const ds::plugin::PluginPinConfig &cfg, const nlohmann::json &manifest,
                       const std::vector<ds::plugin::PlanAction> &actions,
                       const std::filesystem::path &plugins_dir,
                       std::string_view only_id_or_empty);

// Install extracted files: try plugins_dir first; on open/write failure of an existing
// locked target, write to plugins_dir/update_pending/ instead.
// Returns true if all files installed (direct or pending). *used_pending set when any pending.
bool install_extracted_files(const std::filesystem::path &staging_dir,
                             const std::filesystem::path &plugins_dir,
                             const std::vector<std::string> &basenames, bool *used_pending,
                             std::string *err);

} // namespace ds::plugin_manager
