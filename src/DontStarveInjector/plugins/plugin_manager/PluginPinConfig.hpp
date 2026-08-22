#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ds::plugin {

struct PinEntry {
    std::string version;
    std::string source; // "channel" | "override"
};

struct PluginPinConfig {
    int schema_version = 1;
    std::string repo = "fesily/DontStarveLuaJIT2";
    std::string channel_name = "stable";
    std::string release_tag;
    bool follow_latest = true;
    std::string github_base = "https://github.com";
    std::string gh_proxy_base = "https://gh-proxy.com";
    std::string prefer_proxy = "auto";
    bool auto_apply_on_boot = false;
    std::unordered_map<std::string, PinEntry> pins;
    std::vector<std::string> prefer_present; // default empty; soft preference only
};

PluginPinConfig defaults();

// Load pin config from path. Missing/invalid file => defaults.
// If ok != nullptr: *ok = true on successful parse of existing file, false otherwise.
PluginPinConfig load_from_file(const std::filesystem::path &path, bool *ok = nullptr);

bool save_to_file(const PluginPinConfig &cfg, const std::filesystem::path &path);

// Override pin wins; else channel_version when present; else nullopt.
std::optional<std::string> desired_version(const PluginPinConfig &cfg,
                                           std::string_view plugin_id,
                                           const std::optional<std::string> &channel_version);

// Default: <exe parent.parent>/data/unsafedata/luajit_plugins.json (heuristic when no exe helper).
std::filesystem::path default_config_path();

// DS_LUAJIT_PLUGINS_CONFIG env overrides; else default_config_path().
std::filesystem::path resolve_config_path();

} // namespace ds::plugin
