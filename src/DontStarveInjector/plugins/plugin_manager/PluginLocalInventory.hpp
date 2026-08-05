#pragma once

#include "PluginPinConfig.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ds::plugin {

// On-disk plugin discovered via sidecar meta and/or module file.
struct LocalPluginEntry {
    std::string id;                              // logical id (e.g. "debug.dummy")
    std::optional<std::string> version;          // nullopt when meta missing / unparsed
    std::optional<std::string> sha256;
    std::string module;                          // filename (e.g. plugin_dummy.dll)
    std::filesystem::path path;                  // plugins dir entry path (module or meta)
    bool has_meta = false;
    bool has_module = false;
};

// Scan plugins_dir for plugin_*.meta.json and plugin_* modules (.dll/.so/.dylib).
// Pure filesystem — takes an explicit path so unit tests can use a temp dir.
std::vector<LocalPluginEntry> scan_local_inventory(const std::filesystem::path &plugins_dir);

// DS_LUAJIT_PLUGIN_DIR env, else <injector_module_dir>/plugins (may be empty).
std::filesystem::path resolve_plugins_dir();

// Channel cache: plugin id → version from last fetched remote manifest (empty offline).
using ChannelVersionCache = std::unordered_map<std::string, std::string>;

// Status row for one plugin id.
struct PluginStatusEntry {
    std::string id;
    std::optional<std::string> local_version;
    std::optional<std::string> desired_version;
    std::optional<std::string> channel_version;
    std::optional<std::string> pin_source; // "override" | "channel"
    std::string state;                     // ok | missing | update_available | unknown
    std::string module;
    std::optional<std::string> sha256;
};

// Build full status rows from config + local inventory (+ optional channel cache).
// No network. Without channel cache, desired comes from override pins only.
std::vector<PluginStatusEntry> build_plugin_status(
    const PluginPinConfig &cfg,
    const std::vector<LocalPluginEntry> &inventory,
    const ChannelVersionCache &channel_cache = {});

// Apply plan entries: {id, from, to, reason} for version mismatches / missing preferred.
struct PlanAction {
    std::string id;
    std::optional<std::string> from; // local version or nullopt if missing
    std::string to;
    std::string reason; // version_mismatch | missing | prefer_present
};

std::vector<PlanAction> build_plan_actions(
    const PluginPinConfig &cfg,
    const std::vector<LocalPluginEntry> &inventory,
    const ChannelVersionCache &channel_cache = {});

// Known module stem → logical id (mirrors tools/gen_plugins_manifest.py MODULE_TO_ID).
std::optional<std::string> logical_id_for_module_stem(std::string_view stem);

} // namespace ds::plugin
