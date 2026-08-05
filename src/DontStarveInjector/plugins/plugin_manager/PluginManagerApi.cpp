// plugin.manager — pin config + inventory + HTTP fetch/apply pipeline.
#include "PluginManagerApi.hpp"
#include "PluginApply.hpp"
#include "PluginLocalInventory.hpp"
#include "PluginPinConfig.hpp"

#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>

#include <mutex>
#include <string>
#include <unordered_map>

namespace {

std::mutex g_mu;
ds::plugin::PluginPinConfig g_cfg = ds::plugin::defaults();
std::string g_config_path_buf;
std::string g_status_json_buf;
std::string g_manifest_json_buf = "{}";
std::string g_plan_json_buf = "[]";
std::string g_last_error; // empty => null in status
bool g_needs_restart = false;
// Channel version cache filled by fetch_manifest.
ds::plugin::ChannelVersionCache g_channel_cache;
// Full last-fetched manifest (object); "{}" when empty.
nlohmann::json g_manifest = nlohmann::json::object();
// Resolved tag used for last successful fetch (for apply downloads).
std::string g_resolved_release_tag;

nlohmann::json status_plugins_json(const std::vector<ds::plugin::PluginStatusEntry> &rows) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto &r : rows) {
        nlohmann::json item;
        item["id"] = r.id;
        item["local_version"] =
            r.local_version.has_value() ? nlohmann::json(*r.local_version) : nlohmann::json(nullptr);
        item["desired_version"] = r.desired_version.has_value() ? nlohmann::json(*r.desired_version)
                                                                : nlohmann::json(nullptr);
        item["channel_version"] = r.channel_version.has_value() ? nlohmann::json(*r.channel_version)
                                                                : nlohmann::json(nullptr);
        item["pin_source"] =
            r.pin_source.has_value() ? nlohmann::json(*r.pin_source) : nlohmann::json(nullptr);
        item["state"] = r.state;
        item["module"] = r.module;
        item["sha256"] = r.sha256.has_value() ? nlohmann::json(*r.sha256) : nlohmann::json(nullptr);
        arr.push_back(std::move(item));
    }
    return arr;
}

nlohmann::json plan_actions_json(const std::vector<ds::plugin::PlanAction> &actions) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto &a : actions) {
        nlohmann::json item;
        item["id"] = a.id;
        item["from"] = a.from.has_value() ? nlohmann::json(*a.from) : nlohmann::json(nullptr);
        item["to"] = a.to;
        item["reason"] = a.reason;
        arr.push_back(std::move(item));
    }
    return arr;
}

void refresh_plan_locked() {
    const auto plugins_dir = ds::plugin::resolve_plugins_dir();
    const auto inv = ds::plugin::scan_local_inventory(plugins_dir);
    const auto actions = ds::plugin::build_plan_actions(g_cfg, inv, g_channel_cache);
    g_plan_json_buf = plan_actions_json(actions).dump();
}

void refresh_status_locked() {
    const auto plugins_dir = ds::plugin::resolve_plugins_dir();
    const auto inv = ds::plugin::scan_local_inventory(plugins_dir);
    const auto rows = ds::plugin::build_plugin_status(g_cfg, inv, g_channel_cache);

    nlohmann::json j;
    j["plugins"] = status_plugins_json(rows);
    j["last_error"] = g_last_error.empty() ? nlohmann::json(nullptr) : nlohmann::json(g_last_error);
    j["needs_restart"] = g_needs_restart;
    j["config_path"] = g_config_path_buf;
    j["plugins_dir"] = plugins_dir.empty() ? nlohmann::json(nullptr)
                                           : nlohmann::json(plugins_dir.generic_string());
    j["schema_version"] = g_cfg.schema_version;
    j["channel_name"] = g_cfg.channel_name;
    j["repo"] = g_cfg.repo;
    j["release_tag"] = g_cfg.release_tag;
    j["resolved_release_tag"] =
        g_resolved_release_tag.empty() ? nlohmann::json(nullptr)
                                       : nlohmann::json(g_resolved_release_tag);
    j["follow_latest"] = g_cfg.follow_latest;
    j["prefer_proxy"] = g_cfg.prefer_proxy;
    j["auto_apply_on_boot"] = g_cfg.auto_apply_on_boot;
    g_status_json_buf = j.dump();
    refresh_plan_locked();
}

void set_error_locked(std::string msg) {
    g_last_error = std::move(msg);
    refresh_status_locked();
}

void clear_error_locked() {
    g_last_error.clear();
    refresh_status_locked();
}

bool reload_locked() {
    const auto path = ds::plugin::resolve_config_path();
    g_config_path_buf = path.generic_string();
    bool ok = false;
    g_cfg = ds::plugin::load_from_file(path, &ok);
    // Missing file is not an error — defaults apply.
    if (!ok && std::filesystem::exists(path)) {
        set_error_locked("failed to parse pin config");
        return false;
    }
    clear_error_locked();
    return true;
}

bool save_locked(const ds::plugin::PluginPinConfig &cfg) {
    const auto path = ds::plugin::resolve_config_path();
    g_config_path_buf = path.generic_string();
    if (!ds::plugin::save_to_file(cfg, path)) {
        set_error_locked("failed to save pin config");
        return false;
    }
    // Caller commits g_cfg then refresh_status_locked() — avoid stale pins in status.
    g_last_error.clear();
    return true;
}

// Optional on-disk manifest cache next to pin config.
void maybe_write_manifest_cache_locked(const std::string &text) {
    try {
        const auto cfg_path = ds::plugin::resolve_config_path();
        if (cfg_path.empty()) {
            return;
        }
        const auto cache = cfg_path.parent_path() / "plugins-manifest.cache.json";
        if (!cache.parent_path().empty()) {
            std::filesystem::create_directories(cache.parent_path());
        }
        std::ofstream out(cache);
        if (out.is_open()) {
            out << text;
        }
    } catch (...) {
        // best-effort only
    }
}

} // namespace

namespace ds::plugin_manager {

void reload_pin_config() {
    std::lock_guard lock(g_mu);
    (void)reload_locked();
}

} // namespace ds::plugin_manager

DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_config_path() {
    std::lock_guard lock(g_mu);
    if (g_config_path_buf.empty()) {
        g_config_path_buf = ds::plugin::resolve_config_path().generic_string();
    }
    return g_config_path_buf.c_str();
}

DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_manager_status_json() {
    std::lock_guard lock(g_mu);
    if (g_config_path_buf.empty()) {
        g_config_path_buf = ds::plugin::resolve_config_path().generic_string();
    }
    // Always recompute: inventory + pins may change on disk without API calls.
    refresh_status_locked();
    return g_status_json_buf.c_str();
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_config_reload() {
    std::lock_guard lock(g_mu);
    return reload_locked();
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_config_set_json(const char *json) {
    if (!json) {
        std::lock_guard lock(g_mu);
        set_error_locked("config_set_json: null json");
        return false;
    }
    // Validate JSON then write via load/save path (parse lives in PluginPinConfig).
    try {
        auto j = nlohmann::json::parse(json);
        (void)j;
    } catch (...) {
        std::lock_guard lock(g_mu);
        set_error_locked("config_set_json: invalid json");
        return false;
    }

    std::lock_guard lock(g_mu);
    const auto path = ds::plugin::resolve_config_path();
    g_config_path_buf = path.generic_string();
    try {
        if (!path.parent_path().empty()) {
            std::filesystem::create_directories(path.parent_path());
        }
        std::ofstream out(path);
        if (!out.is_open()) {
            set_error_locked("config_set_json: cannot open config for write");
            return false;
        }
        out << json;
        if (!out) {
            set_error_locked("config_set_json: write failed");
            return false;
        }
    } catch (...) {
        set_error_locked("config_set_json: filesystem error");
        return false;
    }
    return reload_locked();
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_pin_set(const char *id, const char *version,
                                                          bool is_override) {
    if (!id || !id[0] || !version) {
        std::lock_guard lock(g_mu);
        set_error_locked("pin_set: missing id or version");
        return false;
    }
    std::lock_guard lock(g_mu);
    // Mutate a copy; only commit to g_cfg after disk save succeeds.
    ds::plugin::PluginPinConfig next = g_cfg;
    ds::plugin::PinEntry entry;
    entry.version = version;
    entry.source = is_override ? "override" : "channel";
    next.pins[std::string(id)] = std::move(entry);
    if (!save_locked(next)) {
        return false;
    }
    g_cfg = std::move(next);
    refresh_status_locked();
    return true;
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_pin_clear(const char *id) {
    if (!id || !id[0]) {
        std::lock_guard lock(g_mu);
        set_error_locked("pin_clear: missing id");
        return false;
    }
    std::lock_guard lock(g_mu);
    // Mutate a copy; only commit to g_cfg after disk save succeeds.
    ds::plugin::PluginPinConfig next = g_cfg;
    next.pins.erase(std::string(id));
    if (!save_locked(next)) {
        return false;
    }
    g_cfg = std::move(next);
    refresh_status_locked();
    return true;
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_fetch_manifest(const char *release_tag_or_null) {
    std::lock_guard lock(g_mu);
    std::string err;
    auto tag = ds::plugin_manager::resolve_release_tag(g_cfg, release_tag_or_null, &err);
    if (!tag) {
        set_error_locked(err.empty() ? "fetch_manifest: resolve tag failed" : err);
        return false;
    }
    auto manifest = ds::plugin_manager::fetch_plugins_manifest(g_cfg, *tag, &err);
    if (!manifest) {
        set_error_locked(err.empty() ? "fetch_manifest: download failed" : err);
        return false;
    }
    g_manifest = std::move(*manifest);
    g_manifest_json_buf = g_manifest.dump();
    g_resolved_release_tag = *tag;
    // Keep cfg.release_tag in sync when it was empty so apply can download assets.
    if (g_cfg.release_tag.empty()) {
        g_cfg.release_tag = *tag;
    }
    g_channel_cache = ds::plugin_manager::channel_cache_from_manifest(g_manifest);
    maybe_write_manifest_cache_locked(g_manifest_json_buf);
    clear_error_locked();
    return true;
}

DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_manifest_json() {
    std::lock_guard lock(g_mu);
    return g_manifest_json_buf.c_str();
}

DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_plan_apply_json() {
    std::lock_guard lock(g_mu);
    // Always recompute plan from current inventory + pins (+ channel cache).
    if (g_config_path_buf.empty()) {
        g_config_path_buf = ds::plugin::resolve_config_path().generic_string();
    }
    refresh_plan_locked();
    return g_plan_json_buf.c_str();
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_apply(const char *id_or_null) {
    std::lock_guard lock(g_mu);
    if (g_manifest.is_null() || !g_manifest.is_object() || g_manifest.empty() ||
        g_manifest_json_buf == "{}") {
        // Allow apply when plugins array missing? Require prior fetch.
        if (!g_manifest.contains("plugins")) {
            set_error_locked("apply: no manifest loaded (call fetch_manifest first)");
            return false;
        }
    }

    const auto plugins_dir = ds::plugin::resolve_plugins_dir();
    if (plugins_dir.empty()) {
        set_error_locked("apply: plugins_dir unavailable");
        return false;
    }

    // Ensure release_tag for asset URLs.
    ds::plugin::PluginPinConfig cfg = g_cfg;
    if (cfg.release_tag.empty() && !g_resolved_release_tag.empty()) {
        cfg.release_tag = g_resolved_release_tag;
    }

    const auto inv = ds::plugin::scan_local_inventory(plugins_dir);
    auto actions = ds::plugin::build_plan_actions(cfg, inv, g_channel_cache);

    const std::string only = (id_or_null && id_or_null[0]) ? std::string(id_or_null) : std::string();
    if (!only.empty()) {
        // Single-id apply: if not in plan (already ok), still force one action when manifest has it.
        bool found = false;
        for (const auto &a : actions) {
            if (a.id == only) {
                found = true;
                break;
            }
        }
        if (!found) {
            ds::plugin::PlanAction a;
            a.id = only;
            a.from = std::nullopt;
            auto it = g_channel_cache.find(only);
            a.to = it != g_channel_cache.end() ? it->second : std::string();
            a.reason = "explicit";
            actions.push_back(std::move(a));
        }
    }

    auto result = ds::plugin_manager::apply_plan(cfg, g_manifest, actions, plugins_dir, only);
    if (result.needs_restart) {
        g_needs_restart = true;
    }
    if (result.succeeded == 0) {
        set_error_locked(result.last_error.empty() ? "apply: nothing applied" : result.last_error);
        return false;
    }
    // Partial success: report last_error but return true if anything applied.
    if (!result.last_error.empty() && result.succeeded < result.attempted) {
        g_last_error = result.last_error;
    } else {
        g_last_error.clear();
    }
    refresh_status_locked();
    return true;
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_needs_restart() {
    std::lock_guard lock(g_mu);
    return g_needs_restart;
}
