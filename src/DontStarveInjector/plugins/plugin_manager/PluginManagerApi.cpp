// plugin.manager — API stubs + pin-config operations (no network in Task 6).
#include "PluginManagerApi.hpp"
#include "PluginPinConfig.hpp"

#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>

#include <mutex>
#include <string>

namespace {

std::mutex g_mu;
ds::plugin::PluginPinConfig g_cfg = ds::plugin::defaults();
std::string g_config_path_buf;
std::string g_status_json_buf;
std::string g_manifest_json_buf = "{}";
std::string g_plan_json_buf = "[]";
std::string g_last_error; // empty => null in status
bool g_needs_restart = false;

void refresh_status_locked() {
    nlohmann::json j;
    j["plugins"] = nlohmann::json::array();
    j["last_error"] = g_last_error.empty() ? nlohmann::json(nullptr) : nlohmann::json(g_last_error);
    j["needs_restart"] = g_needs_restart;
    j["config_path"] = g_config_path_buf;
    j["schema_version"] = g_cfg.schema_version;
    j["channel_name"] = g_cfg.channel_name;
    j["repo"] = g_cfg.repo;
    j["auto_apply_on_boot"] = g_cfg.auto_apply_on_boot;
    g_status_json_buf = j.dump();
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

bool save_locked() {
    const auto path = ds::plugin::resolve_config_path();
    g_config_path_buf = path.generic_string();
    if (!ds::plugin::save_to_file(g_cfg, path)) {
        set_error_locked("failed to save pin config");
        return false;
    }
    clear_error_locked();
    return true;
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
    if (g_status_json_buf.empty()) {
        if (g_config_path_buf.empty()) {
            g_config_path_buf = ds::plugin::resolve_config_path().generic_string();
        }
        refresh_status_locked();
    }
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
    ds::plugin::PinEntry entry;
    entry.version = version;
    entry.source = is_override ? "override" : "channel";
    g_cfg.pins[std::string(id)] = std::move(entry);
    return save_locked();
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_pin_clear(const char *id) {
    if (!id || !id[0]) {
        std::lock_guard lock(g_mu);
        set_error_locked("pin_clear: missing id");
        return false;
    }
    std::lock_guard lock(g_mu);
    g_cfg.pins.erase(std::string(id));
    return save_locked();
}

// Task 8: HTTP fetch — stub.
DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_fetch_manifest(const char *release_tag_or_null) {
    (void)release_tag_or_null;
    std::lock_guard lock(g_mu);
    set_error_locked("fetch_manifest: not implemented (Task 8)");
    g_manifest_json_buf = "{}";
    return false;
}

DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_manifest_json() {
    std::lock_guard lock(g_mu);
    return g_manifest_json_buf.c_str();
}

// Task 7/8: plan/apply — stubs.
DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_plan_apply_json() {
    std::lock_guard lock(g_mu);
    return g_plan_json_buf.c_str();
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_apply(const char *id_or_null) {
    (void)id_or_null;
    std::lock_guard lock(g_mu);
    set_error_locked("apply: not implemented (Task 8)");
    return false;
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_needs_restart() {
    std::lock_guard lock(g_mu);
    return g_needs_restart;
}
