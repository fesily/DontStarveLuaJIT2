// plugin.manager - pin config + inventory + HTTP fetch/apply pipeline.
#include "PluginManagerApi.hpp"
#include "PluginApply.hpp"
#include "PluginLocalInventory.hpp"
#include "PluginPinConfig.hpp"

#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>

#include <atomic>
#include <cstdio>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

std::mutex g_mu;
ds::plugin::PluginPinConfig g_cfg = ds::plugin::defaults();
std::string g_config_path_buf;
std::string g_status_json_buf;
std::string g_manifest_json_buf = "{}";
std::string g_plan_json_buf = "[]";
std::string g_last_error; // empty => null in status
bool g_needs_restart = false;

// Network ops (fetch_manifest / apply) run off the game thread so UI does not freeze.
// g_busy_op is empty when idle; otherwise "fetch_manifest" or "apply".
std::string g_busy_op;
std::atomic<bool> g_fetch_in_flight{false};
std::atomic<bool> g_apply_in_flight{false};

// Progress for UI progress bar (protected by g_mu).
// phase: idle | resolve | download | install | done | error
std::string g_progress_phase;
std::string g_progress_message;
std::string g_progress_plugin_id;
size_t g_progress_current = 0;
size_t g_progress_total = 0;

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

void set_progress_locked(std::string phase, size_t current, size_t total, std::string plugin_id,
                         std::string message) {
    g_progress_phase = std::move(phase);
    g_progress_current = current;
    g_progress_total = total;
    g_progress_plugin_id = std::move(plugin_id);
    g_progress_message = std::move(message);
}

void clear_progress_locked() {
    g_progress_phase.clear();
    g_progress_message.clear();
    g_progress_plugin_id.clear();
    g_progress_current = 0;
    g_progress_total = 0;
}

void refresh_plan_locked_with_inv(const std::vector<ds::plugin::LocalPluginEntry> &inv) {
    const auto actions = ds::plugin::build_plan_actions(g_cfg, inv, g_channel_cache);
    g_plan_json_buf = plan_actions_json(actions).dump();
}

void refresh_plan_locked() {
    const auto plugins_dir = ds::plugin::resolve_plugins_dir();
    const auto inv = ds::plugin::scan_local_inventory(plugins_dir);
    refresh_plan_locked_with_inv(inv);
}

// full_inventory=true: rescan plugins dir. false: only rewrite progress/busy fields
// on top of the last status buffer (used by UI poll while network is in flight).
void refresh_status_locked(bool full_inventory = true) {
    const auto plugins_dir = ds::plugin::resolve_plugins_dir();

    nlohmann::json j;
    if (full_inventory || g_status_json_buf.empty()) {
        const auto inv = ds::plugin::scan_local_inventory(plugins_dir);
        const auto rows = ds::plugin::build_plugin_status(g_cfg, inv, g_channel_cache);
        j["plugins"] = status_plugins_json(rows);
        refresh_plan_locked_with_inv(inv);
    } else {
        // Keep last plugins/plan; only patch live fields below.
        try {
            j = nlohmann::json::parse(g_status_json_buf);
        } catch (...) {
            j = nlohmann::json::object();
            j["plugins"] = nlohmann::json::array();
        }
        if (!j.contains("plugins")) {
            j["plugins"] = nlohmann::json::array();
        }
    }

    j["last_error"] = g_last_error.empty() ? nlohmann::json(nullptr) : nlohmann::json(g_last_error);
    j["needs_restart"] = g_needs_restart;
    j["fetching"] = g_fetch_in_flight.load(std::memory_order_relaxed);
    j["applying"] = g_apply_in_flight.load(std::memory_order_relaxed);
    j["busy"] = !g_busy_op.empty();
    j["busy_op"] = g_busy_op.empty() ? nlohmann::json(nullptr) : nlohmann::json(g_busy_op);
    {
        nlohmann::json prog = nlohmann::json::object();
        prog["phase"] = g_progress_phase.empty() ? "idle" : g_progress_phase;
        prog["message"] = g_progress_message;
        prog["plugin_id"] = g_progress_plugin_id.empty() ? nlohmann::json(nullptr)
                                                         : nlohmann::json(g_progress_plugin_id);
        prog["current"] = g_progress_current;
        prog["total"] = g_progress_total;
        double pct = 0.0;
        if (g_progress_total > 0) {
            pct = static_cast<double>(g_progress_current) / static_cast<double>(g_progress_total);
            if (pct < 0.0) {
                pct = 0.0;
            }
            if (pct > 1.0) {
                pct = 1.0;
            }
        } else if (!g_busy_op.empty()) {
            pct = -1.0;
        }
        prog["percent"] = pct;
        j["progress"] = std::move(prog);
    }
    j["config_path"] = g_config_path_buf;
    j["plugins_dir"] = plugins_dir.empty() ? nlohmann::json(nullptr)
                                           : nlohmann::json(plugins_dir.generic_string());
    j["schema_version"] = g_cfg.schema_version;
    j["channel_name"] = g_cfg.channel_name;
    j["repo"] = g_cfg.repo;
    j["release_tag"] = g_cfg.release_tag;
    j["resolved_release_tag"] = g_resolved_release_tag.empty()
                                    ? nlohmann::json(nullptr)
                                    : nlohmann::json(g_resolved_release_tag);
    j["follow_latest"] = g_cfg.follow_latest;
    j["prefer_proxy"] = g_cfg.prefer_proxy;
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
    // Missing file is not an error - defaults apply.
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
    // Caller commits g_cfg then refresh_status_locked() - avoid stale pins in status.
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

// Callback for apply_plan → status progress (lock held briefly per step).
void apply_progress_cb(const ds::plugin_manager::ApplyProgress &p, void *) {
    std::lock_guard lock(g_mu);
    set_progress_locked(p.phase, p.current, p.total, p.plugin_id, p.message);
    refresh_status_locked();
}

} // namespace

namespace ds::plugin_manager {

void reload_pin_config() {
    std::lock_guard lock(g_mu);
    (void)reload_locked();
}

bool auto_apply_on_boot() {
    std::lock_guard lock(g_mu);
    return g_cfg.auto_apply_on_boot;
}

bool fetch_manifest_blocking(const char *release_tag_or_null) {
    // Synchronous path for EarlyNative auto_apply_on_boot. UI must use the
    // non-blocking DS_LUAJIT_plugin_fetch_manifest export instead.
    std::lock_guard lock(g_mu);
    if (g_fetch_in_flight.load(std::memory_order_relaxed) ||
        g_apply_in_flight.load(std::memory_order_relaxed) || !g_busy_op.empty()) {
        set_error_locked("fetch_manifest_blocking: busy");
        return false;
    }
    set_progress_locked("resolve", 0, 0, "", "resolving release tag");
    refresh_status_locked();
    std::string err;
    auto tag = resolve_release_tag(g_cfg, release_tag_or_null, &err);
    if (!tag) {
        set_progress_locked("error", 0, 0, "", err.empty() ? "resolve tag failed" : err);
        set_error_locked(err.empty() ? "fetch_manifest: resolve tag failed" : err);
        return false;
    }
    set_progress_locked("download", 0, 0, "", "downloading plugins-manifest.json");
    refresh_status_locked();
    auto manifest = fetch_plugins_manifest(g_cfg, *tag, &err);
    if (!manifest) {
        set_progress_locked("error", 0, 0, "", err.empty() ? "download failed" : err);
        set_error_locked(err.empty() ? "fetch_manifest: download failed" : err);
        return false;
    }
    g_manifest = std::move(*manifest);
    g_manifest_json_buf = g_manifest.dump();
    g_resolved_release_tag = *tag;
    if (g_cfg.release_tag.empty()) {
        g_cfg.release_tag = *tag;
    }
    g_channel_cache = channel_cache_from_manifest(g_manifest);
    maybe_write_manifest_cache_locked(g_manifest_json_buf);
    set_progress_locked("done", 1, 1, "", "manifest ready");
    clear_error_locked();
    return true;
}

// Synchronous apply used by auto_apply_on_boot (no UI).
bool apply_blocking(const char *id_or_null) {
    std::lock_guard lock(g_mu);
    if (g_manifest.is_null() || !g_manifest.is_object() || g_manifest.empty() ||
        g_manifest_json_buf == "{}") {
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
    ds::plugin::PluginPinConfig cfg = g_cfg;
    if (cfg.release_tag.empty() && !g_resolved_release_tag.empty()) {
        cfg.release_tag = g_resolved_release_tag;
    }
    const auto inv = ds::plugin::scan_local_inventory(plugins_dir);
    auto actions = ds::plugin::build_plan_actions(cfg, inv, g_channel_cache);
    const std::string only = (id_or_null && id_or_null[0]) ? std::string(id_or_null) : std::string();
    if (!only.empty()) {
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
    auto result = apply_plan(cfg, g_manifest, actions, plugins_dir, only, apply_progress_cb, nullptr);
    if (result.needs_restart) {
        g_needs_restart = true;
    }
    if (result.succeeded == 0) {
        set_error_locked(result.last_error.empty() ? "apply: nothing applied" : result.last_error);
        return false;
    }
    if (!result.last_error.empty() && result.succeeded < result.attempted) {
        g_last_error = result.last_error;
    } else {
        g_last_error.clear();
    }
    refresh_status_locked();
    return true;
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
    // While network is in flight, skip inventory rescan so UI poll never blocks
    // the game thread on disk/discovery. Progress callback already patches status.
    const bool busy = g_fetch_in_flight.load(std::memory_order_relaxed) ||
                      g_apply_in_flight.load(std::memory_order_relaxed) || !g_busy_op.empty();
    refresh_status_locked(!busy);
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
    // Non-blocking: HTTP runs on a worker thread. Poll status_json.fetching/busy/progress.
    // This function MUST return in milliseconds; if the UI freezes, check that the
    // running game loaded this DLL (full restart) and reloaded plugin_manager_screen.lua.
    const auto t0 = std::chrono::steady_clock::now();
    const std::string override_tag =
        (release_tag_or_null && release_tag_or_null[0]) ? std::string(release_tag_or_null)
                                                        : std::string();

    ds::plugin::PluginPinConfig cfg_snap;
    {
        std::lock_guard lock(g_mu);
        if (g_fetch_in_flight.load(std::memory_order_relaxed)) {
            return true; // idempotent
        }
        if (!g_busy_op.empty()) {
            set_error_locked("fetch_manifest: busy (" + g_busy_op + ")");
            return false;
        }
        g_fetch_in_flight.store(true, std::memory_order_relaxed);
        g_busy_op = "fetch_manifest";
        g_last_error.clear();
        set_progress_locked("resolve", 0, 0, "", "resolving release tag...");
        // Light refresh (busy=true path uses cache); force full once so plugins list exists.
        refresh_status_locked(true);
        cfg_snap = g_cfg;
    }

    std::thread([override_tag, cfg_snap]() mutable {
        std::string err;
        const char *tag_arg = override_tag.empty() ? nullptr : override_tag.c_str();
        {
            std::lock_guard lock(g_mu);
            set_progress_locked("resolve", 0, 0, "", "resolving release tag...");
            refresh_status_locked();
        }
        auto tag = ds::plugin_manager::resolve_release_tag(cfg_snap, tag_arg, &err);
        if (!tag) {
            std::lock_guard lock(g_mu);
            g_busy_op.clear();
            g_fetch_in_flight.store(false, std::memory_order_relaxed);
            set_progress_locked("error", 0, 0, "", err.empty() ? "resolve tag failed" : err);
            set_error_locked(err.empty() ? "fetch_manifest: resolve tag failed" : err);
            return;
        }
        {
            std::lock_guard lock(g_mu);
            set_progress_locked("download", 0, 0, "", "downloading plugins-manifest.json...");
            refresh_status_locked();
        }
        auto manifest = ds::plugin_manager::fetch_plugins_manifest(cfg_snap, *tag, &err);
        if (!manifest) {
            std::lock_guard lock(g_mu);
            g_busy_op.clear();
            g_fetch_in_flight.store(false, std::memory_order_relaxed);
            set_progress_locked("error", 0, 0, "", err.empty() ? "download failed" : err);
            set_error_locked(err.empty() ? "fetch_manifest: download failed" : err);
            return;
        }

        std::lock_guard lock(g_mu);
        g_manifest = std::move(*manifest);
        g_manifest_json_buf = g_manifest.dump();
        g_resolved_release_tag = *tag;
        if (g_cfg.release_tag.empty()) {
            g_cfg.release_tag = *tag;
        }
        g_channel_cache = ds::plugin_manager::channel_cache_from_manifest(g_manifest);
        maybe_write_manifest_cache_locked(g_manifest_json_buf);
        g_busy_op.clear();
        g_fetch_in_flight.store(false, std::memory_order_relaxed);
        set_progress_locked("done", 1, 1, "", "manifest ready");
        clear_error_locked();
    }).detach();

    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    std::fprintf(stderr, "[plugin_manager] fetch_manifest accepted in %lld ms (async)\n",
                 static_cast<long long>(ms));
    return true;
}

DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_manifest_json() {
    std::lock_guard lock(g_mu);
    return g_manifest_json_buf.c_str();
}

DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_plan_apply_json() {
    std::lock_guard lock(g_mu);
    if (g_config_path_buf.empty()) {
        g_config_path_buf = ds::plugin::resolve_config_path().generic_string();
    }
    refresh_plan_locked();
    return g_plan_json_buf.c_str();
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_apply(const char *id_or_null) {
    // Non-blocking: downloads + install run on a worker. Poll status.applying/progress.
    const std::string only =
        (id_or_null && id_or_null[0]) ? std::string(id_or_null) : std::string();

    ds::plugin::PluginPinConfig cfg;
    nlohmann::json manifest;
    std::filesystem::path plugins_dir;
    std::vector<ds::plugin::PlanAction> actions;
    {
        std::lock_guard lock(g_mu);
        if (g_apply_in_flight.load(std::memory_order_relaxed)) {
            return true; // already applying
        }
        if (!g_busy_op.empty()) {
            set_error_locked("apply: busy (" + g_busy_op + ")");
            return false;
        }
        if (g_manifest.is_null() || !g_manifest.is_object() || g_manifest.empty() ||
            g_manifest_json_buf == "{}") {
            if (!g_manifest.contains("plugins")) {
                set_error_locked("apply: no manifest loaded (call fetch_manifest first)");
                return false;
            }
        }
        plugins_dir = ds::plugin::resolve_plugins_dir();
        if (plugins_dir.empty()) {
            set_error_locked("apply: plugins_dir unavailable");
            return false;
        }
        cfg = g_cfg;
        if (cfg.release_tag.empty() && !g_resolved_release_tag.empty()) {
            cfg.release_tag = g_resolved_release_tag;
        }
        manifest = g_manifest;
        const auto inv = ds::plugin::scan_local_inventory(plugins_dir);
        actions = ds::plugin::build_plan_actions(cfg, inv, g_channel_cache);
        if (!only.empty()) {
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
        g_apply_in_flight.store(true, std::memory_order_relaxed);
        g_busy_op = "apply";
        g_last_error.clear();
        set_progress_locked("download", 0, actions.size(), "", "starting apply...");
        refresh_status_locked();
    }

    std::thread([cfg = std::move(cfg), manifest = std::move(manifest),
                 plugins_dir = std::move(plugins_dir), actions = std::move(actions),
                 only]() mutable {
        auto result = ds::plugin_manager::apply_plan(cfg, manifest, actions, plugins_dir, only,
                                                     apply_progress_cb, nullptr);
        std::lock_guard lock(g_mu);
        if (result.needs_restart) {
            g_needs_restart = true;
        }
        g_busy_op.clear();
        g_apply_in_flight.store(false, std::memory_order_relaxed);
        if (result.succeeded == 0) {
            set_progress_locked("error", result.attempted, result.attempted, "",
                                result.last_error.empty() ? "nothing applied" : result.last_error);
            set_error_locked(result.last_error.empty() ? "apply: nothing applied"
                                                       : result.last_error);
            return;
        }
        if (!result.last_error.empty() && result.succeeded < result.attempted) {
            g_last_error = result.last_error;
            set_progress_locked("done", result.succeeded, result.attempted, "",
                                "partial: " + result.last_error);
        } else {
            g_last_error.clear();
            set_progress_locked("done", result.succeeded, result.attempted, "",
                                "applied " + std::to_string(result.succeeded) + "/" +
                                    std::to_string(result.attempted));
        }
        refresh_status_locked();
    }).detach();

    return true;
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_needs_restart() {
    std::lock_guard lock(g_mu);
    return g_needs_restart;
}
