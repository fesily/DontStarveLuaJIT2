#include "PluginPinConfig.hpp"

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <fstream>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace ds::plugin {
namespace {

std::filesystem::path exe_parent_parent() {
#if defined(_WIN32)
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return std::filesystem::current_path();
    }
    return std::filesystem::path(buf).parent_path().parent_path();
#else
    // Heuristic for unit tests / non-Windows: cwd when no platform helper.
    return std::filesystem::current_path();
#endif
}

PluginPinConfig parse_json(const nlohmann::json &j) {
    PluginPinConfig cfg = defaults();

    if (j.contains("schema_version") && j["schema_version"].is_number_integer()) {
        cfg.schema_version = j["schema_version"].get<int>();
    }

    if (j.contains("channel") && j["channel"].is_object()) {
        const auto &ch = j["channel"];
        if (ch.contains("repo") && ch["repo"].is_string()) {
            cfg.repo = ch["repo"].get<std::string>();
        }
        if (ch.contains("name") && ch["name"].is_string()) {
            cfg.channel_name = ch["name"].get<std::string>();
        }
        if (ch.contains("release_tag") && ch["release_tag"].is_string()) {
            cfg.release_tag = ch["release_tag"].get<std::string>();
        }
        if (ch.contains("follow_latest") && ch["follow_latest"].is_boolean()) {
            cfg.follow_latest = ch["follow_latest"].get<bool>();
        }
    }

    if (j.contains("download") && j["download"].is_object()) {
        const auto &dl = j["download"];
        if (dl.contains("github_base") && dl["github_base"].is_string()) {
            cfg.github_base = dl["github_base"].get<std::string>();
        }
        if (dl.contains("gh_proxy_base") && dl["gh_proxy_base"].is_string()) {
            cfg.gh_proxy_base = dl["gh_proxy_base"].get<std::string>();
        }
        if (dl.contains("prefer_proxy") && dl["prefer_proxy"].is_string()) {
            cfg.prefer_proxy = dl["prefer_proxy"].get<std::string>();
        }
        if (dl.contains("auto_apply_on_boot") && dl["auto_apply_on_boot"].is_boolean()) {
            cfg.auto_apply_on_boot = dl["auto_apply_on_boot"].get<bool>();
        }
    }

    if (j.contains("pins") && j["pins"].is_object()) {
        for (auto it = j["pins"].begin(); it != j["pins"].end(); ++it) {
            PinEntry entry;
            if (it.value().is_object()) {
                if (it.value().contains("version") && it.value()["version"].is_string()) {
                    entry.version = it.value()["version"].get<std::string>();
                }
                if (it.value().contains("source") && it.value()["source"].is_string()) {
                    entry.source = it.value()["source"].get<std::string>();
                } else {
                    entry.source = "channel";
                }
            }
            cfg.pins.emplace(it.key(), std::move(entry));
        }
    }

    if (j.contains("prefer_present") && j["prefer_present"].is_array()) {
        cfg.prefer_present.clear();
        for (const auto &item : j["prefer_present"]) {
            if (item.is_string()) {
                cfg.prefer_present.push_back(item.get<std::string>());
            }
        }
    }

    return cfg;
}

nlohmann::json to_json(const PluginPinConfig &cfg) {
    nlohmann::json j;
    j["schema_version"] = cfg.schema_version;
    j["channel"] = {
        {"repo", cfg.repo},
        {"name", cfg.channel_name},
        {"release_tag", cfg.release_tag},
        {"follow_latest", cfg.follow_latest},
    };
    j["download"] = {
        {"github_base", cfg.github_base},
        {"gh_proxy_base", cfg.gh_proxy_base},
        {"prefer_proxy", cfg.prefer_proxy},
        {"auto_apply_on_boot", cfg.auto_apply_on_boot},
    };
    nlohmann::json pins = nlohmann::json::object();
    for (const auto &[id, entry] : cfg.pins) {
        pins[id] = {{"version", entry.version}, {"source", entry.source}};
    }
    j["pins"] = std::move(pins);
    j["prefer_present"] = cfg.prefer_present;
    return j;
}

} // namespace

PluginPinConfig defaults() {
    return PluginPinConfig{};
}

PluginPinConfig load_from_file(const std::filesystem::path &path, bool *ok) {
    if (ok) {
        *ok = false;
    }
    if (path.empty() || !std::filesystem::exists(path)) {
        return defaults();
    }
    std::ifstream in(path);
    if (!in.is_open()) {
        return defaults();
    }
    try {
        nlohmann::json j;
        in >> j;
        PluginPinConfig cfg = parse_json(j);
        if (ok) {
            *ok = true;
        }
        return cfg;
    } catch (...) {
        return defaults();
    }
}

bool save_to_file(const PluginPinConfig &cfg, const std::filesystem::path &path) {
    try {
        if (!path.parent_path().empty()) {
            std::filesystem::create_directories(path.parent_path());
        }
        std::ofstream out(path);
        if (!out.is_open()) {
            return false;
        }
        out << to_json(cfg).dump(2);
        return static_cast<bool>(out);
    } catch (...) {
        return false;
    }
}

std::optional<std::string> desired_version(const PluginPinConfig &cfg,
                                           std::string_view plugin_id,
                                           const std::optional<std::string> &channel_version) {
    const std::string key(plugin_id);
    auto it = cfg.pins.find(key);
    if (it != cfg.pins.end() && it->second.source == "override") {
        return it->second.version;
    }
    if (channel_version.has_value()) {
        return *channel_version;
    }
    return std::nullopt;
}

std::filesystem::path default_config_path() {
    return exe_parent_parent() / "data" / "unsafedata" / "luajit_plugins.json";
}

std::filesystem::path resolve_config_path() {
    if (const char *env = std::getenv("DS_LUAJIT_PLUGINS_CONFIG"); env && env[0] != '\0') {
        return std::filesystem::path(env);
    }
    return default_config_path();
}

} // namespace ds::plugin
