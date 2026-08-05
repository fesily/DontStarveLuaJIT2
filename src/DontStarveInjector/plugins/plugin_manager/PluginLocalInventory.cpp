#include "PluginLocalInventory.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <unordered_map>
#include <unordered_set>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace ds::plugin {
namespace {

bool iequals_ascii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool has_plugin_module_extension(const std::filesystem::path &path) {
    const auto ext = path.extension().string();
#if defined(_WIN32)
    return iequals_ascii(ext, ".dll");
#elif defined(__APPLE__)
    return ext == ".dylib" || ext == ".so";
#else
    return ext == ".so";
#endif
}

// plugin_dummy.dll / plugin_dummy.so / plugin_dummy.dylib → plugin_dummy
std::string module_stem(const std::filesystem::path &path) {
    std::string name = path.filename().string();
    // Strip known multi-part extensions first.
    static const char *kExts[] = {".dll", ".so", ".dylib"};
    for (const char *ext : kExts) {
        const size_t n = std::char_traits<char>::length(ext);
        if (name.size() > n && iequals_ascii(std::string_view(name).substr(name.size() - n), ext)) {
            name.resize(name.size() - n);
            break;
        }
    }
    return name;
}

bool is_meta_filename(std::string_view name) {
    // plugin_*.meta.json
    constexpr std::string_view suffix = ".meta.json";
    if (name.size() <= suffix.size() || !name.starts_with("plugin_")) {
        return false;
    }
    return name.ends_with(suffix);
}

std::string meta_stem(std::string_view name) {
    constexpr std::string_view suffix = ".meta.json";
    return std::string(name.substr(0, name.size() - suffix.size()));
}

std::filesystem::path injector_module_dir() {
#if defined(_WIN32)
    HMODULE mod = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&injector_module_dir), &mod) ||
        !mod) {
        return {};
    }
    wchar_t buf[MAX_PATH];
    const DWORD n = GetModuleFileNameW(mod, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return {};
    }
    return std::filesystem::path(buf).parent_path();
#else
    Dl_info info{};
    if (dladdr(reinterpret_cast<const void *>(&injector_module_dir), &info) && info.dli_fname) {
        return std::filesystem::path(info.dli_fname).parent_path();
    }
    return {};
#endif
}

struct Accum {
    LocalPluginEntry entry;
};

void merge_meta(Accum &acc, const std::filesystem::path &meta_path) {
    acc.entry.has_meta = true;
    acc.entry.path = meta_path;
    try {
        std::ifstream in(meta_path);
        if (!in.is_open()) {
            return;
        }
        nlohmann::json j;
        in >> j;
        if (j.contains("id") && j["id"].is_string()) {
            acc.entry.id = j["id"].get<std::string>();
        }
        if (j.contains("version") && j["version"].is_string()) {
            acc.entry.version = j["version"].get<std::string>();
        }
        if (j.contains("sha256") && j["sha256"].is_string()) {
            acc.entry.sha256 = j["sha256"].get<std::string>();
        }
        if (j.contains("module") && j["module"].is_string()) {
            acc.entry.module = j["module"].get<std::string>();
        }
    } catch (...) {
        // Keep partial / empty fields; version stays unknown.
    }
}

void merge_module(Accum &acc, const std::filesystem::path &module_path) {
    acc.entry.has_module = true;
    acc.entry.module = module_path.filename().string();
    if (acc.entry.path.empty()) {
        acc.entry.path = module_path;
    }
}

std::string state_for(const std::optional<std::string> &local,
                      const std::optional<std::string> &desired,
                      bool has_local_module_or_meta) {
    if (!has_local_module_or_meta) {
        if (desired.has_value()) {
            return "missing";
        }
        return "missing";
    }
    if (!local.has_value()) {
        // Present on disk but version unknown (module without meta).
        if (desired.has_value()) {
            return "unknown";
        }
        return "unknown";
    }
    if (desired.has_value() && *desired != *local) {
        return "update_available";
    }
    return "ok";
}

} // namespace

std::optional<std::string> logical_id_for_module_stem(std::string_view stem) {
    static const std::unordered_map<std::string, std::string> kMap = {
        {"plugin_core_vm", "core.vm"},
        {"plugin_dummy", "debug.dummy"},
        {"plugin_network_rpc", "network.rpc"},
        {"plugin_network_sim", "network.sim"},
        {"plugin_network_tick", "network.tick"},
        {"plugin_render_vbpool", "render.vbpool"},
        {"plugin_render_angle", "render.angle"},
        {"plugin_save_fork", "save.fork"},
        {"plugin_sim_lagcomp", "sim.lagcomp"},
        {"plugin_debug_profiler", "debug.profiler"},
        {"plugin_fps_render", "fps.render"},
        {"plugin_manager", "plugin.manager"},
    };
    auto it = kMap.find(std::string(stem));
    if (it == kMap.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<LocalPluginEntry> scan_local_inventory(const std::filesystem::path &plugins_dir) {
    std::vector<LocalPluginEntry> out;
    std::error_code ec;
    if (plugins_dir.empty() || !std::filesystem::is_directory(plugins_dir, ec)) {
        return out;
    }

    // stem → accum
    std::unordered_map<std::string, Accum> by_stem;

    for (const auto &entry : std::filesystem::directory_iterator(plugins_dir, ec)) {
        if (ec) {
            break;
        }
        if (!entry.is_regular_file(ec)) {
            continue;
        }
        const auto path = entry.path();
        const auto name = path.filename().string();

        if (is_meta_filename(name)) {
            const std::string stem = meta_stem(name);
            auto &acc = by_stem[stem];
            merge_meta(acc, path);
            if (acc.entry.id.empty()) {
                if (auto lid = logical_id_for_module_stem(stem)) {
                    acc.entry.id = *lid;
                } else {
                    acc.entry.id = stem;
                }
            }
            continue;
        }

        if (name.rfind("plugin_", 0) == 0 && has_plugin_module_extension(path)) {
            const std::string stem = module_stem(path);
            auto &acc = by_stem[stem];
            merge_module(acc, path);
            if (acc.entry.id.empty()) {
                if (auto lid = logical_id_for_module_stem(stem)) {
                    acc.entry.id = *lid;
                } else {
                    acc.entry.id = stem;
                }
            }
        }
    }

    out.reserve(by_stem.size());
    for (auto &[stem, acc] : by_stem) {
        (void)stem;
        if (acc.entry.id.empty()) {
            continue;
        }
        out.push_back(std::move(acc.entry));
    }

    std::sort(out.begin(), out.end(),
              [](const LocalPluginEntry &a, const LocalPluginEntry &b) { return a.id < b.id; });
    return out;
}

std::filesystem::path resolve_plugins_dir() {
    if (const char *env = std::getenv("DS_LUAJIT_PLUGIN_DIR"); env && *env) {
        return std::filesystem::path(env);
    }
    const auto mod_dir = injector_module_dir();
    if (!mod_dir.empty()) {
        return mod_dir / "plugins";
    }
    return {};
}

std::vector<PluginStatusEntry> build_plugin_status(const PluginPinConfig &cfg,
                                                   const std::vector<LocalPluginEntry> &inventory,
                                                   const ChannelVersionCache &channel_cache) {
    std::unordered_map<std::string, const LocalPluginEntry *> inv_by_id;
    for (const auto &e : inventory) {
        inv_by_id[e.id] = &e;
    }

    std::unordered_set<std::string> ids;
    for (const auto &e : inventory) {
        ids.insert(e.id);
    }
    for (const auto &[id, pin] : cfg.pins) {
        (void)pin;
        ids.insert(id);
    }
    for (const auto &id : cfg.prefer_present) {
        ids.insert(id);
    }

    std::vector<std::string> sorted_ids(ids.begin(), ids.end());
    std::sort(sorted_ids.begin(), sorted_ids.end());

    std::vector<PluginStatusEntry> rows;
    rows.reserve(sorted_ids.size());

    for (const auto &id : sorted_ids) {
        PluginStatusEntry row;
        row.id = id;

        auto inv_it = inv_by_id.find(id);
        const bool has_local = inv_it != inv_by_id.end();
        if (has_local) {
            const LocalPluginEntry *e = inv_it->second;
            row.local_version = e->version;
            row.module = e->module;
            row.sha256 = e->sha256;
        }

        auto cache_it = channel_cache.find(id);
        if (cache_it != channel_cache.end()) {
            row.channel_version = cache_it->second;
        }

        auto pin_it = cfg.pins.find(id);
        if (pin_it != cfg.pins.end()) {
            row.pin_source = pin_it->second.source;
        }

        row.desired_version = desired_version(cfg, id, row.channel_version);
        row.state = state_for(row.local_version, row.desired_version, has_local);
        rows.push_back(std::move(row));
    }

    return rows;
}

std::vector<PlanAction> build_plan_actions(const PluginPinConfig &cfg,
                                           const std::vector<LocalPluginEntry> &inventory,
                                           const ChannelVersionCache &channel_cache) {
    std::unordered_map<std::string, const LocalPluginEntry *> inv_by_id;
    for (const auto &e : inventory) {
        inv_by_id[e.id] = &e;
    }

    std::unordered_set<std::string> considered;
    std::vector<PlanAction> actions;

    auto maybe_add_mismatch = [&](const std::string &id, const std::string &reason_if_missing) {
        if (!considered.insert(id).second) {
            return;
        }
        std::optional<std::string> channel;
        auto cache_it = channel_cache.find(id);
        if (cache_it != channel_cache.end()) {
            channel = cache_it->second;
        }
        auto desired = desired_version(cfg, id, channel);
        if (!desired.has_value()) {
            return;
        }

        auto inv_it = inv_by_id.find(id);
        if (inv_it == inv_by_id.end()) {
            PlanAction a;
            a.id = id;
            a.from = std::nullopt;
            a.to = *desired;
            a.reason = reason_if_missing;
            actions.push_back(std::move(a));
            return;
        }

        const auto &local = inv_it->second->version;
        if (!local.has_value() || *local != *desired) {
            PlanAction a;
            a.id = id;
            a.from = local;
            a.to = *desired;
            a.reason = local.has_value() ? "version_mismatch" : "missing";
            // "missing" here means module present but version unknown — still needs apply target.
            // Prefer version_mismatch only when both sides known and differ.
            if (!local.has_value()) {
                a.reason = "missing";
            }
            actions.push_back(std::move(a));
        }
    };

    // Override / desired mismatches first (pins + channel cache).
    for (const auto &[id, pin] : cfg.pins) {
        (void)pin;
        maybe_add_mismatch(id, "missing");
    }
    for (const auto &[id, ver] : channel_cache) {
        (void)ver;
        maybe_add_mismatch(id, "missing");
    }

    // Soft prefer_present: plan fetch when missing (even without desired/channel).
    for (const auto &id : cfg.prefer_present) {
        if (considered.count(id)) {
            continue;
        }
        if (inv_by_id.count(id)) {
            continue; // present — no soft action
        }
        considered.insert(id);
        PlanAction a;
        a.id = id;
        a.from = std::nullopt;
        // Prefer override/channel desired when available; else leave to as empty? Spec wants to.
        std::optional<std::string> channel;
        auto cache_it = channel_cache.find(id);
        if (cache_it != channel_cache.end()) {
            channel = cache_it->second;
        }
        auto desired = desired_version(cfg, id, channel);
        a.to = desired.value_or("");
        a.reason = "prefer_present";
        actions.push_back(std::move(a));
    }

    std::sort(actions.begin(), actions.end(),
              [](const PlanAction &a, const PlanAction &b) { return a.id < b.id; });
    return actions;
}

} // namespace ds::plugin
