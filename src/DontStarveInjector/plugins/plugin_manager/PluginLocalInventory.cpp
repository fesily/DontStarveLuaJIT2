#include "PluginLocalInventory.hpp"
#include "PluginApply.hpp"  // DS_PLUGIN_BUILD_CONFIG / kBuildConfigAny

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <unordered_map>
#include <unordered_set>

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

// Sidecar meta beside the module inside the package dir. `path` stays on the module
// when one exists (that is the file the loader loads), else it points at the meta.
void merge_meta(LocalPluginEntry &entry, const std::filesystem::path &meta_path) {
    entry.has_meta = true;
    if (!entry.has_module) {
        entry.path = meta_path;
    }
    try {
        std::ifstream in(meta_path);
        if (!in.is_open()) {
            return;
        }
        nlohmann::json j;
        in >> j;
        if (j.contains("id") && j["id"].is_string()) {
            entry.id = j["id"].get<std::string>();
        }
        if (j.contains("version") && j["version"].is_string()) {
            entry.version = j["version"].get<std::string>();
        }
        if (j.contains("sha256") && j["sha256"].is_string()) {
            entry.sha256 = j["sha256"].get<std::string>();
        }
        if (j.contains("module") && j["module"].is_string()) {
            entry.module = j["module"].get<std::string>();
        }
        if (j.contains("build_config") && j["build_config"].is_string()) {
            entry.build_config = j["build_config"].get<std::string>();
        }
    } catch (...) {
        // Keep partial / empty fields; version stays unknown.
    }
}

void merge_module(LocalPluginEntry &entry, const std::filesystem::path &module_path) {
    entry.has_module = true;
    entry.module = module_path.filename().string();
    entry.path = module_path;
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

// Spec "Cross-tag pin (v1)": an override pin at a version the current tag does not
// publish cannot be satisfied without a full-history search — surface it instead of
// pretending an update is available.
bool pin_unavailable_for(const PluginPinConfig &cfg, std::string_view plugin_id,
                         const std::optional<std::string> &desired,
                         const std::optional<std::string> &channel) {
    auto it = cfg.pins.find(std::string(plugin_id));
    return it != cfg.pins.end() && it->second.source == "override" && desired.has_value() &&
           channel.has_value() && *desired != *channel;
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
        {"plugin_render_shadow", "render.shadow"},
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

    // Package layout only: plugins/<stem>/<stem>.<ext> (+ <stem>.meta.json beside it).
    // Flat plugin modules at the root are unsupported (the loader ignores them), so they
    // are not part of the inventory.
    const char *module_exts[] = {".dll", ".so", ".dylib"};
    for (std::filesystem::directory_iterator it(plugins_dir, ec), end; it != end;
         it.increment(ec)) {
        if (ec) {
            break;
        }
        std::error_code probe_ec;
        if (!it->is_directory(probe_ec)) {
            continue;
        }
        const std::string stem = it->path().filename().string();
        if (!stem.starts_with("plugin_")) {
            continue;
        }
        LocalPluginEntry entry;
        entry.id = logical_id_for_module_stem(stem).value_or(stem);
        for (const char *ext : module_exts) {
            std::error_code cand_ec;
            const auto module_path = it->path() / (stem + ext);
            if (std::filesystem::is_regular_file(module_path, cand_ec)) {
                merge_module(entry, module_path);
                break;
            }
        }
        const auto meta_path = it->path() / (stem + ".meta.json");
        std::error_code meta_ec;
        if (std::filesystem::is_regular_file(meta_path, meta_ec)) {
            merge_meta(entry, meta_path);
        }
        if (entry.module.empty() && !entry.has_meta) {
            continue; // empty/unrelated dir
        }
        out.push_back(std::move(entry));
    }

    std::sort(out.begin(), out.end(),
              [](const LocalPluginEntry &a, const LocalPluginEntry &b) { return a.id < b.id; });
    return out;
}

std::filesystem::path resolve_plugins_dir() {
    // Prefer first entry of shared search policy when available.
    auto dirs = default_plugin_search_dirs();
    if (!dirs.empty()) {
        return dirs.front();
    }
    // Fallback: module-relative plugins dir even if missing on disk.
    return plugins_dir_from_module_dir(injector_module_dir());
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
            row.build_config = e->build_config;
            // Mixed trees crash at LoadLibrary; surface it instead of just failing later.
            row.build_mismatch =
                e->build_config.has_value() &&
                !ds::plugin_manager::build_config_compatible(*e->build_config,
                                                             DS_PLUGIN_BUILD_CONFIG);
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
        if (pin_unavailable_for(cfg, id, row.desired_version, row.channel_version)) {
            row.state = "pin_unavailable"; // spec: switch channel/tag first
        }
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

    // Spec "Cross-tag pin (v1)": an override asset must appear on the CURRENT channel
    // tag. Without full-history search such a pin is unsatisfiable here, so mark the
    // action (apply then refuses with "switch channel/tag first" instead of silently
    // installing the channel build).
    for (auto &a : actions) {
        auto pin_it = cfg.pins.find(a.id);
        auto ch_it = channel_cache.find(a.id);
        if (pin_it != cfg.pins.end() && pin_it->second.source == "override" &&
            ch_it != channel_cache.end() && !ch_it->second.empty() &&
            pin_it->second.version != ch_it->second) {
            a.reason = "pin_unavailable";
        }
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
