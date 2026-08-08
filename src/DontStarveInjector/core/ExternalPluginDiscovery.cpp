#include "ExternalPluginDiscovery.hpp"
#include "EnabledDstMods.hpp"
#include "PluginPackModinfo.hpp"

#include <cstdio>
#include <cstring>
#include <string_view>

#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

namespace ds::plugin {
namespace {

bool ieq_ascii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = static_cast<char>(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = static_cast<char>(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return false;
        }
    }
    return true;
}

const char *plugin_module_extension() {
#if defined(_WIN32)
    return ".dll";
#elif defined(__APPLE__)
    return ".dylib";
#else
    return ".so";
#endif
}

std::filesystem::path weakly_canonical_or(const std::filesystem::path &p, std::error_code &ec) {
    auto c = std::filesystem::weakly_canonical(p, ec);
    if (ec) {
        ec.clear();
        return p.lexically_normal();
    }
    return c;
}

} // namespace

bool path_under_root(const std::filesystem::path &root, const std::filesystem::path &candidate) {
    if (root.empty() || candidate.empty()) {
        return false;
    }
    std::error_code ec;
    const auto r = weakly_canonical_or(root, ec);
    const auto c = weakly_canonical_or(candidate, ec);
    auto rs = r.generic_string();
    auto cs = c.generic_string();
    if (rs.empty()) {
        return false;
    }
    // Exact match (root itself) is allowed for jail checks of the root path;
    // module candidates should still be under plugins/ — listing enforces that.
    if (ieq_ascii(rs, cs)) {
        return true;
    }
    if (rs.back() != '/') {
        rs.push_back('/');
    }
#if defined(_WIN32)
    // Case-insensitive prefix on Windows.
    if (cs.size() < rs.size()) {
        return false;
    }
    return ieq_ascii(std::string_view(cs).substr(0, rs.size()), rs);
#else
    return cs.rfind(rs, 0) == 0;
#endif
}

std::vector<std::filesystem::path> list_pack_modules_under_mod(const std::filesystem::path &mod_root) {
    std::vector<std::filesystem::path> out;
    if (mod_root.empty()) {
        return out;
    }
    const auto plugins = mod_root / "plugins";
    std::error_code ec;
    if (!std::filesystem::is_directory(plugins, ec)) {
        return out;
    }

    for (const auto &entry : std::filesystem::directory_iterator(plugins, ec)) {
        if (ec) {
            break;
        }
        if (!entry.is_directory(ec) || ec) {
            continue;
        }
        const auto stem = entry.path().filename().string();
        if (stem.rfind("plugin_", 0) != 0) {
            continue;
        }
        auto module_path = entry.path() / (stem + plugin_module_extension());
        if (!std::filesystem::is_regular_file(module_path, ec) || ec) {
#if defined(__APPLE__)
            module_path = entry.path() / (stem + std::string(".so"));
            if (!std::filesystem::is_regular_file(module_path, ec) || ec) {
                continue;
            }
#else
            continue;
#endif
        }
        if (!path_under_root(mod_root, module_path)) {
            continue;
        }
        std::error_code path_ec;
        auto abs = weakly_canonical_or(module_path, path_ec);
        out.push_back(std::move(abs));
    }
    return out;
}


ExternalDiscoverReport
discover_and_load_external_plugins(PluginHost &host, bool is_client,
                                   const std::filesystem::path &this_mod_root,
                                   ExternalModuleLoadFn load_fn) {
    ExternalDiscoverReport report;
    std::error_code ec;
    std::filesystem::path this_root_canon;
    if (!this_mod_root.empty()) {
        this_root_canon = std::filesystem::weakly_canonical(this_mod_root, ec);
        if (ec) {
            this_root_canon = this_mod_root.lexically_normal();
            ec.clear();
        }
    }

    auto mods = enumerate_enabled_dst_mods(is_client);
    report.mods_seen = mods.size();

    for (const auto &mod : mods) {
        if (mod.root.empty()) {
            report.skipped.push_back(mod.name + ": empty_root");
            continue;
        }
        auto mod_canon = std::filesystem::weakly_canonical(mod.root, ec);
        if (ec) {
            mod_canon = mod.root.lexically_normal();
            ec.clear();
        }
        if (!this_root_canon.empty() &&
            mod_canon.generic_string() == this_root_canon.generic_string()) {
            std::fprintf(stderr, "[plugin-discover] skip mod=%s reason=this_mod\n", mod.name.c_str());
            continue;
        }

        const auto modinfo_path = mod.root / "modinfo.lua";
        auto info = parse_plugin_pack_modinfo(modinfo_path);
        if (!external_pack_trust_ok(info)) {
            std::string reason = !info.ok ? ("modinfo:" + info.parse_error)
                                          : (!info.luajit_plugin_pack ? "no_luajit_plugin_pack"
                                                                      : "missing_plugin_id");
            report.skipped.push_back(mod.name + ": " + reason);
            std::fprintf(stderr, "[plugin-discover] skip mod=%s reason=%s\n", mod.name.c_str(),
                         reason.c_str());
            continue;
        }

        ++report.mods_accepted;
        std::fprintf(stderr, "[plugin-discover] accept mod=%s id=%s\n", mod.name.c_str(),
                     info.plugin_id.c_str());

        auto modules = list_pack_modules_under_mod(mod.root);
        for (const auto &module_path : modules) {
            if (!path_under_root(mod.root, module_path)) {
                report.skipped.push_back(module_path.string() + ": path_jail");
                std::fprintf(stderr, "[plugin-discover] skip mod=%s path=%s reason=path_jail\n",
                             mod.name.c_str(), module_path.string().c_str());
                continue;
            }
            std::string skip;
            bool loaded = false;
            if (load_fn) {
                loaded = load_fn(module_path, &skip);
            } else {
                // Production path requires a live DynamicPluginLoader instance;
                // call site uses load_all overload that passes a bound load_fn.
                skip = "no_load_fn";
            }
            if (!loaded) {
                report.skipped.push_back(module_path.string() + ": " +
                                         (skip.empty() ? "load_failed" : skip));
                std::fprintf(stderr, "[plugin-discover] skip mod=%s path=%s reason=%s\n",
                             mod.name.c_str(), module_path.string().c_str(),
                             skip.empty() ? "load_failed" : skip.c_str());
                continue;
            }
            ++report.modules_loaded;
            report.loaded_modules.push_back(module_path.string());
            std::fprintf(stderr, "[plugin-discover] load mod=%s id=%s module=%s\n", mod.name.c_str(),
                         info.plugin_id.c_str(), module_path.string().c_str());
            (void)host;
        }
    }
    return report;
}

} // namespace ds::plugin
