#include "EnabledDstMods.hpp"

#include <cstdlib>
#include <fstream>
#include <iterator>
#include <sstream>
#include <unordered_set>

#include <sol/sol.hpp>

namespace ds::plugin {
namespace {

std::vector<std::string> split_path_list(const char *raw) {
    std::vector<std::string> out;
    if (!raw || !*raw) {
        return out;
    }
    std::string s(raw);
    size_t start = 0;
    while (start <= s.size()) {
        size_t sep = s.find_first_of(";|", start);
        if (sep == std::string::npos) {
            sep = s.size();
        }
        auto part = s.substr(start, sep - start);
        // trim spaces
        while (!part.empty() && (part.front() == ' ' || part.front() == '\t')) {
            part.erase(part.begin());
        }
        while (!part.empty() && (part.back() == ' ' || part.back() == '\t')) {
            part.pop_back();
        }
        if (!part.empty()) {
            out.push_back(part);
        }
        if (sep == s.size()) {
            break;
        }
        start = sep + 1;
    }
    return out;
}

bool table_entry_enabled(const sol::object &value) {
    if (!value.valid() || value.get_type() == sol::type::lua_nil) {
        return false;
    }
    if (value.get_type() == sol::type::boolean) {
        return value.as<bool>();
    }
    if (value.get_type() != sol::type::table) {
        return false;
    }
    sol::table t = value.as<sol::table>();
    sol::object en = t["enabled"];
    if (!en.valid() || en.get_type() == sol::type::lua_nil) {
        return false;
    }
    if (en.get_type() == sol::type::boolean) {
        return en.as<bool>();
    }
    return false;
}

} // namespace

std::vector<std::string> parse_modoverrides_enabled_names(const std::filesystem::path &path) {
    std::vector<std::string> out;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return out;
    }
    std::string content{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    try {
        sol::state lua;
        lua.open_libraries(sol::lib::base);
        auto result = lua.safe_script(content, sol::script_pass_on_error);
        if (!result.valid()) {
            return out;
        }
        sol::object root_obj = result;
        // Some files return a table; others assign to a global. Prefer return value.
        sol::table root;
        if (root_obj.get_type() == sol::type::table) {
            root = root_obj.as<sol::table>();
        } else if (lua["modoverrides"].get_type() == sol::type::table) {
            root = lua["modoverrides"];
        } else {
            return out;
        }
        for (const auto &kv : root) {
            if (kv.first.get_type() != sol::type::string) {
                continue;
            }
            if (!table_entry_enabled(kv.second)) {
                continue;
            }
            out.push_back(kv.first.as<std::string>());
        }
    } catch (...) {
        out.clear();
    }
    return out;
}

std::filesystem::path resolve_dst_mod_root(const std::string &mod_name,
                                           const std::vector<std::filesystem::path> &search_bases) {
    if (mod_name.empty()) {
        return {};
    }
    std::error_code ec;
    for (const auto &base : search_bases) {
        if (base.empty()) {
            continue;
        }
        auto candidate = base / mod_name;
        if (std::filesystem::is_directory(candidate, ec)) {
            return std::filesystem::weakly_canonical(candidate, ec);
        }
        // workshop- style sometimes nested
        auto workshop = base / ("workshop-" + mod_name);
        if (std::filesystem::is_directory(workshop, ec)) {
            return std::filesystem::weakly_canonical(workshop, ec);
        }
    }
    return {};
}

std::vector<EnabledDstMod> enumerate_enabled_dst_mods(bool is_client) {
    std::vector<EnabledDstMod> out;
    std::unordered_set<std::string> seen_names;

    auto push_name = [&](const std::string &name, const std::filesystem::path &root) {
        if (name.empty() || root.empty()) {
            return;
        }
        if (!seen_names.insert(name).second) {
            return;
        }
        out.push_back(EnabledDstMod{name, root});
    };

    // Search bases: game mods + UGC style roots already used by PluginPath discovery.
    // For unit tests / extra packs: DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS lists absolute mod roots.
    std::vector<std::filesystem::path> bases;
    // PluginPath does not export all bases; use env + relative ../mods heuristics.
    if (const char *mods = std::getenv("DS_LUAJIT_MODS_ROOT"); mods && *mods) {
        bases.emplace_back(mods);
    }
    bases.emplace_back(std::filesystem::path("..") / "mods");
    bases.emplace_back(std::filesystem::path("mods"));

    // Explicit absolute mod roots (test seam + advanced ops). Still must be "enabled"
    // via either appearing in overrides OR being listed here for local dev.
    if (const char *extra = std::getenv("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS"); extra && *extra) {
        for (const auto &part : split_path_list(extra)) {
            std::error_code ec;
            std::filesystem::path root(part);
            if (!std::filesystem::is_directory(root, ec)) {
                continue;
            }
            auto name = root.filename().string();
            auto canon = std::filesystem::weakly_canonical(root, ec);
            push_name(name, canon);
        }
    }

    if (!is_client) {
        // Server: scan known modoverrides.lua candidates if DS_LUAJIT_MODOVERRIDES_PATH set
        // or common relative cluster path for tests.
        std::vector<std::filesystem::path> override_files;
        if (const char *p = std::getenv("DS_LUAJIT_MODOVERRIDES_PATH"); p && *p) {
            override_files.emplace_back(p);
        }
        // Allow multiple via same split
        if (const char *plist = std::getenv("DS_LUAJIT_MODOVERRIDES_PATHS"); plist && *plist) {
            for (const auto &part : split_path_list(plist)) {
                override_files.emplace_back(part);
            }
        }
        for (const auto &ov : override_files) {
            for (const auto &name : parse_modoverrides_enabled_names(ov)) {
                auto root = resolve_dst_mod_root(name, bases);
                if (!root.empty()) {
                    push_name(name, root);
                }
            }
        }
    } else {
        // Client: optional modsettings.lua path for force-enable style lists is complex;
        // v1 uses DS_LUAJIT_CLIENT_ENABLED_MODS as comma/semicolon list of mod names
        // for tests, plus EXTRA roots.
        if (const char *clist = std::getenv("DS_LUAJIT_CLIENT_ENABLED_MODS"); clist && *clist) {
            for (const auto &name : split_path_list(clist)) {
                auto root = resolve_dst_mod_root(name, bases);
                if (!root.empty()) {
                    push_name(name, root);
                }
            }
        }
        if (const char *settings = std::getenv("DS_LUAJIT_MODSETTINGS_PATH"); settings && *settings) {
            // Best-effort: if file returns a table of [modname]=true style, reuse parser
            // by wrapping — many modsettings are scripts not tables. Skip if parse empty.
            for (const auto &name : parse_modoverrides_enabled_names(settings)) {
                auto root = resolve_dst_mod_root(name, bases);
                if (!root.empty()) {
                    push_name(name, root);
                }
            }
        }
    }

    return out;
}

} // namespace ds::plugin
