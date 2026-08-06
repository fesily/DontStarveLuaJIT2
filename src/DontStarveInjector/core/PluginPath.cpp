#include "PluginPath.hpp"

#include "config/path/ModFolderAliases.hpp"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string_view>
#include <unordered_set>


#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#else
#  include <dlfcn.h>
#  include <limits.h>
#  include <unistd.h>
#endif

namespace ds::plugin {
namespace {

using namespace std::string_view_literals;

std::string g_modmain_override;
ModmainPathProvider g_modmain_provider = nullptr;
std::mutex g_dll_search_mu;
// Bookkeeping only: AddDllDirectory USER_DIRS paths (absolute/weakly_canonical).
// Process-wide SetDefaultDllDirectories is intentionally NOT used — plugin loads
// pass LOAD_LIBRARY_SEARCH_USER_DIRS | DLL_LOAD_DIR | DEFAULT_DIRS on LoadLibraryEx.
std::unordered_set<std::string> g_added_dll_dirs;

// Primary workshop folder + local/dev aliases used when luajit_config.modmain_path
// is empty (first client boot / dedicated before config is written).
// Shared list: ds::config::path::kModFolderAliases / kPrimaryWorkshopModName.

bool iequals_ascii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        const unsigned char ca = static_cast<unsigned char>(a[i]);
        const unsigned char cb = static_cast<unsigned char>(b[i]);
        if (std::tolower(ca) != std::tolower(cb)) {
            return false;
        }
    }
    return true;
}

void try_push_dir(std::vector<std::filesystem::path> &out,
                  std::unordered_set<std::string> &seen,
                  const std::filesystem::path &dir) {
    std::error_code ec;
    if (dir.empty() || !std::filesystem::is_directory(dir, ec)) {
        return;
    }
    const auto canon = std::filesystem::weakly_canonical(dir, ec);
    const auto key = (ec ? dir : canon).string();
    if (!seen.insert(key).second) {
        return;
    }
    out.push_back(ec ? dir : canon);
}

void log_once(const char *tag, const char *msg) {
    // Path helpers may run before spdlog is ready; stderr is always available.
    static std::mutex mu;
    static std::unordered_set<std::string> seen;
    std::lock_guard lock(mu);
    const std::string key = std::string(tag) + "|" + msg;
    if (!seen.insert(key).second) {
        return;
    }
    std::fprintf(stderr, "[ds-plugin] %s: %s\n", tag, msg);
    std::fflush(stderr);
}

std::filesystem::path exe_directory() {
#if defined(_WIN32)
    wchar_t buf[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return {};
    }
    return std::filesystem::path(buf).parent_path();
#else
    // Linux dedicated/client typically run from bin64; /proc/self/exe is reliable.
    char buf[PATH_MAX];
    const ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) {
        return {};
    }
    buf[n] = '\0';
    return std::filesystem::path(buf).parent_path();
#endif
}

// Candidate parents of game `mods/` and Steam workshop content roots.
void collect_mod_search_bases(std::vector<std::filesystem::path> &bases) {
    auto push_unique = [&](const std::filesystem::path &p) {
        if (p.empty()) {
            return;
        }
        for (const auto &existing : bases) {
            if (existing == p) {
                return;
            }
        }
        bases.push_back(p);
    };

    const auto exe = exe_directory();
    if (!exe.empty()) {
        // bin64 → game root → mods/
        push_unique(exe.parent_path() / "mods");
        // Rare: process cwd already under game root.
        push_unique(exe / "mods");
        // Steam workshop content: .../steamapps/common/<game>/bin64
        // → .../steamapps/workshop/content/322330
        const auto steamapps = exe.parent_path().parent_path().parent_path();
        if (!steamapps.empty()) {
            push_unique(steamapps / "workshop" / "content" / "322330");
        }
    }

    // Also probe relative to Injector module (usually game bin64).
    const auto inj = injector_module_dir();
    if (!inj.empty()) {
        push_unique(inj.parent_path() / "mods");
        push_unique(inj / "mods");
        const auto steamapps = inj.parent_path().parent_path().parent_path();
        if (!steamapps.empty()) {
            push_unique(steamapps / "workshop" / "content" / "322330");
        }
    }
}

// When luajit_config has not written modmain_path yet, locate known mod roots
// that already have a plugins/ tree (post-install first boot / dedicated).
std::filesystem::path discover_mod_plugins_dir() {
    std::vector<std::filesystem::path> bases;
    collect_mod_search_bases(bases);

    std::error_code ec;
    for (const auto &base : bases) {
        if (base.empty() || !std::filesystem::is_directory(base, ec)) {
            continue;
        }
        for (const auto alias : ds::config::path::kModFolderAliases) {
            const auto mod_root = base / std::string{alias};
            const auto plugins = mod_root / "plugins";
            if (std::filesystem::is_directory(plugins, ec)) {
                // Prefer a root that looks like a real mod install.
                if (std::filesystem::is_regular_file(mod_root / "modmain.lua", ec) ||
                    std::filesystem::is_regular_file(mod_root / "modinfo.lua", ec) ||
                    std::filesystem::is_regular_file(mod_root / "install.bat", ec) ||
                    std::filesystem::is_regular_file(mod_root / "install_linux.sh", ec)) {
                    return plugins;
                }
                // plugins/ alone is enough after install.bat staged native modules.
                return plugins;
            }
        }
    }
    return {};
}

} // namespace

void set_modmain_path_override_for_test(std::string_view path_or_empty) {
    g_modmain_override.assign(path_or_empty.begin(), path_or_empty.end());
}

void set_modmain_path_provider(ModmainPathProvider fn) {
    g_modmain_provider = fn;
}

std::filesystem::path plugins_dir_from_modmain(std::string_view modmain_path) {
    if (modmain_path.empty()) {
        return {};
    }
    return std::filesystem::path(modmain_path).parent_path() / "plugins";
}

std::filesystem::path plugins_dir_from_module_dir(const std::filesystem::path &module_dir) {
    if (module_dir.empty()) {
        return {};
    }
    // Prefer the path as-is when this module already lives under plugins/
    // (plugin_manager.dll is deployed to <InjectorDir>/plugins/).
    const auto leaf = module_dir.filename();
    if (!leaf.empty() && iequals_ascii(leaf.string(), "plugins")) {
        return module_dir;
    }
    // Also accept paths whose string form ends with /plugins (defensive for
    // root-edge cases where filename() may be empty on some platforms).
    const auto s = module_dir.generic_string();
    if (s.size() >= 8) {
        const auto tail = std::string_view(s).substr(s.size() - 8);
        if (iequals_ascii(tail, "/plugins") || iequals_ascii(tail, "\\plugins")) {
            return module_dir;
        }
    }
    if (iequals_ascii(s, "plugins")) {
        return module_dir;
    }
    return module_dir / "plugins";
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

std::string resolve_modmain_path() {
    if (!g_modmain_override.empty()) {
        return g_modmain_override;
    }
    if (g_modmain_provider) {
        return g_modmain_provider();
    }
    return {};
}

std::vector<std::filesystem::path> default_plugin_search_dirs() {
    std::vector<std::filesystem::path> dirs;
    std::unordered_set<std::string> seen;

    if (const char *env = std::getenv(kPluginDirEnv); env && *env) {
        try_push_dir(dirs, seen, std::filesystem::path(env));
    }

    const auto modmain = resolve_modmain_path();
    const auto mod_plugins = plugins_dir_from_modmain(modmain);
    if (!modmain.empty()) {
        try_push_dir(dirs, seen, mod_plugins);
        std::error_code mod_plugins_ec;
        if (mod_plugins.empty() || !std::filesystem::is_directory(mod_plugins, mod_plugins_ec)) {
            log_once("warn",
                     "modmain_path set but parent(modmain)/plugins is missing; "
                     "mod-local plugins unavailable from config path");
        }
    } else {
        // First boot / dedicated: luajit_config may not have modmain_path yet.
        // Discover known workshop/local mod roots that already staged plugins/.
        const auto discovered = discover_mod_plugins_dir();
        if (!discovered.empty()) {
            try_push_dir(dirs, seen, discovered);
            log_once("info",
                     "modmain_path empty; using discovered mod plugins root "
                     "(workshop/local alias under game mods or Steam UGC)");
        } else {
            log_once("warn",
                     "modmain_path empty and no known mod plugins root found; "
                     "mod-local plugins unavailable until config is written or "
                     "DS_LUAJIT_PLUGIN_DIR is set");
        }
    }

    const auto inj = injector_module_dir();
    if (!inj.empty()) {
        const auto inj_plugins = plugins_dir_from_module_dir(inj);
        const size_t before = dirs.size();
        try_push_dir(dirs, seen, inj_plugins);
        if (dirs.size() > before) {
            // Injector plugins root was added (not deduped). Always warn once:
            // design treats this as migration/compat fallback, even when env is
            // also present (env still wins ordering via try_push_dir order).
            if (before == 0) {
                log_once("warn",
                         "using injector_module_dir()/plugins as plugin search fallback "
                         "(compat); prefer mod-local plugins or DS_LUAJIT_PLUGIN_DIR");
            } else {
                log_once("warn",
                         "also scanning injector_module_dir()/plugins as migration "
                         "fallback");
            }
        }
    }

    return dirs;
}

std::filesystem::path mod_root_from_plugins_dir(const std::filesystem::path &plugins_dir) {
    if (plugins_dir.empty()) {
        return {};
    }
    const auto leaf = plugins_dir.filename();
    if (!leaf.empty() && iequals_ascii(leaf.string(), "plugins")) {
        return plugins_dir.parent_path();
    }
    // Defensive: some platforms may yield empty filename() for trailing separators.
    const auto s = plugins_dir.generic_string();
    if (s.size() >= 8) {
        const auto tail = std::string_view(s).substr(s.size() - 8);
        if (iequals_ascii(tail, "/plugins") || iequals_ascii(tail, "\\plugins")) {
            return plugins_dir.parent_path();
        }
    }
    if (iequals_ascii(s, "plugins")) {
        return plugins_dir.parent_path();
    }
    return plugins_dir;
}

std::filesystem::path mod_deps_dir(const std::filesystem::path &mod_root) {
    if (mod_root.empty()) {
        return {};
    }
    return mod_root / "deps";
}

bool configure_plugin_dll_search(const std::vector<std::filesystem::path> &plugins_roots) {
#if !defined(_WIN32)
    (void)plugins_roots;
    return true;
#else
    std::lock_guard lock(g_dll_search_mu);
    // Do NOT call SetDefaultDllDirectories: it is process-wide and changes
    // default LoadLibrary search for the whole game. Plugin loads already pass
    // LOAD_LIBRARY_SEARCH_USER_DIRS | DLL_LOAD_DIR | DEFAULT_DIRS on LoadLibraryEx,
    // which honors AddDllDirectory without mutating process defaults.
    for (const auto &root : plugins_roots) {
        std::error_code ec;
        auto add = [&](const std::filesystem::path &p) {
            if (p.empty() || !std::filesystem::is_directory(p, ec)) {
                return;
            }
            const auto canon = std::filesystem::weakly_canonical(p, ec);
            const auto key = (ec ? p : canon).string();
            if (!g_added_dll_dirs.insert(key).second) {
                return;
            }
            const DLL_DIRECTORY_COOKIE cookie =
                AddDllDirectory((ec ? p : canon).wstring().c_str());
            if (cookie == nullptr) {
                // Keep bookkeeping so we do not spam; still report once.
                const DWORD err = GetLastError();
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                              "AddDllDirectory failed for '%s' (GetLastError=%lu)",
                              key.c_str(), static_cast<unsigned long>(err));
                log_once("warn", buf);
            }
        };
        // mod_root/deps: third-party + lua51* + signatures_*.json (canonical)
        add(mod_deps_dir(mod_root_from_plugins_dir(root)));
        // legacy discarded layout plugins/deps — still AddDllDirectory if present during migration
        add(root / "deps");
        add(root); // optional private side-by-side next to plugin_*.dll
    }
    return true;
#endif
}

void reset_plugin_dll_search_for_test() {
#if defined(_WIN32)
    std::lock_guard lock(g_dll_search_mu);
    // Win32 has no bulk RemoveDllDirectory; tests only clear bookkeeping so re-Add is attempted.
    g_added_dll_dirs.clear();
#endif
}

} // namespace ds::plugin
