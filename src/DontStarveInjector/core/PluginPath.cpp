#include "PluginPath.hpp"

#include "util/PathText.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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

// Test seam: non-empty makes injector_module_dir() return this path.
std::filesystem::path g_injector_dir_override;
std::mutex g_dll_search_mu;
// Bookkeeping only: AddDllDirectory USER_DIRS paths (absolute/weakly_canonical).
// Process-wide SetDefaultDllDirectories is intentionally NOT used — plugin loads
// pass LOAD_LIBRARY_SEARCH_USER_DIRS | DLL_LOAD_DIR | DEFAULT_DIRS on LoadLibraryEx.
std::unordered_set<std::filesystem::path, util::PathHash> g_added_dll_dirs;
// POSIX counterpart: the roots themselves, in registration order, walked by
// util/platform.cpp loadlib(). Windows keeps the authoritative list in the OS.
std::vector<std::filesystem::path> g_dll_roots;

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

} // namespace

void set_injector_module_dir_for_test(const std::filesystem::path &module_dir_or_empty) {
    g_injector_dir_override = module_dir_or_empty;
}

std::filesystem::path plugins_dir_from_module_dir(const std::filesystem::path &module_dir) {
    if (module_dir.empty()) {
        return {};
    }
    // Prefer the path as-is when this module already lives under plugins/
    // (plugin_manager.dll is deployed to <InjectorDir>/plugins/).
    const auto leaf = module_dir.filename();
    if (!leaf.empty() && iequals_ascii(util::path_to_utf8(leaf), "plugins")) {
        return module_dir;
    }
    // Also accept paths whose string form ends with /plugins (defensive for
    // root-edge cases where filename() may be empty on some platforms).
    const auto s = util::path_to_utf8_generic(module_dir);
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
    if (!g_injector_dir_override.empty()) {
        return g_injector_dir_override;
    }
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

std::vector<std::filesystem::path> default_plugin_search_dirs() {
    std::filesystem::path env_root;
#if defined(_WIN32)
    // The environment is UTF-16 on Windows; getenv()/path(char*) would narrow it
    // through the ANSI code page. Copy out of _wgetenv's shared buffer at once.
    static const std::wstring env_key(kPluginDirEnv,
                                      kPluginDirEnv + std::strlen(kPluginDirEnv));
    if (const wchar_t *env = _wgetenv(env_key.c_str()); env != nullptr && env[0] != L'\0') {
        env_root = std::filesystem::path(env);
    }
#else
    if (const char *env = std::getenv(kPluginDirEnv); env != nullptr && *env != '\0') {
        env_root = util::path_from_utf8(env);
    }
#endif

    std::filesystem::path module_dir;
    std::filesystem::path candidate = env_root;
    if (candidate.empty()) {
        module_dir = injector_module_dir();
        if (!module_dir.empty()) {
            candidate = plugins_dir_from_module_dir(module_dir);
        }
    }

    std::error_code ec;
    if (candidate.empty() || !std::filesystem::is_directory(candidate, ec)) {
        // No fallback: one tree, or no plugins. Scanning another install would
        // reintroduce the injector-root/plugin-root split this contract removes.
        if (!env_root.empty()) {
            log_once("warn", (std::string{"DS_LUAJIT_PLUGIN_DIR is not a directory: "} +
                              util::path_to_utf8(env_root))
                                 .c_str());
        } else if (module_dir.empty()) {
            log_once("warn", "cannot determine the real Injector module dir; no plugin root");
        } else {
            log_once("warn",
                     (std::string{"injector module dir has no plugins/ tree: "} +
                      util::path_to_utf8(candidate))
                         .c_str());
        }
        return {};
    }

    const auto canon = std::filesystem::weakly_canonical(candidate, ec);
    if (ec) {
        log_once("warn", (std::string{"weakly_canonical failed for "} +
                          util::path_to_utf8(candidate) + ": " + ec.message())
                             .c_str());
    }
    const auto root = ec ? candidate : canon;
    log_once("info", (std::string{"plugin root: "} + util::path_to_utf8(root)).c_str());
    return {root};
}

std::filesystem::path mod_root_from_plugins_dir(const std::filesystem::path &plugins_dir) {
    if (plugins_dir.empty()) {
        return {};
    }
    const auto leaf = plugins_dir.filename();
    if (!leaf.empty() && iequals_ascii(util::path_to_utf8(leaf), "plugins")) {
        return plugins_dir.parent_path();
    }
    // Defensive: some platforms may yield empty filename() for trailing separators.
    const auto s = util::path_to_utf8_generic(plugins_dir);
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

namespace {

std::vector<std::string> list_plugin_packages_in(const std::filesystem::path &dir) {
    std::vector<std::string> out;
    std::error_code ec;
    if (dir.empty() || !std::filesystem::is_directory(dir, ec)) {
        return out;
    }
    for (std::filesystem::directory_iterator it(dir, ec), end; it != end; it.increment(ec)) {
        if (ec) {
            break;
        }
        std::error_code probe_ec;
        if (!it->is_directory(probe_ec)) {
            continue;
        }
        const std::string stem = util::path_to_utf8(it->path().filename());
        if (stem.rfind("plugin_", 0) != 0) {
            continue;
        }
        if (!std::filesystem::is_regular_file(it->path() / "modinfo.lua", probe_ec)) {
            continue;
        }
        out.push_back(stem);
    }
    std::sort(out.begin(), out.end());
    return out;
}

} // namespace

std::vector<std::string> list_plugin_packages(std::string_view plugins_dir_utf8) {
    if (plugins_dir_utf8.empty()) {
        return {};
    }
    return list_plugin_packages_in(util::path_from_utf8(plugins_dir_utf8));
}

std::vector<std::string> list_installed_plugin_packages(std::string_view plugins_dir_utf8) {
    // The single native root is the source of truth: the Lua face must register
    // exactly what DynamicPluginLoader loads. The hint the registry passes is a
    // MODROOT-relative engine path (a Workshop item loads from Steam UGC while
    // MODROOT stays "../mods/workshop-<id>/"), so it may not exist on disk and
    // may even name another install; consult it only when no root resolves.
    const auto roots = default_plugin_search_dirs();
    if (!roots.empty()) {
        return list_plugin_packages_in(roots.front());
    }
    return list_plugin_packages(plugins_dir_utf8);
}

std::filesystem::path mod_deps_dir(const std::filesystem::path &mod_root) {
    if (mod_root.empty()) {
        return {};
    }
    return mod_root / "deps";
}

bool configure_plugin_dll_search(const std::vector<std::filesystem::path> &plugins_roots) {
    std::lock_guard lock(g_dll_search_mu);
    for (const auto &root : plugins_roots) {
        if (root.empty()) {
            continue;
        }
        // One definition of "which roots" for every platform.
        const std::filesystem::path candidates[] = {
            mod_deps_dir(mod_root_from_plugins_dir(root)), // <mod>/deps (canonical)
            root / "deps",                                 // legacy plugins/deps
            root,                                          // private side-by-side deps
        };
        for (const auto &p : candidates) {
            if (p.empty()) {
                continue;
            }
            std::error_code ec;
            if (!std::filesystem::is_directory(p, ec)) {
                continue;
            }
            const auto canon = std::filesystem::weakly_canonical(p, ec);
            const auto abs_path = ec ? p : canon;
            if (!g_added_dll_dirs.insert(abs_path).second) {
                continue; // already registered
            }
            const auto key = util::path_to_utf8_generic(abs_path);  // diagnostics only
#if defined(_WIN32)
            const DLL_DIRECTORY_COOKIE cookie = AddDllDirectory(abs_path.wstring().c_str());
            if (cookie == nullptr) {
                // Keep bookkeeping so we do not spam; still report once.
                const DWORD err = GetLastError();
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                              "AddDllDirectory failed for '%s' (GetLastError=%lu)",
                              key.c_str(), static_cast<unsigned long>(err));
                log_once("warn", buf);
                // Not actually registered, so it must not show up in the roots
                // list either (g_added_dll_dirs already suppresses a retry).
                continue;
            }
#endif
            // Bookkeeping on every platform: POSIX loadlib() walks this list
            // instead of probing the ELF global symbol scope (util/platform.cpp),
            // Windows reaches the same dirs through AddDllDirectory(USER_DIRS).
            // Keeping both in plugin_dll_search_roots() is what makes the
            // idempotency/dedup contract observable (and testable) on Windows.
            g_dll_roots.push_back(abs_path);
        }
    }
    return true;
}

std::vector<std::filesystem::path> plugin_dll_search_roots() {
    std::lock_guard lock(g_dll_search_mu);
    return g_dll_roots;
}

void reset_plugin_dll_search_for_test() {
    std::lock_guard lock(g_dll_search_mu);
    // Win32 has no bulk RemoveDllDirectory; tests only clear bookkeeping so re-Add is attempted.
    g_added_dll_dirs.clear();
    g_dll_roots.clear();
}

} // namespace ds::plugin
