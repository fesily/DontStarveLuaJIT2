#include "PluginPath.hpp"

#include <cctype>
#include <cstdlib>
#include <mutex>
#include <unordered_set>

#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#else
#  include <dlfcn.h>
#endif

namespace ds::plugin {
namespace {

std::string g_modmain_override;
ModmainPathProvider g_modmain_provider = nullptr;
std::mutex g_dll_search_mu;
bool g_default_dirs_set = false;
std::unordered_set<std::string> g_added_dll_dirs; // weakly_canonical string keys

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
    try_push_dir(dirs, seen, plugins_dir_from_modmain(resolve_modmain_path()));
    const auto inj = injector_module_dir();
    if (!inj.empty()) {
        try_push_dir(dirs, seen, plugins_dir_from_module_dir(inj));
    }
    return dirs;
}

std::filesystem::path plugins_deps_dir(const std::filesystem::path &plugins_root) {
    return plugins_root / "deps";
}

bool configure_plugin_dll_search(const std::vector<std::filesystem::path> &plugins_roots) {
#if !defined(_WIN32)
    (void)plugins_roots;
    return true;
#else
    std::lock_guard lock(g_dll_search_mu);
    if (!g_default_dirs_set) {
        // Prefer SetDefaultDllDirectories when available (kernel32).
        // If call fails, continue — LoadLibraryEx flags still help for DLL_LOAD_DIR.
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
        g_default_dirs_set = true;
    }
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
            AddDllDirectory((ec ? p : canon).wstring().c_str());
        };
        add(plugins_deps_dir(root));
        add(root); // optional private side-by-side
    }
    return true;
#endif
}

void reset_plugin_dll_search_for_test() {
#if defined(_WIN32)
    std::lock_guard lock(g_dll_search_mu);
    // Win32 has no RemoveDllDirectory for all; tests only clear bookkeeping so re-Add is attempted.
    g_added_dll_dirs.clear();
    // Do not clear g_default_dirs_set (process-wide policy stays).
#endif
}

} // namespace ds::plugin
