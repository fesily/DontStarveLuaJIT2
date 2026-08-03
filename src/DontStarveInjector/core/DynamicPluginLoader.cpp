#include "DynamicPluginLoader.hpp"
#include "PluginModuleAbi.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
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

using AbiVersionFn = const char *(*)();
using ModuleInitFn = bool (*)(PluginHost *);

#if defined(_WIN32)
using ModuleHandle = HMODULE;

void *load_library(const std::filesystem::path &path) {
    // Avoid modal "Bad Image" / critical-error UI when probing non-PE files under CTest.
    const UINT prev = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX | SEM_NOGPFAULTERRORBOX);
    void *handle = static_cast<void *>(LoadLibraryW(path.wstring().c_str()));
    SetErrorMode(prev);
    return handle;
}

void *lookup_symbol(void *handle, const char *name) {
    return reinterpret_cast<void *>(GetProcAddress(static_cast<HMODULE>(handle), name));
}

void close_library(void *handle) {
    if (handle) {
        FreeLibrary(static_cast<HMODULE>(handle));
    }
}

std::filesystem::path injector_module_dir() {
    HMODULE mod = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
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
}
#else
void *load_library(const std::filesystem::path &path) {
    return dlopen(path.c_str(), RTLD_NOW);
}

void *lookup_symbol(void *handle, const char *name) {
    return dlsym(handle, name);
}

void close_library(void *handle) {
    if (handle) {
        dlclose(handle);
    }
}

std::filesystem::path injector_module_dir() {
    Dl_info info{};
    if (dladdr(reinterpret_cast<const void *>(&injector_module_dir), &info) && info.dli_fname) {
        return std::filesystem::path(info.dli_fname).parent_path();
    }
    return {};
}
#endif

bool has_plugin_extension(const std::filesystem::path &path) {
    const auto ext = path.extension().string();
#if defined(_WIN32)
    return _stricmp(ext.c_str(), ".dll") == 0;
#elif defined(__APPLE__)
    return ext == ".dylib" || ext == ".so";
#else
    return ext == ".so";
#endif
}

bool is_plugin_candidate(const std::filesystem::directory_entry &entry) {
    if (!entry.is_regular_file()) {
        return false;
    }
    const auto name = entry.path().filename().string();
    if (name.rfind("plugin_", 0) != 0) {
        return false;
    }
    return has_plugin_extension(entry.path());
}

std::string skip_reason(const std::filesystem::path &path, const char *reason) {
    return path.string() + ": " + reason;
}

void try_push_dir(std::vector<std::filesystem::path> &out, std::unordered_set<std::string> &seen,
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

DynamicPluginLoader::~DynamicPluginLoader() {
    // Successful plugin modules stay mapped for process lifetime.
    // FreeLibrary/dlclose of live plugin code is UB if Host still holds vtables.
    handles_.clear();
}

std::vector<std::filesystem::path> DynamicPluginLoader::default_search_dirs() {
    std::vector<std::filesystem::path> dirs;
    std::unordered_set<std::string> seen;

    if (const char *env = std::getenv("DS_LUAJIT_PLUGIN_DIR"); env && *env) {
        try_push_dir(dirs, seen, std::filesystem::path(env));
    }

    const auto mod_dir = injector_module_dir();
    if (!mod_dir.empty()) {
        try_push_dir(dirs, seen, mod_dir / "plugins");
    }

    return dirs;
}

DynamicLoadReport DynamicPluginLoader::load_all(PluginHost &host) {
    DynamicLoadReport report;
    for (const auto &dir : default_search_dirs()) {
        auto partial = load_directory(host, dir);
        report.loaded_modules.insert(report.loaded_modules.end(), partial.loaded_modules.begin(),
                                     partial.loaded_modules.end());
        report.skipped.insert(report.skipped.end(), partial.skipped.begin(), partial.skipped.end());
    }
    return report;
}

DynamicLoadReport DynamicPluginLoader::load_directory(PluginHost &host, const std::filesystem::path &dir) {
    DynamicLoadReport report;
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) {
        return report;
    }

    for (const auto &entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) {
            break;
        }
        if (!is_plugin_candidate(entry)) {
            continue;
        }

        const auto abs = std::filesystem::weakly_canonical(entry.path(), ec);
        const auto path = ec ? entry.path() : abs;
        const auto path_str = path.string();

        void *handle = load_library(path);
        if (!handle) {
            report.skipped.push_back(skip_reason(path, "load_failed"));
            std::fprintf(stderr, "[DynamicPluginLoader] load_failed: %s\n", path_str.c_str());
            continue;
        }

        if (auto *abi = reinterpret_cast<AbiVersionFn>(lookup_symbol(handle, "ds_plugin_module_abi_version"))) {
            const char *ver = abi();
            if (ver == nullptr || std::strcmp(ver, DS_PLUGIN_ABI_VERSION) != 0) {
                close_library(handle);
                report.skipped.push_back(skip_reason(path, "abi_mismatch"));
                std::fprintf(stderr, "[DynamicPluginLoader] abi_mismatch: %s\n", path_str.c_str());
                continue;
            }
        }

        auto *init = reinterpret_cast<ModuleInitFn>(lookup_symbol(handle, "ds_plugin_module_init"));
        if (!init) {
            close_library(handle);
            report.skipped.push_back(skip_reason(path, "missing_init"));
            std::fprintf(stderr, "[DynamicPluginLoader] missing_init: %s\n", path_str.c_str());
            continue;
        }

        bool ok = false;
        try {
            ok = init(&host);
        } catch (...) {
            ok = false;
        }
        if (!ok) {
            close_library(handle);
            report.skipped.push_back(skip_reason(path, "init_failed"));
            std::fprintf(stderr, "[DynamicPluginLoader] init_failed: %s\n", path_str.c_str());
            continue;
        }

        handles_.push_back(handle);
        report.loaded_modules.push_back(path_str);
        std::fprintf(stderr, "[DynamicPluginLoader] loaded: %s\n", path_str.c_str());
    }

    return report;
}

} // namespace ds::plugin
