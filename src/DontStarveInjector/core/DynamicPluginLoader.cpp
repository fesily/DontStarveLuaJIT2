#include "DynamicPluginLoader.hpp"
#include "PluginModuleAbi.hpp"
#include "PluginPath.hpp"
#include "PluginPendingUpdates.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>


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

void *load_library(const std::filesystem::path &path, DWORD *out_err = nullptr) {
    // Avoid modal "Bad Image" / critical-error UI when probing non-PE files under CTest.
    const UINT prev = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX | SEM_NOGPFAULTERRORBOX);
    SetLastError(0);
    // Prefer LoadLibraryEx so dependencies resolve from the DLL's directory,
    // USER_DIRS (plugins + plugins/deps via configure_plugin_dll_search), and
    // default system dirs — without PATH games.
    void *handle = static_cast<void *>(LoadLibraryExW(
        path.wstring().c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
            LOAD_LIBRARY_SEARCH_USER_DIRS));
    if (!handle) {
        // Fallback for older search-path combinations / non-standard layouts.
        SetLastError(0);
        handle = static_cast<void *>(LoadLibraryW(path.wstring().c_str()));
    }
    if (out_err) {
        *out_err = handle ? 0 : GetLastError();
    }
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

#else
void *load_library(const std::filesystem::path &path) {
    return dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL);
}

void *lookup_symbol(void *handle, const char *name) {
    return dlsym(handle, name);
}

void close_library(void *handle) {
    if (handle) {
        dlclose(handle);
    }
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

// Platform shared-library suffix for package-layout candidate:
// plugins/plugin_<stem>/plugin_<stem>.{dll,so,dylib}
const char *plugin_module_extension() {
#if defined(_WIN32)
    return ".dll";
#elif defined(__APPLE__)
    return ".dylib";
#else
    return ".so";
#endif
}

// Package dir: name starts with plugin_; candidate is <dir>/<name><ext>
// and must be a regular file. Directory name is the module stem.
bool package_plugin_candidate(const std::filesystem::directory_entry &entry,
                              std::filesystem::path *out_path) {
    std::error_code ec;
    if (!entry.is_directory(ec) || ec) {
        return false;
    }
    const auto stem = entry.path().filename().string();
    if (stem.rfind("plugin_", 0) != 0) {
        return false;
    }
    auto candidate = entry.path() / (stem + plugin_module_extension());
    if (!std::filesystem::is_regular_file(candidate, ec) || ec) {
#if defined(__APPLE__)
        // Prefer .dylib, fall back to .so on Apple.
        candidate = entry.path() / (stem + std::string(".so"));
        if (!std::filesystem::is_regular_file(candidate, ec) || ec) {
            return false;
        }
#else
        return false;
#endif
    }
    if (out_path) {
        *out_path = std::move(candidate);
    }
    return true;
}


std::string skip_reason(const std::filesystem::path &path, const char *reason) {
    return path.string() + ": " + reason;
}


} // namespace

DynamicPluginLoader::~DynamicPluginLoader() {
    // Successful plugin modules stay mapped for process lifetime.
    // FreeLibrary/dlclose of live plugin code is UB if Host still holds vtables.
    handles_.clear();
}

std::vector<std::filesystem::path> DynamicPluginLoader::default_search_dirs() {
    return default_plugin_search_dirs();
}

DynamicLoadReport DynamicPluginLoader::load_all(PluginHost &host) {
    DynamicLoadReport report;
    const auto dirs = default_search_dirs();
    (void)configure_plugin_dll_search(dirs);
    for (const auto &dir : dirs) {
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

    // Test seam / per-root: register this plugins root (and deps/) for USER_DIRS.
    (void)configure_plugin_dll_search({dir});

    // Apply manager/manual drops from update_pending/ before any LoadLibrary.
    (void)apply_pending_plugin_updates(dir);

    for (const auto &entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) {
            break;
        }

        std::filesystem::path module_path;
        bool from_package = false;
        if (is_plugin_candidate(entry)) {
            module_path = entry.path();
        } else if (package_plugin_candidate(entry, &module_path)) {
            from_package = true;
        } else {
            continue;
        }

        // Package modules may ship private deps beside the DLL; register the
        // package dir in addition to the plugins root already configured above.
        if (from_package) {
            (void)configure_plugin_dll_search({module_path.parent_path()});
        }

        // Do not reuse `ec` from the iterator — a failed weakly_canonical
        // must not abort the rest of the directory scan.
        std::error_code path_ec;
        const auto abs = std::filesystem::weakly_canonical(module_path, path_ec);
        const auto path = path_ec ? module_path : abs;
        const auto path_str = path.string();

#if defined(_WIN32)
        DWORD load_err = 0;
        void *handle = load_library(path, &load_err);
#else
        void *handle = load_library(path);
        unsigned long load_err = 0;
#endif
        if (!handle) {
            char reason[64];
            std::snprintf(reason, sizeof(reason), "load_failed(err=%lu)", static_cast<unsigned long>(load_err));
            report.skipped.push_back(skip_reason(path, reason));
            std::fprintf(stderr, "[DynamicPluginLoader] load_failed: %s err=%lu\n", path_str.c_str(),
                         static_cast<unsigned long>(load_err));
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
            host.begin_module_registration();
            ok = init(&host);
            host.end_module_registration();
        } catch (...) {
            host.end_module_registration();
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
