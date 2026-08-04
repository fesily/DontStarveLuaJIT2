#include "CoreVmBootstrap.hpp"

#include <cstdio>
#include <filesystem>
#include <mutex>
#include <string>

#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#else
#  include <dlfcn.h>
#  include <limits.h>
#  include <unistd.h>
#endif

namespace ds::core_vm {
namespace {

#if defined(_WIN32)
constexpr const char *kCoreVmModuleName = "plugin_core_vm.dll";
#else
#  if defined(__APPLE__)
constexpr const char *kCoreVmModuleName = "plugin_core_vm.dylib";
#  else
constexpr const char *kCoreVmModuleName = "plugin_core_vm.so";
#  endif
#endif

constexpr const char *kRunExportName = "ds_core_vm_run_signature_and_replace";

std::filesystem::path injector_module_dir() {
#if defined(_WIN32)
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
#else
    Dl_info info{};
    if (dladdr(reinterpret_cast<const void *>(&injector_module_dir), &info) && info.dli_fname) {
        return std::filesystem::path(info.dli_fname).parent_path();
    }
    return {};
#endif
}

void *core_vm_module_handle() {
#if defined(_WIN32)
    return static_cast<void *>(GetModuleHandleA(kCoreVmModuleName));
#else
    // Prefer an already-mapped handle (DynamicPluginLoader or prior Ensure).
    void *existing = dlopen(kCoreVmModuleName, RTLD_NOLOAD | RTLD_LAZY);
    if (existing) {
        // dlopen(RTLD_NOLOAD) bumps the refcount; drop the extra ref.
        dlclose(existing);
        return existing;
    }
    return nullptr;
#endif
}

void *load_core_vm_from_plugins_dir() {
    const auto dir = injector_module_dir();
    if (dir.empty()) {
        return nullptr;
    }
    const auto path = dir / "plugins" / kCoreVmModuleName;
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        return nullptr;
    }
#if defined(_WIN32)
    const UINT prev = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX | SEM_NOGPFAULTERRORBOX);
    SetLastError(0);
    HMODULE handle = LoadLibraryExW(path.wstring().c_str(), nullptr,
                                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!handle) {
        SetLastError(0);
        handle = LoadLibraryW(path.wstring().c_str());
    }
    SetErrorMode(prev);
    return static_cast<void *>(handle);
#else
    return dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL);
#endif
}

void *lookup_symbol(void *handle, const char *name) {
    if (!handle || !name) {
        return nullptr;
    }
#if defined(_WIN32)
    return reinterpret_cast<void *>(GetProcAddress(static_cast<HMODULE>(handle), name));
#else
    return dlsym(handle, name);
#endif
}

// One-shot load attempt; never FreeLibrary — module stays mapped for process life.
void *ensure_handle_locked() {
    if (void *h = core_vm_module_handle()) {
        return h;
    }
    return load_core_vm_from_plugins_dir();
}

} // namespace

bool EnsureCoreVmModuleLoaded() {
    static std::once_flag once;
    static bool loaded = false;
    std::call_once(once, [] {
        void *h = ensure_handle_locked();
        loaded = h != nullptr;
        if (loaded) {
            std::fprintf(stderr, "[core.vm] module mapped: %s\n", kCoreVmModuleName);
        } else {
            std::fprintf(stderr, "[core.vm] module not found (optional): %s\n", kCoreVmModuleName);
        }
    });
    return loaded;
}

RunSigReplaceFn GetRunSignatureAndReplaceFn() {
    if (!EnsureCoreVmModuleLoaded()) {
        return nullptr;
    }
    void *h = core_vm_module_handle();
    if (!h) {
        // Ensure may have loaded via full path; re-resolve basename handle.
        h = ensure_handle_locked();
    }
    if (!h) {
        return nullptr;
    }
    return reinterpret_cast<RunSigReplaceFn>(lookup_symbol(h, kRunExportName));
}

bool TryRunSignatureAndReplace(const BootstrapArgs &args) {
    if (auto *fn = GetRunSignatureAndReplaceFn()) {
        if (fn(&args)) {
            return true;
        }
        // V-S1 stub returns false intentionally; fall back while impl still in Injector.
        std::fprintf(stderr,
                     "[core.vm] ds_core_vm_run_signature_and_replace returned false — "
                     "using legacy Injector signature/replace\n");
    }
    return LegacySignatureAndReplaceInInjector(args);
}

} // namespace ds::core_vm
