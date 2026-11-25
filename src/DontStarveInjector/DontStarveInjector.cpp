// DontStarveInjector.cpp : Defines the exported functions for the DLL application.
//

#include "config/InjectorHostConfig.hpp"
#include "util/inlinehook.hpp"
#include "util/PathText.hpp"
#include "util/platform.hpp"
#include "util/Unsafedata.hpp"
#include "ctx.hpp"
#include "core/InjectorSignatures.hpp"
#include "core/SignatureManager.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginConfigBridge.hpp"
#include "config/ConfigSchema.hpp"
#include "config/ResolvedConfig.hpp"
#include "core/RegisterBuiltinPlugins.hpp"
#include "core/DynamicPluginLoader.hpp"
#include "core/CoreVmBootstrap.hpp"
#include "core/LuaPucDumpService.hpp"
#include "core/PluginServices.hpp"
#include "core/alloc/AllocShim.hpp"
#include <mimalloc.h>
#ifdef ENABLE_STEAM_SUPPORT
#include "sdk/steam/Steam.hpp"
#endif

#include <spdlog/fmt/std.h>
#include <spdlog/spdlog.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_NONSTDC_NO_WARNINGS
#include <windows.h>
#include <spdlog/sinks/msvc_sink.h>
#else
#include <pthread.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

#include <string>
#include <algorithm>
#include <cstring>
#include <iterator>
#include <map>
#include <cstdint>
#include <list>
#include <atomic>
#include <cstdio>


#include <frida-gum.h>
#include "util/frida_gum_interceptor.hpp"
#include <spdlog/sinks/basic_file_sink.h>


#if !ONLY_LUA51
#include <lua.h>
#else
extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

#endif
#include "util/tools.hpp"

using namespace std;

namespace {

#ifndef _WIN32
    bool name_contains_dontstarve(const char *name, size_t length) noexcept {
        constexpr char needle[] = "dontstarve";
        constexpr size_t needle_length = sizeof(needle) - 1;
        if (length < needle_length) return false;
        for (size_t i = 0; i + needle_length <= length; ++i) {
            bool match = true;
            for (size_t k = 0; k < needle_length; ++k) {
                char c = name[i + k];
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                if (c != needle[k]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }
#endif

    // phase 0 guard: stack buffer only. getExePath() returns std::filesystem::path,
    // which allocates through the CRT this code is about to replace.
    bool is_dontstarve_process() noexcept {
#ifdef _WIN32
        wchar_t path[1024];
        const DWORD length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
        if (length == 0 || length >= std::size(path)) return false;
        const wchar_t *name = path;
        for (const wchar_t *p = path; *p != L'\0'; ++p) {
            if (*p == L'\\' || *p == L'/') name = p + 1;
        }
        size_t name_length = 0;
        while (name[name_length] != L'\0') ++name_length;
        constexpr wchar_t needle[] = L"dontstarve";
        constexpr size_t needle_length = 10;
        if (name_length < needle_length) return false;
        for (size_t i = 0; i + needle_length <= name_length; ++i) {
            bool match = true;
            for (size_t k = 0; k < needle_length; ++k) {
                wchar_t c = name[i + k];
                if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
                if (c != needle[k]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
#else
        char path[4096];
#ifdef __APPLE__
        uint32_t size = static_cast<uint32_t>(sizeof(path));
        if (_NSGetExecutablePath(path, &size) != 0) return false;
        const char *name = std::strrchr(path, '/');
        name = name != nullptr ? name + 1 : path;
        return name_contains_dontstarve(name, std::strlen(name));
#else
        const ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
        if (length <= 0) return false;
        path[length] = '\0';
        const char *name = std::strrchr(path, '/');
        name = name != nullptr ? name + 1 : path;
        return name_contains_dontstarve(name, static_cast<size_t>(length) - static_cast<size_t>(name - path));
#endif
#endif
    }

    ds::alloc::Options alloc_shim_options() noexcept {
        ds::alloc::Options options{};
        options.enabled = ds::alloc::read_env_switch();
        options.stats = ds::alloc::read_env_stats();
        options.patch_all_modules = true;
        return options;
    }

    // phase 1: the allocator installed in phase 0 cannot log there (no logger, no
    // file IO, no InjectorCtx), so its state is reported once logging exists.
    void log_alloc_shim_state() {
        if (!ds::alloc::installed()) {
            if (!ds::alloc::read_env_switch()) {
                spdlog::info("alloc shim: disabled by DS_ALLOC_SHIM");
                std::fprintf(stderr, "[alloc] disabled by DS_ALLOC_SHIM\n");
            } else if (ds::alloc::skipped_debug_crt()) {
                spdlog::info("alloc shim: skipped (debug CRT image loaded; release CRT only)");
                std::fprintf(stderr, "[alloc] skipped: debug CRT image\n");
            } else {
                spdlog::error("alloc shim: install failed backend={} failures={}",
                              ds::alloc::backend_name(), ds::alloc::failure_count());
                std::fprintf(stderr, "[alloc] install failed backend=%s failures=%zu\n",
                             ds::alloc::backend_name(), ds::alloc::failure_count());
            }
            return;
        }
        spdlog::info("alloc shim: backend={} primary={} slots={} failures={}",
                     ds::alloc::backend_name(), ds::alloc::primary_target_patched() ? 1 : 0,
                     ds::alloc::patched_slot_count(), ds::alloc::failure_count());
        std::fprintf(stderr, "[alloc] backend=%s primary=%d slots=%zu failures=%zu\n",
                     ds::alloc::backend_name(), ds::alloc::primary_target_patched() ? 1 : 0,
                     ds::alloc::patched_slot_count(), ds::alloc::failure_count());
        if (!ds::alloc::primary_target_patched()) {
            spdlog::error("alloc shim: primary target not patched, allocations stay on the CRT");
            std::fprintf(stderr, "[alloc] primary target not patched\n");
        } else if (ds::alloc::failure_count() != 0) {
            spdlog::warn("alloc shim: {} entries failed (partial coverage)", ds::alloc::failure_count());
        }
    }

    void mimalloc_stats_line(const char *message, void *) {
        if (message == nullptr) return;
        std::string_view line{message};
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.remove_suffix(1);
        if (!line.empty()) spdlog::info("[mimalloc] {}", line);
    }

    // DS_ALLOC_SHIM_STATS: own/foreign counters plus the allocator's own stats.
    // mi_option_show_stats is never used: it would LoadLibrary("psapi.dll") during
    // DLL_PROCESS_DETACH.
    void log_alloc_shim_stats() {
        if (!ds::alloc::installed() || !ds::alloc::read_env_stats()) return;
        const auto s = ds::alloc::stats();
        spdlog::info("alloc shim stats: malloc={} free_own={} free_foreign={} realloc_foreign={}",
                     s.malloc_calls, s.free_own, s.free_foreign, s.realloc_foreign);
        std::fprintf(stderr, "[alloc] stats malloc=%llu free_own=%llu free_foreign=%llu realloc_foreign=%llu\n",
                     static_cast<unsigned long long>(s.malloc_calls), static_cast<unsigned long long>(s.free_own),
                     static_cast<unsigned long long>(s.free_foreign), static_cast<unsigned long long>(s.realloc_foreign));
        mi_stats_print_out(&mimalloc_stats_line, nullptr);
    }

}// namespace


void wait_for_debugger_before_inject() {
#ifndef NDEBUG
    if (InjectorConfig::instance()->LuajitWaitDebuggerEnable) {
        while (!gum_process_is_debugger_attached()) {
            std::this_thread::sleep_for(200ms);
        }
    }
#endif
}


G_NORETURN void showError(const std::string_view &msg) {
#ifdef _WIN32
    // Release builds log at error level only, and a bare MessageBox behind the
    // game window leaves the user with "the process just exited, no dump".
    spdlog::error("fatal: {}", msg);
    if (auto *logger = spdlog::default_logger_raw()) logger->flush();
    MessageBoxA(NULL, msg.data(), "error!", MB_SETFOREGROUND | MB_TOPMOST | MB_ICONERROR);
#else
    spdlog::error("error: {}", msg);
#endif
    std::exit(1);
}


static bool server_is_master() {
    return std::string_view{get_cmd()}.contains("DST_Master");
}

static bool check_crash() {
    if (!getenv("SteamClientLaunch")) {
        return true;
    }
    if (!InjectorCtx::instance()->DontStarveInjectorIsClient) {
        return true;
    }
#ifndef NDEBUG
    return true;
#endif// !NDEBUG
    // Requires the Steam account id: the sentinel lives next to the mod's files
    // in the save dir, so check_crash must run after sdk::steam::Initialize.
    return ds::unsafedata::allow_inject(ds::unsafedata::sentinel_path());
}

void DisableScriptZip() {
    if (!InjectorConfig::instance()->DisableGameScriptsZip) {
        return;
    }
    // DEV=databundles/scripts.zip — resolved through the shared provider registry
    // (the pattern itself lives in core/InjectorSignatures.cpp, not here).
    constexpr auto key = "DEV=databundles/scripts.zip"sv;
    ds::sig::ResolveReport report{};
    if (ds::sig::resolve_entry("injector.scripts_zip", &report) && report.target_va != 0) {
        gum_memory_write((void *) report.target_va, (const guint8 *) "DEV=databundles/script1.zip", key.size());
        spdlog::info("disable script zip[{}]", (void *) report.target_va);
    }
}

// VM soft-skip (DisableJITWhenServer / DS_LUAJIT_FORCE_DISABLE_VM) lives in
// CoreVmBootstrap — L0 never aborts Inject for those flags (OB-S1).



// VM signature/replace is owned by plugin_core_vm (ds_core_vm_run_signature_and_replace).
// No in-process legacy fallback after Task 3.

extern "C" void LoadGameModConfig();
DONTSTARVEINJECTOR_API void Inject(bool isClient) {
    auto ictx = InjectorCtx::instance();
    if (ictx->config.DontStarveInjectorDisable) {
        spdlog::info("DontStarveInjector is disabled");
        return;
    }
    if (!function_relocation::init_ctx()) {
        showError("can't init signature");
        return;
    }
    auto defer = create_defer(&function_relocation::deinit_ctx);


    ictx->DontStarveInjectorIsClient = isClient;
#ifdef _WIN32
    const auto log_path = std::format("DontStarveInjector_{}.log", isClient ? "client"s : "server"s);
    auto logger = std::make_shared<spdlog::logger>("", std::make_shared<spdlog::sinks::msvc_sink_st>());
    // Append, do not truncate: the failure a user is reporting survived the process
    // exit, and the next launch used to erase it before anyone could read it.
    logger->sinks().push_back(std::make_shared<spdlog::sinks::basic_file_sink_st>(log_path, false));
    spdlog::set_default_logger(std::move(logger));
#endif
#ifdef __linux__
    const auto log_path = std::format("DontStarveInjector_{}.log", isClient ? "client"s : std::format("server_{}", server_is_master() ? "master" : "caves"));
    spdlog::default_logger()->sinks().push_back(std::make_shared<spdlog::sinks::basic_file_sink_st>(log_path));
#endif
#if USE_LISTENER
    interceptor = InjectorCtx::instance()->GetGumInterceptor();
#endif

    spdlog::set_level(spdlog::level::err);
#if defined(DEBUG) || defined(_DEBUG)
    spdlog::set_level(spdlog::level::trace);
#endif
    if (gum_process_is_debugger_attached()) {
        spdlog::set_level(spdlog::level::debug);
    }
    spdlog::flush_on(spdlog::level::trace);
    // Explicit level wins over the defaults above, for either the process env
    // (`log_level=info`) or a launcher argument (`-log_level=info`). set_level()
    // applies to every registered logger, so the FunctionRelocation file follows too.
    if (const char *requested = ictx->config.log_level; requested && *requested) {
        std::string_view name{requested};
        if (name == "warning") name = "warn";
        if (name == "error") name = "err";
        const auto parsed = spdlog::level::from_str(std::string{name});
        // from_str() maps anything unrecognized to off: a typo must not mute the log.
        if (parsed != spdlog::level::off || name == "off") {
            spdlog::set_level(parsed);
            spdlog::warn("log level set to '{}' by log_level={}", spdlog::level::to_string_view(parsed), requested);
        } else {
            spdlog::error("unknown log_level='{}' (trace|debug|info|warn|err|critical|off); keeping default",
                          requested);
        }
    }
    spdlog::info("Inject start: isClient={} debuggerAttached={}", isClient, gum_process_is_debugger_attached());

#ifndef _WIN32
    // Whatever dlopen()ed between phase 0 and now (before the rescan hook existed).
    ds::alloc::detail::rescan_modules();
#endif
    log_alloc_shim_state();
    log_alloc_shim_stats();

#ifdef ENABLE_STEAM_SUPPORT
    ds::sdk::steam::Initialize(isClient);
#endif

    // Runtime state is shared with the mod through <save dir>/unsafedata (DST io
    // sandbox root). Create it so the mod's first relative write can land, even
    // when the crash guard below is compiled out.
    if (const auto state_dir = ds::unsafedata::dir(); !state_dir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(state_dir, ec);
        spdlog::info("unsafedata dir: {}", state_dir);
    }

    if (!check_crash()) {
        spdlog::error("skip inject, find crash content");
        return;
    }

    // SignatureManager target context + the L0 provider must exist before
    // LoadGameModConfig(): its SetThreadName / scripts-zip consumers resolve
    // through the same registry every plugin uses.
    {
        ds::sig::RuntimeTarget target{};
        target.platform = ds::sig::host_platform();
        target.is_client = isClient;
        ds::sig::configure_runtime(target);
#if defined(DS_SIG_HAVE_INJECTOR)
        std::string provider_detail;
        if (!ds::sig::register_injector_provider(&provider_detail)) {
            spdlog::warn("injector signature provider rejected: {}", provider_detail);
        }
#endif
    }
    LoadGameModConfig();

    // PluginHost: static RegisterBuiltinPlugins (empty extension point) then
    // DynamicPluginLoader (network.rpc / render.vbpool / render.angle / core.vm / …).
    // OB-S2/S4: load modules (schema register) BEFORE full cascade resolve so
    // save/env can apply VM + business keys registered in module_init.
    {
        using namespace ds::plugin;
        static PluginHost g_plugin_host;
        // L0 base schema must exist even with zero plugins (C-S6 / OB-S2).
        // Business keys come only from plugins (OB-S4).
        RegisterCoreOptionSchema(g_plugin_host.option_schema());
        RegisterBuiltinPlugins(g_plugin_host);
        // The VM's lj_ds_puc_dump slot is filled by core.vm (jit/jit_gen) from this
        // service, so it must be published before any plugin module is initialized:
        // a missing service is a hard failure for the mod dump path, not a silent
        // fallback to LuaJIT bytecode.
        if (!register_service("ds_lua_puc51_dump", &ds::puc51::Dump)) {
            spdlog::error("cannot register service ds_lua_puc51_dump (PUC 5.1 mod string.dump unavailable)");
        }
        {
            static DynamicPluginLoader g_dyn_loader;
            auto report = g_dyn_loader.load_all(g_plugin_host, isClient);
            for (auto &p : report.loaded_modules) {
                spdlog::info("dynamic plugin module loaded: {}", p);
            }
            for (auto &s : report.skipped) {
                spdlog::warn("dynamic plugin module skipped: {}", s);
            }
            // Providers published by modules whose init succeeded become the
            // Manager's registry. Registration order here is load order, so a
            // duplicate name is rejected deterministically instead of racing.
            for (size_t i = 0; i < g_plugin_host.signature_provider_count(); ++i) {
                std::string provider_detail;
                if (!ds::sig::add_provider(g_plugin_host.signature_provider(i), &provider_detail)) {
                    spdlog::warn("signature provider rejected: {}", provider_detail);
                    std::fprintf(stderr, "[signature] provider rejected: %s\n", provider_detail.c_str());
                }
            }
            for (auto *e : g_plugin_host.option_schema().all()) {
                const char *type_name = "None";
                switch (e->type) {
                case ConfigValueType::Bool:
                    type_name = "Bool";
                    break;
                case ConfigValueType::String:
                    type_name = "String";
                    break;
                case ConfigValueType::Number:
                    type_name = "Number";
                    break;
                case ConfigValueType::None:
                default:
                    break;
                }
                spdlog::info("option schema: {} type={}", e->key, type_name);
                // Default Injector log level is err; mirror to stderr so L-G/server capture sees keys.
                std::fprintf(stderr, "option schema: %s type=%s\n", e->key.c_str(), type_name);
            }
        }

        // Merge late keys (VM from core.vm, business from plugins) and re-resolve.
        ds::config::refresh_cascade_after_plugins(g_plugin_host.option_schema());

        // core.vm is required: force-load plugin_core_vm and run signature/replace.
        // Missing module/export aborts inject. Soft skip only for intentional VM disable
        // (server DisableJITWhenServer / DS_LUAJIT_FORCE_DISABLE_VM) or soft miss.
        {
            ds::core_vm::BootstrapArgs args{};
            args.is_client = isClient;
            args.lua_module_base = 0;
            args.main_path = nullptr;
            if (!ds::core_vm::ForceRunSignatureAndReplace(args)) {
                spdlog::warn("core.vm signature/replace soft-skipped — continuing inject");
                std::fprintf(stderr, "[core.vm] signature/replace soft-skipped — continuing inject\n");
            }
        }

        // CF-S4: PluginHost gates from cascade ResolvedConfig.view SSOT.
        ConfigView plugin_cfg;
        if (auto *rc = ds::config::current()) {
            plugin_cfg = BuildConfigView(g_plugin_host.option_schema(), rc->view);
        }
        PluginContext gate_ctx;
        gate_ctx.injector = InjectorCtx::instance();
        gate_ctx.is_client = isClient;
        gate_ctx.config = &plugin_cfg;
        (void) g_plugin_host.resolve(plugin_cfg, gate_ctx);
        (void) g_plugin_host.load_phase(PluginPhase::EarlyNative);
    }

#ifndef _WIN32
    // Backstop for images the dlopen hook did not see (namespace loads, failed hook).
    ds::alloc::detail::rescan_modules();
#endif

    DisableScriptZip();
    log_alloc_shim_stats();
}


#ifndef _WIN32
#include <dlfcn.h>

// Task 6: images loaded after phase 0 must join the shim too. The dlopen return is
// the cheapest reliable trigger; a failed install only costs coverage, never the
// process. macOS needs none of this - dyld reports image additions itself.
#if !defined(__APPLE__)
using DlopenFn = void *(*)(const char *, int);
using DlmopenFn = void *(*)(const char *, int, long);

DlopenFn original_dlopen = nullptr;
DlmopenFn original_dlmopen = nullptr;

void *dlopen_rescan_hook(const char *path, int flags) {
    void *handle = original_dlopen(path, flags);
    if (handle != nullptr) ds::alloc::detail::rescan_modules();
    return handle;
}

void *dlmopen_rescan_hook(const char *path, int flags, long namespace_id) {
    void *handle = original_dlmopen(path, flags, namespace_id);
    if (handle != nullptr) ds::alloc::detail::rescan_modules();
    return handle;
}
#endif

int (*origin)(const char *path);
int chdir_hook(const char *path) {
    static bool injector = false;
    if ("../data"sv == path && !injector) {
        wait_for_debugger_before_inject();
        auto isClientMode =
            !ds::util::path_to_native_lossy(getExePath()).contains("dontstarve_dedicated_server_nullrenderer");
        Inject(isClientMode);
        spdlog::default_logger_raw()->flush();
        injector = true;
    }
    return origin(path);
}

extern char *__progname;
static bool gum_initialized = false;
static std::atomic_bool posix_startup_hook_installed = false;

// Shared by constructor (LD_PRELOAD / direct load) and HookStartupEntry (bootstrap
// stub after dlopen). Idempotent: only the first caller installs the chdir hook.
static bool install_posix_startup_hook() {
    bool expected = false;
    if (!posix_startup_hook_installed.compare_exchange_strong(expected, true)) {
        return true;
    }

    auto api = dlsym(RTLD_DEFAULT, "chdir");
    if (!api) {
        posix_startup_hook_installed = false;
        return false;
    }
    if (!gum_initialized) {
        gum_init_embedded();
        gum_initialized = true;
    }
    auto interceptor = InjectorCtx::instance()->GetGumInterceptor();
    ds::gum::replace(interceptor, api, (void *) &chdir_hook, (void **) &origin);
    if (!origin) {
        posix_startup_hook_installed = false;
        return false;
    }

#if !defined(__APPLE__)
    static bool rescan_hooks_installed = false;
    if (!rescan_hooks_installed) {
        rescan_hooks_installed = true;
        if (auto *dlopen_fn = dlsym(RTLD_DEFAULT, "dlopen"); dlopen_fn != nullptr) {
            ds::gum::replace(interceptor, dlopen_fn, reinterpret_cast<void *>(&dlopen_rescan_hook),
                             reinterpret_cast<void **>(&original_dlopen));
            if (original_dlopen == nullptr) {
                std::fprintf(stderr, "[alloc] dlopen rescan hook rejected; later images stay unshimmed\n");
            }
        }
        if (auto *dlmopen_fn = dlsym(RTLD_DEFAULT, "dlmopen"); dlmopen_fn != nullptr) {
            ds::gum::replace(interceptor, dlmopen_fn, reinterpret_cast<void *>(&dlmopen_rescan_hook),
                             reinterpret_cast<void **>(&original_dlmopen));
        }
    }
#endif
    return true;
}

__attribute__((constructor)) void init() {
    if (!is_dontstarve_process()) {
        return;
    }
    // phase 0: no logging, no file IO, no InjectorCtx - only the GOT rewrite.
    (void) ds::alloc::install_early(alloc_shim_options());
    (void) install_posix_startup_hook();
}

__attribute__((destructor)) void fini() {
    ds::alloc::set_shutting_down();
    if (!gum_initialized) {
        return;
    }
    if (ds::alloc::installed() && ds::alloc::read_env_stats()) {
        const auto s = ds::alloc::stats();
        std::fprintf(stderr, "[alloc] final stats malloc=%llu free_own=%llu free_foreign=%llu realloc_foreign=%llu\n",
                     static_cast<unsigned long long>(s.malloc_calls), static_cast<unsigned long long>(s.free_own),
                     static_cast<unsigned long long>(s.free_foreign), static_cast<unsigned long long>(s.realloc_foreign));
    }
    _exit(0);
}

// Exported for shell bootstrap (InjectorStub) dlsym("HookStartupEntry").
// Constructor may already have installed the chdir hook — return true when ready.
DONTSTARVEINJECTOR_API bool HookStartupEntry() {
    if (posix_startup_hook_installed.load(std::memory_order_acquire)) {
        return true;
    }
    return install_posix_startup_hook();
}

#else
using SetCurrentDirectoryWFn = BOOL(WINAPI *)(LPCWSTR);
SetCurrentDirectoryWFn original_SetCurrentDirectoryW = nullptr;

void inject_from_startup_entry() {
    static std::atomic_bool startup_injected = false;
    bool expected = false;
    if (!startup_injected.compare_exchange_strong(expected, true)) {
        return;
    }

    wait_for_debugger_before_inject();

    const auto is_client_mode =
        !ds::util::path_to_native_lossy(getExePath()).contains("dontstarve_dedicated_server_nullrenderer");
    Inject(is_client_mode);
    if (auto *logger = spdlog::default_logger_raw()) {
        logger->flush();
    }
}

static BOOL WINAPI SetCurrentDirectoryW_hook(LPCWSTR path) {
    if (path != nullptr && std::wstring_view{path} == L"../data") {
        inject_from_startup_entry();
    }
    return original_SetCurrentDirectoryW(path);
}

DONTSTARVEINJECTOR_API bool HookStartupEntry() {
    static std::atomic_bool startup_hook_installed = false;
    bool expected = false;
    if (!startup_hook_installed.compare_exchange_strong(expected, true)) {
        return true;
    }

    if (!is_dontstarve_process()) {
        startup_hook_installed = false;
        return false;
    }

    gum_init_embedded();

    // phase 0: replace the CRT allocation entry points before anything else in this
    // process allocates again. No getExePath() and no InjectorCtx::instance() above
    // this line: both allocate, and InjectorCtx would build the config first.
    (void) ds::alloc::install_early(alloc_shim_options());

    const auto kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) {
        startup_hook_installed = false;
        return false;
    }

    const auto set_current_directory_w = GetProcAddress(kernel32, "SetCurrentDirectoryW");
    if (!set_current_directory_w) {
        startup_hook_installed = false;
        return false;
    }

    auto interceptor = gum_interceptor_obtain();// same singleton, without InjectorCtx
    ds::gum::replace(
        interceptor,
        set_current_directory_w,
        reinterpret_cast<void *>(&SetCurrentDirectoryW_hook),
        reinterpret_cast<void **>(&original_SetCurrentDirectoryW));

    return original_SetCurrentDirectoryW != nullptr;
}

// Pinning (GET_MODULE_HANDLE_EX_FLAG_PIN) makes DLL_PROCESS_DETACH mean process
// exit, so this is the one point where a late module can still call the shim:
// release stays disabled from here on instead of touching a dying allocator.
BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_DETACH) {
        ds::alloc::set_shutting_down();
    }
    return TRUE;
}


#endif