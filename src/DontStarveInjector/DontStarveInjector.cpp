// DontStarveInjector.cpp : Defines the exported functions for the DLL application.
//

#include "config.hpp"
#include "util/inlinehook.hpp"
#include "util/platform.hpp"
#include "ctx.hpp"
#include "MemorySignature.hpp"
#include "gameModConfig.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginConfigBridge.hpp"
#include "config/ConfigSchema.hpp"
#include "config/ResolvedConfig.hpp"
#include "core/RegisterBuiltinPlugins.hpp"
#include "core/DynamicPluginLoader.hpp"
#include "core/CoreVmBootstrap.hpp"



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
#endif

#include <string>
#include <algorithm>
#include <map>
#include <cstdint>
#include <list>
#include <atomic>
#include <cstdio>


#include <frida-gum.h>
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
    MessageBoxA(NULL, msg.data(), "error!", 0);
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

    auto rootpath = getExePath().parent_path().parent_path();
    auto unsafedatapath = rootpath / "data" / "unsafedata" / "luajit_crash.json";
    if (std::filesystem::exists(unsafedatapath)) {
        auto fp = fopen(unsafedatapath.string().c_str(), "r+");
        char buf[32] = {};
        auto len = fread(buf, sizeof(char), 16, fp);
        fclose(fp);
        if (len > 0) {
            return false;
        }
    }
    auto fp = fopen(unsafedatapath.string().c_str(), "w");
    fwrite("{1}", 1, 3, fp);
    fclose(fp);
    return true;
}

/* 把字符串转换成hex数组*/
std::string String2Hex(std::string_view str) {
    std::string hex;
    hex.reserve(str.size() * 3);
    for (size_t i = 0; i < str.size(); ++i) {
        hex += fmt::format("{:02x} ", static_cast<uint8_t>(str[i]));
    }
    return hex;
}

void DisableScriptZip() {
    if (!InjectorConfig::instance()->DisableGameScriptsZip) {
        return;
    }
    // DEV=databundles/scripts.zip
    auto key = "DEV=databundles/scripts.zip"sv;
    auto key1 = String2Hex(key);
    function_relocation::MemorySignature signature = {key1.c_str(), 0};
    signature.prot_flag = GUM_PAGE_READ;
    if (signature.scan(nullptr)) {
        gum_memory_write((void *) signature.target_address, (const guint8 *) "DEV=databundles/script1.zip", key.size());
        spdlog::info("disable script zip[{}]", (void *) signature.target_address);
    }
}

static bool VmPathEnabled(bool isClient) {
    if (isClient) {
        return true;
    }
    // CI / harness: force DisableJITWhenServer-equivalent without mutating config.
    if (const char *env = std::getenv("DS_LUAJIT_FORCE_DISABLE_VM"); env && env[0] == '1') {
        return false;
    }
    // Ensure cascade has run; prefer ResolvedConfig accessors (CF-S5).
    (void) GameJitModConfig::instance();
    if (auto *rc = ds::config::current(); rc && rc->disable_jit_when_server()) {
        return false;
    }
    return true;
}


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
    logger->sinks().push_back(std::make_shared<spdlog::sinks::basic_file_sink_st>(log_path, true));
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
    spdlog::info("Inject start: isClient={} debuggerAttached={}", isClient, gum_process_is_debugger_attached());

    if (!check_crash()) {
        spdlog::error("skip inject, find crash content");
        return;
    }

    // Steam UGC workshop path hook lives in plugin_core_vm (with gameio).

    if (VmPathEnabled(isClient)) {
        ds::core_vm::BootstrapArgs args{};
        args.is_client = isClient;
        // lua_module_base / main_path resolved inside plugin when zero/null.
        args.lua_module_base = 0;
        args.main_path = nullptr;
        if (!ds::core_vm::TryRunSignatureAndReplace(args)) {
            // Hard failures call showError inside plugin_core_vm; soft skip when
            // module/export missing or soft miss (no luamodule base).
            spdlog::warn("core.vm signature/replace path skipped — continuing inject");
            std::fprintf(stderr, "[core.vm] signature/replace path skipped — continuing inject\n");
        }
    } else {
        spdlog::info("Lua VM path disabled — skipping signature/replace; native plugins continue");
        std::fprintf(stderr, "[core.vm] Lua VM path disabled — skipping signature/replace; native plugins continue\n");
    }

    LoadGameModConfig();

    // PluginHost: static RegisterBuiltinPlugins (empty extension point) then
    // DynamicPluginLoader (network.rpc / render.vbpool / render.angle / dummy).
    {
        using namespace ds::plugin;
        static PluginHost g_plugin_host;
        // L0 core schema must exist even with zero plugins (C-S6).
        RegisterCoreOptionSchema(g_plugin_host.option_schema());
        // Also seed builtin business keys so cascade defaults are present when
        // plugins fail to load; plugins re-register the same entries.
        RegisterBuiltinBusinessOptionSchema(g_plugin_host.option_schema());
        RegisterBuiltinPlugins(g_plugin_host);
        {
            static DynamicPluginLoader g_dyn_loader;
            auto report = g_dyn_loader.load_all(g_plugin_host);
            for (auto &p : report.loaded_modules) {
                spdlog::info("dynamic plugin module loaded: {}", p);
            }
            for (auto &s : report.skipped) {
                spdlog::warn("dynamic plugin module skipped: {}", s);
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


        // CF-S4: PluginHost gates from cascade ResolvedConfig.view SSOT.
        // Ensure resolve has run (fills ds::config::current()); then fill only
        // late schema defaults for keys registered after DynamicPluginLoader.
        (void) GameJitModConfig::instance();
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

    DisableScriptZip();
}


#ifndef _WIN32
#include <dlfcn.h>

int (*origin)(const char *path);
int chdir_hook(const char *path) {
    static bool injector = false;
    if ("../data"sv == path && !injector) {
        wait_for_debugger_before_inject();
        auto isClientMode = !getExePath().string().contains("dontstarve_dedicated_server_nullrenderer");
        Inject(isClientMode);
        spdlog::default_logger_raw()->flush();
        injector = true;
    }
    return origin(path);
}

extern char *__progname;
static bool gum_initialized = false;

__attribute__((constructor)) void init() {
    if (!getExePath().string().contains("dontstarve")) {
        return;
    }
    auto api = dlsym(RTLD_DEFAULT, "chdir");
    if (!api) {
        return;
    }
    gum_init_embedded();
    gum_initialized = true;
    auto intercetor = InjectorCtx::instance()->GetGumInterceptor();
    gum_interceptor_replace_fast(intercetor, api, (void *) &chdir_hook, (void **) &origin);
}

__attribute__((destructor)) void fini() {
    if (!gum_initialized) {
        return;
    }
    _exit(0);
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

    const auto is_client_mode = !getExePath().string().contains("dontstarve_dedicated_server_nullrenderer");
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

    gum_init_embedded();

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

    auto interceptor = InjectorCtx::instance()->GetGumInterceptor();
    gum_interceptor_replace_fast(
        interceptor,
        set_current_directory_w,
        reinterpret_cast<void *>(&SetCurrentDirectoryW_hook),
        reinterpret_cast<void **>(&original_SetCurrentDirectoryW));

    return original_SetCurrentDirectoryW != nullptr;
}


#endif