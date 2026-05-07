// DontStarveInjector.cpp : Defines the exported functions for the DLL application.
//

#include "config.hpp"
#include "util/inlinehook.hpp"
#include "GameSignature.hpp"
#include "DontStarveSignature.hpp"
#include "util/platform.hpp"
#include "ctx.hpp"
#include "ModuleSections.hpp"
#include "disasm.h"
#include "ScanCtx.hpp"
#include "ProcessMutex.hpp"
#include "gameModConfig.hpp"
#include "GameLua.hpp"
#include "GameSteam.hpp"
#include "GameNetwork.hpp"
#include "GameRenderHook.hpp"
#include <spdlog/spdlog.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_NONSTDC_NO_WARNINGS
#include <windows.h>
#include <spdlog/sinks/msvc_sink.h>
#else
#include <pthread.h>
#endif

#include <string>
#include <algorithm>
#include <map>
#include <cstdint>
#include <list>
#include <atomic>


#if USE_LISTENER
#include <frida-gum.h>
#endif
#include <spdlog/sinks/basic_file_sink.h>


#if !ONLY_LUA51
#include <lua.hpp>
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

#ifdef _WIN32
namespace {
using GetBuildTypeFn = const char *(*)(void *self);
GetBuildTypeFn original_get_build_type = nullptr;

const char *forced_get_build_type(void *self) {
    (void) self;
    return "dev";
}

uintptr_t find_build_type_function(const function_relocation::ModuleSections &module_main) {
    function_relocation::MemorySignature build_type_signature{"48 8B 05 ?? ?? ?? ?? C3", 0};
    build_type_signature.only_one = false;
    build_type_signature.log = false;
    build_type_signature.prot_flag = GUM_PAGE_EXECUTE;
    if (!build_type_signature.scan(module_main.text.base_address, module_main.text.size)) {
        return 0;
    }

    for (const auto candidate : build_type_signature.targets) {
        auto insn = function_relocation::disasm::get_insn(reinterpret_cast<void *>(candidate), 8);
        if (!insn || insn->detail->x86.op_count != 2) {
            continue;
        }

        const auto &x86 = insn->detail->x86;
        if (x86.operands[0].type != X86_OP_REG || x86.operands[1].type != X86_OP_MEM) {
            continue;
        }

        const auto string_ptr_address = function_relocation::read_operand_rip_mem(*insn, x86.operands[1]);
        if (!string_ptr_address || !module_main.in_rodata(*reinterpret_cast<uintptr_t *>(string_ptr_address))) {
            continue;
        }

        const auto build_type = reinterpret_cast<const char *>(*reinterpret_cast<uintptr_t *>(string_ptr_address));
        if (build_type && std::string_view{build_type} == "release") {
            return candidate;
        }
    }

    return 0;
}
} // namespace
#endif

G_NORETURN void showError(const std::string_view &msg) {
#ifdef _WIN32
    MessageBoxA(NULL, msg.data(), "error!", 0);
#else
    spdlog::error("error: {}", msg);
#endif
    std::exit(1);
}


void replace_game_branch_flag_to_dev(const std::string &mainPath) {
#ifdef _WIN32
    if (!InjectorConfig::instance()->AppVersionDevPatch) {
        return;
    }

    static bool patched = false;
    if (patched) {
        return;
    }

    function_relocation::ModuleSections moduleMain{};
    if (!function_relocation::get_module_sections(mainPath.c_str(), moduleMain)) {
        spdlog::error("failed to get module sections for {}", mainPath);
        return;
    }

    const auto target = find_build_type_function(moduleMain);
    if (!target) {
        spdlog::error("failed to locate GetBuildType function by binary signature");
        return;
    }

    auto interceptor = InjectorCtx::instance()->GetGumInterceptor();
    auto replace_result = gum_interceptor_replace(
        interceptor,
        reinterpret_cast<void *>(target),
        reinterpret_cast<void *>(&forced_get_build_type),
        nullptr,
        reinterpret_cast<void **>(&original_get_build_type));
    if (replace_result != GUM_REPLACE_OK) {
        spdlog::error("failed to replace GetBuildType at {}: {}", reinterpret_cast<void *>(target), static_cast<int>(replace_result));
        return;
    }

    patched = true;
    spdlog::info("patched GetBuildType at {} to force dev build type", reinterpret_cast<void *>(target));
#endif
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

    if (!isClient) {
        auto config = GameJitModConfig::instance();
        if (config && config->DisableJITWhenServer) {
            return;
        }
    }

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

    HookSteamGameServerInterface();

    auto lua51 = loadlib(lua51_name);
    if (!lua51) {
        showError("can't load lua51");
        return;
    }
    auto defer1 = create_defer([&lua51]() {
        if (lua51)
            unloadlib(lua51);
    });

    spdlog::info("main module base address:{}", (void *) gum_module_get_range(gum_process_get_main_module())->base_address);
    auto mainPath = getExePath().string();
    if (luaModuleSignature.scan(mainPath.c_str()) == 0) {
        spdlog::error("can't find luamodule base address");
        return;
    }
    ProcessMutex mtx("DontStarveInjectorSignature");
    std::lock_guard guard{mtx};
    auto res = SignatureUpdater::create_or_update(isClient, luaModuleSignature.target_address);
    if (!res) {
        showError(res.error());
        return;
    }
    unloadlib(lua51);
    auto &val = res.value();
    ReplaceLuaModule(mainPath, val.signatures, val.exports);
    replace_game_branch_flag_to_dev(mainPath);

    LoadGameModConfig();
    GameNetWorkHookRpc4();
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
__attribute__((constructor)) void init() {
    if (!getExePath().string().contains("dontstarve")) {
        return;
    }
    auto api = dlsym(RTLD_DEFAULT, "chdir");
    if (!api) {
        return;
    }
    gum_init_embedded();
    auto intercetor = InjectorCtx::instance()->GetGumInterceptor();
    gum_interceptor_replace_fast(intercetor, api, (void *) &chdir_hook, (void **) &origin);
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