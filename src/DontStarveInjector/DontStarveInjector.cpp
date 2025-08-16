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
#include "luajit_config.hpp"
#include "GameLua.hpp"
#include "GameSteam.hpp"
#include "GameNetwork.hpp"
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

G_NORETURN void showError(const std::string_view &msg) {
#ifdef _WIN32
    MessageBoxA(NULL, msg.data(), "error!", 0);
#else
    spdlog::error("error: {}", msg);
#endif
    std::exit(1);
}


void replace_game_branch_flag_to_dev(const std::string &mainPath) {
#define REPALCE_CONST_STRING_BRANCH_DEV 1
#ifndef NDEBUG
#ifdef REPALCE_CONST_STRING_BRANCH_DEV
#ifdef _WIN32
    function_relocation::ModuleSections moduleMain{};
    using namespace std::literals;

    if (function_relocation::get_module_sections(mainPath.c_str(), moduleMain)) {
        function_relocation::MemorySignature scaner{"00 72 65 6C 65 61 73 65 00", 1};
        auto str = (char *) scaner.scan(moduleMain.rodata.base_address, moduleMain.rodata.size);
        if (str && "release"sv == (str + 1)) {
            GumPageProtection prot;
            if (gum_memory_query_protection(str, &prot) && gum_try_mprotect(str, 4, GUM_PAGE_RW)) {
                gum_memory_write(str, (const guint8 *) "dev", 4);
                gum_try_mprotect(str, 4, prot);
            }
        }
    }
#endif
#endif
#endif
}

static bool server_is_master() {
    return std::string_view{get_cmd()}.contains("DST_Master");
}

static bool check_crash() {
    if (!getenv("SteamClientLaunch")) {
        return true;
    }
    if (!InjectorConfig::instance().DontStarveInjectorIsClient) {
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
    if (!InjectorConfig::instance().DisableGameScriptsZip) {
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
    if (InjectorConfig::instance().DontStarveInjectorDisable) {
        spdlog::info("DontStarveInjector is disabled");
        return;
    }
    if (!isClient) {
        auto config = luajit_config::read_from_file();
        if (config && config->server_disable_luajit) {
            return;
        }
    }

    InjectorConfig::instance().DontStarveInjectorIsClient = isClient;
#ifdef _WIN32
    gum_init();
    spdlog::set_default_logger(std::make_shared<spdlog::logger>("", std::make_shared<spdlog::sinks::msvc_sink_st>()));
#endif
#ifdef __linux__
    const auto log_path = std::format("DontStarveInjector_{}.log", isClient ? "client"s : std::format("server_{}", server_is_master() ? "master" : "caves"));
    spdlog::default_logger()->sinks().push_back(std::make_shared<spdlog::sinks::basic_file_sink_st>(log_path));
#endif
#if USE_LISTENER
    interceptor = gum_interceptor_obtain();
#endif

    spdlog::set_level(spdlog::level::err);
#ifdef DEBUG
    spdlog::set_level(spdlog::level::trace);
#endif
    if (gum_process_is_debugger_attached()) {
        spdlog::set_level(spdlog::level::debug);
    }

    if (!check_crash()) {
        spdlog::error("skip inject, find crash content");
        return;
    }


    if (!function_relocation::init_ctx()) {
        showError("can't init signature");
        return;
    }
    auto defer = create_defer(&function_relocation::deinit_ctx);

    auto lua51 = loadlib(lua51_name);
    if (!lua51) {
        showError("can't load lua51");
        return;
    }
    auto defer1 = create_defer([lua51]() {
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
    auto &val = res.value();
    ReplaceLuaModule(mainPath, val.signatures, val.exports);
#if 0
    RedirectOpenGLEntries();
#endif
    replace_game_branch_flag_to_dev(mainPath);

    LoadGameModConfig();
    if (!InjectorConfig::instance().DontStarveInjectorIsClient) {
        HookSteamGameServerInterface();
    }
    GameNetWorkHookRpc4();
    DisableScriptZip();
}


#ifndef _WIN32
#include <dlfcn.h>

int (*origin)(const char *path);
int chdir_hook(const char *path) {
    static bool injector = false;
    if ("../data"sv == path && !injector) {
#ifndef NDEBUG
        if (InjectorConfig::instance().LuajitWaitDebuggerEnable) {
            while (!gum_process_is_debugger_attached()) {
                std::this_thread::sleep_for(200ms);
            }
        }

#endif
        auto isClientMode = !getExePath().string().contains("dontstarve_dedicated_server_nullrenderer");
        Inject(isClientMode);
        spdlog::default_logger_raw()->flush();
        injector = true;
    }
    return origin(path);
}
__attribute__((constructor)) void init() {
    gum_init_embedded();
    auto path = std::filesystem::path(gum_module_get_path(gum_process_get_main_module())).filename().string();
    if (!path.contains("dontstarve")) {
        gum_deinit_embedded();
        return;
    }
    auto api = dlsym(RTLD_DEFAULT, "chdir");
    if (!api) {
        gum_deinit_embedded();
        return;
    }
    auto intercetor = gum_interceptor_obtain();
    gum_interceptor_replace_fast(intercetor, api, (void *) &chdir_hook, (void **) &origin);
}
#endif