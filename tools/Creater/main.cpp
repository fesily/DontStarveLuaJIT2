#include <format>
#include <fstream>
#include <iostream>
#include <ranges>
#include <algorithm>
#include <frida-gum.h>
#include <spdlog/spdlog.h>
#include <filesystem>
#include <thread>
#include <spdlog/sinks/basic_file_sink.h>

#include "platform.hpp"
#include "SignatureJson.hpp"
#include "LuaModule.hpp"
#include "DontStarveSignature.hpp"
#include "GameVersionFile.hpp"

#ifndef GAMEDIR
#error "not defined GAME_DIR"
#endif

#ifndef LUA51_PATH
#error "not defined LUA51_PATH"
#endif

#ifndef WORKER_DIR
#error "not defined WORKER_DIR"
#endif

const char *game_path = GAMEDIR R"(/bin64/dontstarve_steam_x64)" EXECUTABLE_SUFFIX;
const char *game_server_path = GAMEDIR R"(/bin64/dontstarve_dedicated_server_nullrenderer_x64)" EXECUTABLE_SUFFIX;
const char *lua51_path = LUA51_PATH;
const char *worker_dir = WORKER_DIR;


int update(bool isClient, const char *path) {
    fprintf(stderr, "game_path:\t%s\n", path);
#ifdef _WIN32
    if (!loadlib(path)){
        fprintf(stderr, "can't load %s\n", path);
        return 1;
    }
#endif
    if (luaModuleSignature.scan(path) == 0) {
        fprintf(stderr, "%s", "can find lua module base addr\n");
        return 1;
    }

    auto updater = SignatureUpdater::create(isClient, luaModuleSignature.target_address);
    if (!updater) {
        fprintf(stderr, "%s", updater.error().c_str());
        return 1;
    }
    return 0;
}

bool pre_updater() {
    set_worker_directory(worker_dir);
    SignatureJson::version_path = GAMEDIR "/version.txt";
    return loadlib(lua51_path);
}

#ifdef _WIN32
int main()
{
    gum_init_embedded();
    if (pre_updater())
        return update(true, game_path) + update(false, game_server_path);
    return -1;
}
#else

#include <dlfcn.h>
#include <chrono>
#include "ExectuableSignature.hpp"
#include "ctx.hpp"
static void create_signature() {
    function_relocation::init_ctx();
    exit(!function_relocation::FileSignature::create_file_signature(gum_process_get_main_module()->path));
}

static bool (*orgin)(uint32_t unOwnAppID);

static bool SteamAPI_RestartAppIfNecessary_hook(uint32_t unOwnAppID) {
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(10000s);
    return orgin(unOwnAppID);
}
static bool (*orgin1)(uint32_t unIP, uint16_t usSteamPort, uint16_t usGamePort, uint16_t usQueryPort, int eServerMode, const char *pchVersionString );
bool SteamGameServer_Init_hook(uint32_t unIP, uint16_t usSteamPort, uint16_t usGamePort, uint16_t usQueryPort, int eServerMode, const char *pchVersionString ){
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(10000s);
    return orgin1(unIP, usSteamPort, usGamePort, usQueryPort, eServerMode, pchVersionString);
}

__attribute__((constructor)) void init() {
    gum_init_embedded();
    auto path = std::filesystem::path(gum_process_get_main_module()->path).filename().string();
    if (!path.contains("dontstarve")) {
        if (path.contains("lua51")) {
            std::thread(create_signature).detach();
        }else {
            gum_deinit_embedded();
        }
        return;
    }
    auto hsteam = dlopen("libsteam_api.so", RTLD_NOW);
    bool isClient = !path.contains("nullrenderer");
    auto api = dlsym(hsteam, isClient ? "SteamAPI_RestartAppIfNecessary" : "SteamInternal_GameServer_Init");
    if (!api) {
        gum_deinit_embedded();
        return;
    }
    auto interceptor = gum_interceptor_obtain();
    if (isClient) 
        gum_interceptor_replace_fast(interceptor, api, (void*) &SteamGameServer_Init_hook, (void **) &orgin1);
    else 
        gum_interceptor_replace_fast(interceptor, api, (void *) &SteamAPI_RestartAppIfNecessary_hook, (void **) &orgin);
    std::thread([isClient] {
                    if (pre_updater()) {
                        spdlog::set_default_logger(std::make_shared<spdlog::logger>("", std::make_shared<spdlog::sinks::basic_file_sink_st>("DontStarveInjector.log")));
                        exit(update(isClient, gum_process_get_main_module()->path));
                    }
                    exit(-1);
                }
    ).detach();
}

#endif
