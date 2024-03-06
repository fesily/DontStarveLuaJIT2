#include <format>
#include <fstream>
#include <iostream>
#include <ranges>
#include <algorithm>
#include <frida-gum.h>
#include <spdlog/spdlog.h>
#include <filesystem>
#include <thread>

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


int update(bool isClient, const char *path)
{
    fprintf(stderr, "game_path:\t%s\n", path);
#ifdef _WIN32
    if (!loadModule(path))
        return 1;
#endif
    if (luaModuleSignature.scan(path) == 0)
    {
        fprintf(stderr, "%s", "can find lua module base addr\n");
        return 1;
    }

    auto updater = SignatureUpdater::create(isClient, luaModuleSignature.target_address);
    if (!updater)
    { 
        fprintf(stderr, "%s", updater.error().c_str());
        return 1;
    }
    return 0;
}

bool pre_updater()
{
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
static bool (*orgin)(uint32_t unOwnAppID);
static bool SteamAPI_RestartAppIfNecessary_hook(uint32_t unOwnAppID)
{
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(10000s);
    return orgin(unOwnAppID);
}
__attribute__((constructor)) void init()
{
    gum_init_embedded();
    auto path = std::filesystem::path(gum_process_get_main_module()->path).string();
    if (!path.contains("dontstarve"))
    {
        gum_deinit_embedded();
        return;
    }
    auto hsteam = dlopen("libsteam_api.so", RTLD_NOW);
    auto api = dlsym(hsteam, "SteamAPI_RestartAppIfNecessary");
    if (!api)
    {
        gum_deinit_embedded();
        return;
    }
    auto interceptor = gum_interceptor_obtain();
    gum_interceptor_replace_fast(interceptor, api, (void *)&SteamAPI_RestartAppIfNecessary_hook, (void **)&orgin);
    std::thread([path]()
                {
    bool isClient = !path.contains("nullrenderer");
    if (pre_updater())
        _exit(update(isClient, path.c_str()));
    _exit(-1); })
        .detach();
}
#endif
