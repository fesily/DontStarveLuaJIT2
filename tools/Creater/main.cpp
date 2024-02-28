#include <format>
#include <fstream>
#include <iostream>
#include <ranges>
#include <algorithm>
#include <frida-gum.h>
#include <spdlog/spdlog.h>
#include <filesystem>

#include "platform.hpp"
#include "missfunc.h"
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

bool loadModule(const char *path)
{
    GError *err = nullptr;
    if (!gum_module_load(path, &err))
    {
        g_error_free(err);
        fprintf(stderr, "load module error:%s-%s\n", path, err->message);
        return false;
    }
    return true;
}

int update(bool isClient, const char *path)
{
    SignatureJson sj{isClient};
    auto signatures_op = sj.read_from_signatures();
    if (!signatures_op.has_value())
    {
        fprintf(stderr, "can't read from json\n");
        return 1;
    }
    auto &signatures = signatures_op.value();
    fprintf(stderr, "game_path:\t%s\n", path);
    if (!loadModule(path))
        return 1;
    if (luaModuleSignature.scan(path) == 0)
    {
        fprintf(stderr, "%s", "can find lua module base addr\n");
        return 1;
    }

    ListExports_t exports;
    exports.assign_range(signatures.funcs);
    auto msg = update_signatures(signatures, luaModuleSignature.target_address, exports);
    if (!msg.empty())
    {
        fprintf(stderr, "%s\n", msg.c_str());
        return 1;
    }
    signatures.version = SignatureJson::current_version();
    auto name = isClient ? "client" : "server";
    sj.update_signatures(signatures);
    return 0;
}

bool pre_updater()
{
    gum_init_embedded();
    set_worker_directory(worker_dir);
    SignatureJson::version_path = GAMEDIR "/version.txt";
    return loadModule(lua51_path);
}

#ifdef _WIN32
int main()
{
    if (pre_updater())
        return update(true, game_path) + update(false, game_server_path);
    return -1;
}
#else
__attribute__(constructor) void init()
{
    auto path = std::path(gum_process_get_main_module()->path).string();
    bool isClient = !path.contains("nullrenderer");
    if (pre_updater())
        _exit(update(isClient, path.c_str()));
    _exit(-1);
}
#endif
