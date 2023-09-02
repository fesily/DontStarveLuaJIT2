#define NOMINMAX
#include <Windows.h>
#include <format>
#include <fstream>
#include <iostream>
#include <ranges>
#include <algorithm>
#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include "missfunc.h"
#include "signatures_server.hpp"
#include "signatures_client.hpp"
#include "LuaModule.hpp"
#include "DontStarveSignature.hpp"
#include "GameVersionFile.hpp"

#ifndef GAMEDIR
#error "not defined GAME_DIR"
#endif

#ifndef LUA51_PATH
#error "not defined LUA51_PATH"
#endif

const char *game_path = GAMEDIR R"(\bin64\dontstarve_steam_x64.exe)";
const char *game_server_path = GAMEDIR R"(\bin64\dontstarve_dedicated_server_nullrenderer_x64.exe)";
const char *lua51_path = LUA51_PATH;

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

int update(bool isClient)
{
    auto path = isClient ? game_path : game_server_path;
    auto signatures = isClient ? signatures_client : signatures_server;
    fprintf(stderr, "game_path:\t%s\n", path);
    if (!loadModule(path))
        return 1;
    if (luaModuleSignature.scan(path) == 0)
    {
        fprintf(stderr, "%s", "can find lua module base addr\n");
        return 1;
    }

    auto lua51_baseaddr = gum_module_find_base_address(lua51_path);
    auto hlua51 = gum_module_find_base_address(lua51_path);
    auto htarget = gum_module_find_base_address(path);
    ListExports_t exports;
    exports.assign_range(signatures.funcs);
    auto msg = update_signatures(signatures, luaModuleSignature.target_address, exports);
    if (!msg.empty())
    {
        fprintf(stderr, "%s\n", msg.c_str());
        return 1;
    }

    auto name = isClient ? "client" : "server";
    msg =
        std::format("#ifndef SIGNATURES_{}_H\n", name) +
        std::format("#define SIGNATURES_{}_H\n", name) +
        "#include \"Signature.hpp\"\n"
        "using namespace std::literals;\n" +

        std::format("static Signatures signatures_{} = \n", name) +
        "{\n" +
        std::format("{}\n,\n", readGameVersion(PROJECT_DIR "/../version.txt")) +
        "\t{\n";
    exports.assign_range(signatures.funcs);
    std::ranges::sort(exports, [](auto &l, auto &r)
                      { return l.first < r.first; });
    for (auto [func, offset] : exports)
    {
        if (missfuncs.contains(func))
            continue;
        msg += std::format("\t{{\"{}\"s, {}}},\n", func, offset);
    }
    msg.append("}};\n#endif\n");
    auto outputfile = PROJECT_DIR "/src/signatures_"s + name + ".hpp"s;
    spdlog::info("output {}", outputfile);
    std::ofstream sf(outputfile, std::ios::out | std::ios::trunc);
    assert(sf.is_open());
    sf << msg;
    sf.close();
    return 0;
}

int main()
{
    gum_init_embedded();
    auto lua51_path1 = getenv("GAME_PATH");
    if (lua51_path1)
    {
        game_path = lua51_path1;
    }
    fprintf(stderr, "lua51_path:\t%s\n", lua51_path);
    if (!loadModule(lua51_path))
        return 1;
    return update(true) + update(false);
}
