#define NOMINMAX

#include "SignatureJson.hpp"
#include "frida-gum.h"

#include "GameSignature.hpp"
#include "platform.hpp"

#ifndef GAMEDIR
#error "not defined GAME_DIR"
#endif

#ifndef LUA51_PATH
#error "not defined LUA51_PATH"
#endif

#ifndef PROJECT_DIR
#error "not defined PROJECT_DIR"
#endif

const char *game_path = GAMEDIR R"(\bin64\dontstarve_steam_x64.exe)";
const char *game_server_path = GAMEDIR R"(\bin64\dontstarve_dedicated_server_nullrenderer_x64.exe)";
const char *lua51_path = LUA51_PATH;
const char *worker_dir = PROJECT_DIR "/Mod/bin64/windows";

bool loadModule(const char *path) {
    GError *err = nullptr;
    if (!gum_module_load(path, &err)) {
        g_error_free(err);
        fprintf(stderr, "load module error:%s-%s\n", path, err->message);
        return false;
    }
    return true;
}

int check(const char *path, bool isClient) {
    SignatureJson sj{isClient};
    auto signatures = sj.read_from_signatures().value();
    fprintf(stderr, "game_path:\t%s\n", path);
    if (!loadModule(path))
        return 1;
    luaModuleSignature.log = false;
    if (luaModuleSignature.scan(path) == 0) {
        fprintf(stderr, "%s", "can find lua module base addr\n");
        return 1;
    }
    using namespace std::literals;
    SignatureJson sjCopy{isClient};
    auto p = std::filesystem::path{PROJECT_DIR} / "tests" / "windows_x64" / (("Signatures_"s + (isClient ? "client" : "server")) + ".txt.json");
    sjCopy.file_path = p.string();
    auto sCopy = sjCopy.read_from_signatures().value();

    auto count = 0;
    for (auto [func, info]: signatures.funcs) {
        const auto ida_offset = sCopy.funcs.at(func).offset;
        if (ida_offset != info.offset) {
            fprintf(stderr, "[%s]%s [%d]-[%d]\n", func.c_str(), "can't match the address", (int) ida_offset, (int) info.offset);
            count++;
        }
    }
    return count;
}

int main() {
    gum_init_embedded();
    auto lua51_path1 = getenv("GAME_PATH");
    if (lua51_path1) {
        game_path = lua51_path1;
    }
    fprintf(stderr, "lua51_path:\t%s\n", lua51_path);
    if (!loadModule(lua51_path))
        return 1;
    set_worker_directory(worker_dir);
    SignatureJson::version_path = GAMEDIR "/version.txt";
    return check(game_path, true) + check(game_server_path, false);
}