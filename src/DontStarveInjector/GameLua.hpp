#pragma once
#include "LuaApi.hpp"
#include "DontStarveSignature.hpp"
#include <string>
#include <string_view>
#include <frida-gum.h>
#include <lua.hpp>

enum class GameLuaType {
    _51,
    jit,
};

enum class LUA_EVENT {
    new_state,
    close_state,
    call_lua_gc,
};

/*
    this is a struct to hold all lua export functions
    so we can replace them with our own implementation
*/
struct LuaInterfaces {
#define IMPORT_LUA_API(name) decltype(&name) _##name;

    LUA51_API_DEFINES(IMPORT_LUA_API);
#undef IMPORT_LUA_API
};
extern LuaInterfaces interface;


struct GameLuaContext {
    std::string sharedlibraryName;
    GameLuaType luaType;
    lua_State *luaState;
    GumModule *LuaModule;
    LuaInterfaces interface;
    void luaL_openlibs_hooker(lua_State *L);
};

GameLuaContext &GetGameLuaContext();

void ReplaceLuaApi(GameLuaType type, const char *shared_library_name);
void ReplaceLuaModule(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports);