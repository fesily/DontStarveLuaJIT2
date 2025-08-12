#pragma once
#include "LuaApi.hpp"
#include "DontStarveSignature.hpp"
#include <string>
#include <string_view>
#include <frida-gum.h>
#include <lua.hpp>
#include <lj_arch.h>

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
struct LuaApis {
#define IMPORT_LUA_API(name) decltype(&name) _##name;

    LUA51_API_DEFINES(IMPORT_LUA_API);
    LUAJIT_API_DEFINES(IMPORT_LUA_API);
    LUAJIT_API_DEFINES_5_2(IMPORT_LUA_API);
    LUAJIT_API_DEFINES_5_3(IMPORT_LUA_API);
#undef IMPORT_LUA_API
};

struct GameLuaContext {
    std::string sharedlibraryName;
    GameLuaType luaType;
    lua_State *luaState;
    GumModule *LuaModule;
    LuaApis api;
    void luaL_openlibs_hooker(lua_State *L);
};

GameLuaContext &GetGameLuaContext();

void ReplaceLuaApi(GameLuaType type, const char *shared_library_name);
void ReplaceLuaModule(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports);