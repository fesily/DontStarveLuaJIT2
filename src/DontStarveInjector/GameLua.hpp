#pragma once
#include "LuaApi.hpp"
#include <string>
#include <string_view>
#include <frida-gum.h>
#include <lua.hpp>

enum class GameLuaType {
    Lua51,
    LuaJit,
};

/*
    this is a struct to hold all lua export functions
    so we can replace them with our own implementation
*/
struct LuaInterfaces {
#define IMPORT_LUA_API(name) \
    decltype(name) _##name;
    LUA51_API_DEFINES(IMPORT_LUA_API)
#undef IMPORT_LUA_API
};

struct GameLuaContext {
    std::string_view sharedlibraryName;
    GameLuaType luaType;
    lua_State *luaState;
    LuaInterfaces *interface;
    GumModule* LuaModule;
};

GameLuaContext &GetGameLuaContext();

void ReplaceLuaApi(GameLuaType type, const char *shared_library_name);