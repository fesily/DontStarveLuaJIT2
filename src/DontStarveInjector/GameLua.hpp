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

    bool _luaL_dostring(lua_State *L, const char *s) {
        return (_luaL_loadstring(L, s) || _lua_pcall(L, 0, 0, 0));
    }
    bool _luaL_dostringex(lua_State *L, const char *s, const char *chunkname) {
        return (_luaL_loadbuffer(L, s, strlen(s), chunkname) || _lua_pcall(L, 0, 0, 0));
    }
    bool _luaL_dofile(lua_State *L, const char *filename) {
        return (_luaL_loadfile(L, filename) || _lua_pcall(L, 0, 0, 0));
    }
    void _lua_getglobal(lua_State *L, const char *name) {
        _lua_getfield(L, LUA_GLOBALSINDEX, name);
    }
    bool _lua_istable(lua_State *L, int index) {
        return _lua_type(L, index) == LUA_TTABLE;
    }
    bool _lua_isfunction(lua_State *L, int index) {
        return _lua_type(L, index) == LUA_TFUNCTION;
    }
    const char* _lua_tostring(lua_State *L, int index) {
        return _lua_tolstring(L, index, nullptr);
    }
    void _lua_pop(lua_State* L, int n) {
        _lua_settop(L, -(n) - 1);
    }
};

struct GameLuaContext {
    std::string sharedlibraryName;
    GameLuaType luaType;
    lua_State *luaState;
    GumModule *LuaModule;
    LuaApis api;

    void luaL_openlibs_hooker(lua_State *L);

    LuaApis* operator->() {
        return &api;
    }
};

GameLuaContext &GetGameLuaContext();

void ReplaceLuaApi(GameLuaType type, const char *shared_library_name);
void ReplaceLuaModule(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports);