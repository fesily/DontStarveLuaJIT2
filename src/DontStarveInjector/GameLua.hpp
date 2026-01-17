#pragma once
#include "LuaApi.hpp"
#include "DontStarveSignature.hpp"
#include <string>
#include <string_view>
#include <frida-gum.h>
#include <lua.hpp>
#include <lj_arch.h>

#define GAME_LUA_TYPE_ENUM(_) \
    _(jit)                 \
    _(game)                \
    _(_51)

enum class GameLuaType {
#define DEFINE_ENUM(name) name,
    GAME_LUA_TYPE_ENUM(DEFINE_ENUM) 
#undef DEFINE_ENUM
};

inline std::string_view GameLuaTypeToString(GameLuaType type)
{
    switch (type) {
#define CASE_ENUM_TO_STRING(name) \
    case GameLuaType::name:       \
        return std::string_view{#name};
        GAME_LUA_TYPE_ENUM(CASE_ENUM_TO_STRING)
#undef CASE_ENUM_TO_STRING
    default:
        return "unknown";
    }
}

inline GameLuaType GameLuaTypeFromString(const std::string_view &str)
{
    #define IF_STRING_TO_ENUM(name) \
        if (str == std::string_view{#name})           \
            return GameLuaType::name;
    GAME_LUA_TYPE_ENUM(IF_STRING_TO_ENUM)
    #undef IF_STRING_TO_ENUM
    return GameLuaType::jit; // default
}

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

    int _luaL_dostring(lua_State *L, const char *s) {
        return (_luaL_loadstring(L, s) || _lua_pcall(L, 0, 0, 0));
    }
    int _luaL_dostringex(lua_State *L, const char *s, const char *chunkname) {
        return (_luaL_loadbuffer(L, s, strlen(s), chunkname) || _lua_pcall(L, 0, 0, 0));
    }
    int _luaL_dofile(lua_State *L, const char *filename) {
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
    const char *_lua_tostring(lua_State *L, int index) {
        return _lua_tolstring(L, index, nullptr);
    }
    void _lua_pop(lua_State *L, int n) {
        _lua_settop(L, -(n) -1);
    }
    void _lua_newtable(lua_State *L) {
        _lua_createtable(L, 0, 0);
    }
    void _lua_pushcfunction(lua_State *L, lua_CFunction f) {
        _lua_pushcclosure(L, f, 0);
    }
    const char *_luaL_checkstring(lua_State *L, int n) {
        return _luaL_checklstring(L, (n), NULL);
    }

    void _lua_setglobal(lua_State *L, const char *name) {
        _lua_setfield(L, LUA_GLOBALSINDEX, name);
    }

    const char *_luaL_optstring(lua_State *L, int n, const char *d) {
        return _luaL_optlstring(L, (n), (d), NULL);
    }
    void _luaL_getmetatable(lua_State *L, const char *name) {
        _lua_getfield(L, LUA_REGISTRYINDEX, name);
    }
    void _lua_pushliteral(lua_State *L, const char *s) {
        _lua_pushlstring(L, "", (sizeof(s) / sizeof(char)) - 1);
    }
    void _luaL_argcheck(lua_State *L, int cond, int numarg, const char *extramsg) {
        ((void) ((cond) || _luaL_argerror(L, (numarg), (extramsg))));
    }
    bool _lua_isnone(lua_State *L, int index) {
        return _lua_type(L, (index)) == LUA_TNONE;
    }
    bool _lua_isnoneornil(lua_State *L, int index) {
        return _lua_type(L, (index)) <= 0;
    }
    bool _lua_isnil(lua_State *L, int index) {
        return _lua_type(L, (index)) == LUA_TNIL;
    }
    int _lua_absindex(lua_State* L, int i) {
        if (i < 0 && i > LUA_REGISTRYINDEX)
            i += _lua_gettop(L) + 1;
        return i;
    }
};

struct GameLuaContext {
    std::string sharedlibraryName;
    GameLuaType luaType;
    lua_State *luaState = nullptr;
    GumModule *LuaModule = nullptr;
    LuaApis api;

    LuaApis *operator->() {
        return &api;
    }

protected:
    GameLuaContext(const char *shared_library_name, GameLuaType type)
        : sharedlibraryName(shared_library_name), luaType(type) {
    }
    virtual ~GameLuaContext() = default;
};

GameLuaContext &GetGameLuaContext();

void ReplaceLuaApi(GameLuaType type, const char *shared_library_name);
void ReplaceLuaModule(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports);