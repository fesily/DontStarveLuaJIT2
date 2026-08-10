// game/GameDbgExports.cpp — GameDbg_* Lua API exports (GameLua.def coupling on MSVC)
#include "GameLua.hpp"
#include "game/GameLuaContext.hpp"
#include <string>
#include <string_view>
#include <filesystem>
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <cstdarg>

/*
----------------------------------------------EXPORT_GAME_LUA_API
Windows: GameLua.def renames exports (lua_* = GameDbg_lua_*).
Non-Windows: export GameDbg_* with default visibility; on Linux also alias
lua_* → GameDbg_*. Do NOT use DONTSTARVEINJECTOR_API here — plugin_core_vm is
DS_INJECTOR_CONSUMER (dllimport path), not DONTSTARVEINJECTOR_BUILD.
*/

#ifdef _WIN32
#define EXPORT_GAME_LUA_API(name) extern "C"
#else
#ifdef __linux__
#define EXPORT_GAME_LUA_API_NAME_CONCAT(a) #a
#define EXPORT_GAME_LUA_API_NAME(name) EXPORT_GAME_LUA_API_NAME_CONCAT(GameDbg_##name)
#define EXPORT_GAME_LUA_API(name) \
    decltype(name) name __attribute__((alias(EXPORT_GAME_LUA_API_NAME(name)), visibility("default"))); \
    extern "C" __attribute__((visibility("default")))
#else
#define EXPORT_GAME_LUA_API(name) extern "C" __attribute__((visibility("default")))
#endif
#endif
EXPORT_GAME_LUA_API(lua_getinfo)
int GameDbg_lua_getinfo(lua_State *L, const char *what, lua_Debug *ar) {
    int ret = GetGameLuaContext()->_lua_getinfo(L, what, ar);
    if (ret && std::string_view{what}.contains('S')) {
        std::string_view source{ar->source ? ar->source : ""};
        if (!source.empty() && source[0] != '=' && source[0] != '@') {
            // transform source path
            bool is_path = source.starts_with("../mods/") || source.starts_with("scripts/");
            if (!is_path) {
                std::string_view short_src{ar->short_src ? ar->short_src : ""};
                if (short_src.starts_with("[string")) {
                    return ret;
                }
                try {
                    is_path = std::filesystem::exists(source);
                } catch (const std::filesystem::filesystem_error &e) {
                    spdlog::warn("Error checking file existence for lua source path {}: {}", source, e.what());
                }
            }
            if (is_path) {
                thread_local std::string source_path;
                source_path = fmt::format("@{}", source);
                ar->source = source_path.c_str();
            }
        }
    }
    return ret;
};

EXPORT_GAME_LUA_API(lua_newstate)
void *GameDbg_lua_newstate(lua_Alloc f, void *ud) { return GetGameLuaContext()->_lua_newstate(f, ud); };
EXPORT_GAME_LUA_API(lua_close)
void GameDbg_lua_close(lua_State *L) { return GetGameLuaContext()->_lua_close(L); };
EXPORT_GAME_LUA_API(lua_newthread)
lua_State *GameDbg_lua_newthread(lua_State *L) { return GetGameLuaContext()->_lua_newthread(L); };
EXPORT_GAME_LUA_API(lua_atpanic)
lua_CFunction GameDbg_lua_atpanic(lua_State *L, lua_CFunction panicf) { return GetGameLuaContext()->_lua_atpanic(L, panicf); };
EXPORT_GAME_LUA_API(lua_gettop)
int GameDbg_lua_gettop(lua_State *L) { return GetGameLuaContext()->_lua_gettop(L); };
EXPORT_GAME_LUA_API(lua_settop)
void GameDbg_lua_settop(lua_State *L, int idx) { return GetGameLuaContext()->_lua_settop(L, idx); };
EXPORT_GAME_LUA_API(lua_pushvalue)
void GameDbg_lua_pushvalue(lua_State *L, int idx) { return GetGameLuaContext()->_lua_pushvalue(L, idx); };
EXPORT_GAME_LUA_API(lua_remove)
void GameDbg_lua_remove(lua_State *L, int idx) { return GetGameLuaContext()->_lua_remove(L, idx); };
EXPORT_GAME_LUA_API(lua_insert)
void GameDbg_lua_insert(lua_State *L, int idx) { return GetGameLuaContext()->_lua_insert(L, idx); };
EXPORT_GAME_LUA_API(lua_replace)
void GameDbg_lua_replace(lua_State *L, int idx) { return GetGameLuaContext()->_lua_replace(L, idx); };
EXPORT_GAME_LUA_API(lua_checkstack)
int GameDbg_lua_checkstack(lua_State *L, int sz) { return GetGameLuaContext()->_lua_checkstack(L, sz); };
EXPORT_GAME_LUA_API(lua_xmove)
void GameDbg_lua_xmove(lua_State *from, lua_State *to, int n) { return GetGameLuaContext()->_lua_xmove(from, to, n); };
EXPORT_GAME_LUA_API(lua_isnumber)
int GameDbg_lua_isnumber(lua_State *L, int idx) { return GetGameLuaContext()->_lua_isnumber(L, idx); };
EXPORT_GAME_LUA_API(lua_isstring)
int GameDbg_lua_isstring(lua_State *L, int idx) { return GetGameLuaContext()->_lua_isstring(L, idx); };
EXPORT_GAME_LUA_API(lua_iscfunction)
int GameDbg_lua_iscfunction(lua_State *L, int idx) { return GetGameLuaContext()->_lua_iscfunction(L, idx); };
EXPORT_GAME_LUA_API(lua_isuserdata)
int GameDbg_lua_isuserdata(lua_State *L, int idx) { return GetGameLuaContext()->_lua_isuserdata(L, idx); };
EXPORT_GAME_LUA_API(lua_type)
int GameDbg_lua_type(lua_State *L, int idx) { return GetGameLuaContext()->_lua_type(L, idx); };
EXPORT_GAME_LUA_API(lua_typename)
const char *GameDbg_lua_typename(lua_State *L, int tp) { return GetGameLuaContext()->_lua_typename(L, tp); };
EXPORT_GAME_LUA_API(lua_equal)
int GameDbg_lua_equal(lua_State *L, int idx1, int idx2) { return GetGameLuaContext()->_lua_equal(L, idx1, idx2); };
EXPORT_GAME_LUA_API(lua_rawequal)
int GameDbg_lua_rawequal(lua_State *L, int idx1, int idx2) { return GetGameLuaContext()->_lua_rawequal(L, idx1, idx2); };
EXPORT_GAME_LUA_API(lua_lessthan)
int GameDbg_lua_lessthan(lua_State *L, int idx1, int idx2) { return GetGameLuaContext()->_lua_lessthan(L, idx1, idx2); };
EXPORT_GAME_LUA_API(lua_tonumber)
lua_Number GameDbg_lua_tonumber(lua_State *L, int idx) { return GetGameLuaContext()->_lua_tonumber(L, idx); };
EXPORT_GAME_LUA_API(lua_tointeger)
lua_Integer GameDbg_lua_tointeger(lua_State *L, int idx) { return GetGameLuaContext()->_lua_tointeger(L, idx); };
EXPORT_GAME_LUA_API(lua_toboolean)
int GameDbg_lua_toboolean(lua_State *L, int idx) { return GetGameLuaContext()->_lua_toboolean(L, idx); };
EXPORT_GAME_LUA_API(lua_tolstring)
const char *GameDbg_lua_tolstring(lua_State *L, int idx, size_t *len) { return GetGameLuaContext()->_lua_tolstring(L, idx, len); };
EXPORT_GAME_LUA_API(lua_objlen)
size_t GameDbg_lua_objlen(lua_State *L, int idx) { return GetGameLuaContext()->_lua_objlen(L, idx); };
EXPORT_GAME_LUA_API(lua_tocfunction)
lua_CFunction GameDbg_lua_tocfunction(lua_State *L, int idx) { return GetGameLuaContext()->_lua_tocfunction(L, idx); };
EXPORT_GAME_LUA_API(lua_touserdata)
void *GameDbg_lua_touserdata(lua_State *L, int idx) { return GetGameLuaContext()->_lua_touserdata(L, idx); };
EXPORT_GAME_LUA_API(lua_tothread)
lua_State *GameDbg_lua_tothread(lua_State *L, int idx) { return GetGameLuaContext()->_lua_tothread(L, idx); };
EXPORT_GAME_LUA_API(lua_topointer)
const void *GameDbg_lua_topointer(lua_State *L, int idx) { return GetGameLuaContext()->_lua_topointer(L, idx); };
EXPORT_GAME_LUA_API(lua_pushnil)
void GameDbg_lua_pushnil(lua_State *L) { return GetGameLuaContext()->_lua_pushnil(L); };
EXPORT_GAME_LUA_API(lua_pushnumber)
void GameDbg_lua_pushnumber(lua_State *L, lua_Number n) { return GetGameLuaContext()->_lua_pushnumber(L, n); };
EXPORT_GAME_LUA_API(lua_pushinteger)
void GameDbg_lua_pushinteger(lua_State *L, lua_Integer n) { return GetGameLuaContext()->_lua_pushinteger(L, n); };
EXPORT_GAME_LUA_API(lua_pushlstring)
void GameDbg_lua_pushlstring(lua_State *L, const char *s, size_t len) { return GetGameLuaContext()->_lua_pushlstring(L, s, len); };
EXPORT_GAME_LUA_API(lua_pushstring)
void GameDbg_lua_pushstring(lua_State *L, const char *s) { return GetGameLuaContext()->_lua_pushstring(L, s); };
EXPORT_GAME_LUA_API(lua_pushvfstring)
const char *GameDbg_lua_pushvfstring(lua_State *L, const char *fmt, va_list argp) { return GetGameLuaContext()->_lua_pushvfstring(L, fmt, argp); };
EXPORT_GAME_LUA_API(lua_pushcclosure)
void GameDbg_lua_pushcclosure(lua_State *L, lua_CFunction fn, int n) { return GetGameLuaContext()->_lua_pushcclosure(L, fn, n); };
EXPORT_GAME_LUA_API(lua_pushboolean)
void GameDbg_lua_pushboolean(lua_State *L, int b) { return GetGameLuaContext()->_lua_pushboolean(L, b); };
EXPORT_GAME_LUA_API(lua_pushlightuserdata)
void GameDbg_lua_pushlightuserdata(lua_State *L, void *p) { return GetGameLuaContext()->_lua_pushlightuserdata(L, p); };
EXPORT_GAME_LUA_API(lua_pushthread)
int GameDbg_lua_pushthread(lua_State *L) { return GetGameLuaContext()->_lua_pushthread(L); };
EXPORT_GAME_LUA_API(lua_gettable)
void GameDbg_lua_gettable(lua_State *L, int idx) { return GetGameLuaContext()->_lua_gettable(L, idx); };
EXPORT_GAME_LUA_API(lua_getfield)
void GameDbg_lua_getfield(lua_State *L, int idx, const char *k) { return GetGameLuaContext()->_lua_getfield(L, idx, k); };
EXPORT_GAME_LUA_API(lua_rawget)
void GameDbg_lua_rawget(lua_State *L, int idx) { return GetGameLuaContext()->_lua_rawget(L, idx); };
EXPORT_GAME_LUA_API(lua_rawgeti)
void GameDbg_lua_rawgeti(lua_State *L, int idx, int n) { return GetGameLuaContext()->_lua_rawgeti(L, idx, n); };
EXPORT_GAME_LUA_API(lua_createtable)
void GameDbg_lua_createtable(lua_State *L, int narr, int nrec) { return GetGameLuaContext()->_lua_createtable(L, narr, nrec); };
EXPORT_GAME_LUA_API(lua_newuserdata)
void *GameDbg_lua_newuserdata(lua_State *L, size_t sz) { return GetGameLuaContext()->_lua_newuserdata(L, sz); };
EXPORT_GAME_LUA_API(lua_getmetatable)
int GameDbg_lua_getmetatable(lua_State *L, int objindex) { return GetGameLuaContext()->_lua_getmetatable(L, objindex); };
EXPORT_GAME_LUA_API(lua_getfenv)
void GameDbg_lua_getfenv(lua_State *L, int idx) { return GetGameLuaContext()->_lua_getfenv(L, idx); };
EXPORT_GAME_LUA_API(lua_settable)
void GameDbg_lua_settable(lua_State *L, int idx) { return GetGameLuaContext()->_lua_settable(L, idx); };
EXPORT_GAME_LUA_API(lua_setfield)
void GameDbg_lua_setfield(lua_State *L, int idx, const char *k) { return GetGameLuaContext()->_lua_setfield(L, idx, k); };
EXPORT_GAME_LUA_API(lua_rawset)
void GameDbg_lua_rawset(lua_State *L, int idx) { return GetGameLuaContext()->_lua_rawset(L, idx); };
EXPORT_GAME_LUA_API(lua_rawseti)
void GameDbg_lua_rawseti(lua_State *L, int idx, int n) { return GetGameLuaContext()->_lua_rawseti(L, idx, n); };
EXPORT_GAME_LUA_API(lua_setmetatable)
int GameDbg_lua_setmetatable(lua_State *L, int objindex) { return GetGameLuaContext()->_lua_setmetatable(L, objindex); };
EXPORT_GAME_LUA_API(lua_setfenv)
int GameDbg_lua_setfenv(lua_State *L, int idx) { return GetGameLuaContext()->_lua_setfenv(L, idx); };
EXPORT_GAME_LUA_API(lua_call)
void GameDbg_lua_call(lua_State *L, int nargs, int nresults) { return GetGameLuaContext()->_lua_call(L, nargs, nresults); };
EXPORT_GAME_LUA_API(lua_pcall)
int GameDbg_lua_pcall(lua_State *L, int nargs, int nresults, int errfunc) { return GetGameLuaContext()->_lua_pcall(L, nargs, nresults, errfunc); };
EXPORT_GAME_LUA_API(lua_cpcall)
int GameDbg_lua_cpcall(lua_State *L, lua_CFunction func, void *ud) { return GetGameLuaContext()->_lua_cpcall(L, func, ud); };
EXPORT_GAME_LUA_API(lua_load)
int GameDbg_lua_load(lua_State *L, lua_Reader reader, void *dt, const char *chunkname) { return GetGameLuaContext()->_lua_load(L, reader, dt, chunkname); };
EXPORT_GAME_LUA_API(lua_dump)
int GameDbg_lua_dump(lua_State *L, lua_Writer writer, void *data) { return GetGameLuaContext()->_lua_dump(L, writer, data); };
EXPORT_GAME_LUA_API(lua_yield)
int GameDbg_lua_yield(lua_State *L, int nresults) { return GetGameLuaContext()->_lua_yield(L, nresults); };
EXPORT_GAME_LUA_API(lua_resume)
int GameDbg_lua_resume(lua_State *L, int narg) { return GetGameLuaContext()->_lua_resume(L, narg); };
EXPORT_GAME_LUA_API(lua_status)
int GameDbg_lua_status(lua_State *L) { return GetGameLuaContext()->_lua_status(L); };
EXPORT_GAME_LUA_API(lua_gc)
int GameDbg_lua_gc(lua_State *L, int what, int data) { return GetGameLuaContext()->_lua_gc(L, what, data); };
EXPORT_GAME_LUA_API(lua_error)
int GameDbg_lua_error(lua_State *L) { return GetGameLuaContext()->_lua_error(L); };
EXPORT_GAME_LUA_API(lua_next)
int GameDbg_lua_next(lua_State *L, int idx) { return GetGameLuaContext()->_lua_next(L, idx); };
EXPORT_GAME_LUA_API(lua_concat)
void GameDbg_lua_concat(lua_State *L, int n) { return GetGameLuaContext()->_lua_concat(L, n); };
EXPORT_GAME_LUA_API(lua_getallocf)
lua_Alloc GameDbg_lua_getallocf(lua_State *L, void **ud) { return GetGameLuaContext()->_lua_getallocf(L, ud); };
EXPORT_GAME_LUA_API(lua_setallocf)
void GameDbg_lua_setallocf(lua_State *L, lua_Alloc f, void *ud) { return GetGameLuaContext()->_lua_setallocf(L, f, ud); };
EXPORT_GAME_LUA_API(lua_setlevel)
void GameDbg_lua_setlevel(lua_State *from, lua_State *to) { return GetGameLuaContext()->_lua_setlevel(from, to); };
EXPORT_GAME_LUA_API(lua_getstack)
int GameDbg_lua_getstack(lua_State *L, int level, lua_Debug *ar) { return GetGameLuaContext()->_lua_getstack(L, level, ar); };
EXPORT_GAME_LUA_API(lua_getlocal)
const char *GameDbg_lua_getlocal(lua_State *L, const lua_Debug *ar, int n) { return GetGameLuaContext()->_lua_getlocal(L, ar, n); };
EXPORT_GAME_LUA_API(lua_setlocal)
const char *GameDbg_lua_setlocal(lua_State *L, const lua_Debug *ar, int n) { return GetGameLuaContext()->_lua_setlocal(L, ar, n); };
EXPORT_GAME_LUA_API(lua_getupvalue)
const char *GameDbg_lua_getupvalue(lua_State *L, int funcindex, int n) { return GetGameLuaContext()->_lua_getupvalue(L, funcindex, n); };
EXPORT_GAME_LUA_API(lua_setupvalue)
const char *GameDbg_lua_setupvalue(lua_State *L, int funcindex, int n) { return GetGameLuaContext()->_lua_setupvalue(L, funcindex, n); };
EXPORT_GAME_LUA_API(lua_sethook)
int GameDbg_lua_sethook(lua_State *L, lua_Hook func, int mask, int count) { return GetGameLuaContext()->_lua_sethook(L, func, mask, count); };
EXPORT_GAME_LUA_API(lua_gethook)
lua_Hook GameDbg_lua_gethook(lua_State *L) { return GetGameLuaContext()->_lua_gethook(L); };
EXPORT_GAME_LUA_API(lua_gethookmask)
int GameDbg_lua_gethookmask(lua_State *L) { return GetGameLuaContext()->_lua_gethookmask(L); };
EXPORT_GAME_LUA_API(lua_gethookcount)
int GameDbg_lua_gethookcount(lua_State *L) { return GetGameLuaContext()->_lua_gethookcount(L); };
EXPORT_GAME_LUA_API(luaL_openlib)
void GameDbg_luaL_openlib(lua_State *L, const char *libname, const luaL_Reg *l, int nup) { return GetGameLuaContext()->_luaL_openlib(L, libname, l, nup); };
EXPORT_GAME_LUA_API(luaL_register)
void GameDbg_luaL_register(lua_State *L, const char *libname, const luaL_Reg *l) { return GetGameLuaContext()->_luaL_register(L, libname, l); };
EXPORT_GAME_LUA_API(luaL_getmetafield)
int GameDbg_luaL_getmetafield(lua_State *L, int obj, const char *e) { return GetGameLuaContext()->_luaL_getmetafield(L, obj, e); };
EXPORT_GAME_LUA_API(luaL_callmeta)
int GameDbg_luaL_callmeta(lua_State *L, int obj, const char *e) { return GetGameLuaContext()->_luaL_callmeta(L, obj, e); };
EXPORT_GAME_LUA_API(luaL_typerror)
int GameDbg_luaL_typerror(lua_State *L, int narg, const char *tname) { return GetGameLuaContext()->_luaL_typerror(L, narg, tname); };
EXPORT_GAME_LUA_API(luaL_argerror)
int GameDbg_luaL_argerror(lua_State *L, int numarg, const char *extramsg) { return GetGameLuaContext()->_luaL_argerror(L, numarg, extramsg); };
EXPORT_GAME_LUA_API(luaL_checklstring)
const char *GameDbg_luaL_checklstring(lua_State *L, int numarg, size_t *len) { return GetGameLuaContext()->_luaL_checklstring(L, numarg, len); };
EXPORT_GAME_LUA_API(luaL_optlstring)
const char *GameDbg_luaL_optlstring(lua_State *L, int numarg, const char *def, size_t *len) { return GetGameLuaContext()->_luaL_optlstring(L, numarg, def, len); };
EXPORT_GAME_LUA_API(luaL_checknumber)
lua_Number GameDbg_luaL_checknumber(lua_State *L, int numarg) { return GetGameLuaContext()->_luaL_checknumber(L, numarg); };
EXPORT_GAME_LUA_API(luaL_optnumber)
lua_Number GameDbg_luaL_optnumber(lua_State *L, int numarg, lua_Number def) { return GetGameLuaContext()->_luaL_optnumber(L, numarg, def); };
EXPORT_GAME_LUA_API(luaL_checkinteger)
lua_Integer GameDbg_luaL_checkinteger(lua_State *L, int numarg) { return GetGameLuaContext()->_luaL_checkinteger(L, numarg); };
EXPORT_GAME_LUA_API(luaL_optinteger)
lua_Integer GameDbg_luaL_optinteger(lua_State *L, int numarg, lua_Integer def) { return GetGameLuaContext()->_luaL_optinteger(L, numarg, def); };
EXPORT_GAME_LUA_API(luaL_optboolean)
int GameDbg_luaL_optboolean(lua_State *L, int numarg, int def) { return GetGameLuaContext()->_luaL_optboolean(L, numarg, def); };
EXPORT_GAME_LUA_API(luaL_checkboolean)
int GameDbg_luaL_checkboolean(lua_State *L, int numarg) { return GetGameLuaContext()->_luaL_checkboolean(L, numarg); };
EXPORT_GAME_LUA_API(luaL_checkstack)
void GameDbg_luaL_checkstack(lua_State *L, int sz, const char *msg) { return GetGameLuaContext()->_luaL_checkstack(L, sz, msg); };
EXPORT_GAME_LUA_API(luaL_checktype)
void GameDbg_luaL_checktype(lua_State *L, int narg, int t) { return GetGameLuaContext()->_luaL_checktype(L, narg, t); };
EXPORT_GAME_LUA_API(luaL_checkany)
void GameDbg_luaL_checkany(lua_State *L, int narg) { return GetGameLuaContext()->_luaL_checkany(L, narg); };
EXPORT_GAME_LUA_API(luaL_newmetatable)
int GameDbg_luaL_newmetatable(lua_State *L, const char *tname) { return GetGameLuaContext()->_luaL_newmetatable(L, tname); };
EXPORT_GAME_LUA_API(luaL_checkudata)
void *GameDbg_luaL_checkudata(lua_State *L, int ud, const char *tname) { return GetGameLuaContext()->_luaL_checkudata(L, ud, tname); };
EXPORT_GAME_LUA_API(luaL_where)
void GameDbg_luaL_where(lua_State *L, int lvl) { return GetGameLuaContext()->_luaL_where(L, lvl); };
EXPORT_GAME_LUA_API(luaL_checkoption)
int GameDbg_luaL_checkoption(lua_State *L, int narg, const char *def, const char *const lst[]) { return GetGameLuaContext()->_luaL_checkoption(L, narg, def, lst); };
EXPORT_GAME_LUA_API(luaL_ref)
int GameDbg_luaL_ref(lua_State *L, int t) { return GetGameLuaContext()->_luaL_ref(L, t); };
EXPORT_GAME_LUA_API(luaL_unref)
void GameDbg_luaL_unref(lua_State *L, int t, int ref) { return GetGameLuaContext()->_luaL_unref(L, t, ref); };
EXPORT_GAME_LUA_API(luaL_loadfile)
int GameDbg_luaL_loadfile(lua_State *L, const char *filename) { return GetGameLuaContext()->_luaL_loadfile(L, filename); };
EXPORT_GAME_LUA_API(luaL_loadbuffer)
int GameDbg_luaL_loadbuffer(lua_State *L, const char *buff, size_t sz, const char *name) { return GetGameLuaContext()->_luaL_loadbuffer(L, buff, sz, name); };
EXPORT_GAME_LUA_API(luaL_loadstring)
int GameDbg_luaL_loadstring(lua_State *L, const char *s) { return GetGameLuaContext()->_luaL_loadstring(L, s); };
EXPORT_GAME_LUA_API(luaL_newstate)
lua_State *GameDbg_luaL_newstate() { return GetGameLuaContext()->_luaL_newstate(); };
EXPORT_GAME_LUA_API(luaL_gsub)
const char *GameDbg_luaL_gsub(lua_State *L, const char *s, const char *p, const char *r) { return GetGameLuaContext()->_luaL_gsub(L, s, p, r); };
EXPORT_GAME_LUA_API(luaL_findtable)
const char *GameDbg_luaL_findtable(lua_State *L, int idx, const char *fname, int szhint) { return GetGameLuaContext()->_luaL_findtable(L, idx, fname, szhint); };
EXPORT_GAME_LUA_API(luaL_buffinit)
void GameDbg_luaL_buffinit(lua_State *L, luaL_Buffer *B) { return GetGameLuaContext()->_luaL_buffinit(L, B); };
EXPORT_GAME_LUA_API(luaL_prepbuffer)
char *GameDbg_luaL_prepbuffer(luaL_Buffer *B) { return GetGameLuaContext()->_luaL_prepbuffer(B); };
EXPORT_GAME_LUA_API(luaL_addlstring)
void GameDbg_luaL_addlstring(luaL_Buffer *B, const char *s, size_t len) { return GetGameLuaContext()->_luaL_addlstring(B, s, len); };
EXPORT_GAME_LUA_API(luaL_addstring)
void GameDbg_luaL_addstring(luaL_Buffer *B, const char *s) { return GetGameLuaContext()->_luaL_addstring(B, s); };
EXPORT_GAME_LUA_API(luaL_addvalue)
void GameDbg_luaL_addvalue(luaL_Buffer *B) { return GetGameLuaContext()->_luaL_addvalue(B); };
EXPORT_GAME_LUA_API(luaL_pushresult)
void GameDbg_luaL_pushresult(luaL_Buffer *B) { return GetGameLuaContext()->_luaL_pushresult(B); };
EXPORT_GAME_LUA_API(luaL_openlibs)
void GameDbg_luaL_openlibs(lua_State *L) { return GetGameLuaContext()->_luaL_openlibs(L); };
EXPORT_GAME_LUA_API(luaopen_base)
int GameDbg_luaopen_base(lua_State *L) { return GetGameLuaContext()->_luaopen_base(L); };
EXPORT_GAME_LUA_API(luaopen_debug)
int GameDbg_luaopen_debug(lua_State *L) { return GetGameLuaContext()->_luaopen_debug(L); };
EXPORT_GAME_LUA_API(luaopen_io)
int GameDbg_luaopen_io(lua_State *L) { return GetGameLuaContext()->_luaopen_io(L); };
EXPORT_GAME_LUA_API(luaopen_math)
int GameDbg_luaopen_math(lua_State *L) { return GetGameLuaContext()->_luaopen_math(L); };
EXPORT_GAME_LUA_API(luaopen_os)
int GameDbg_luaopen_os(lua_State *L) { return GetGameLuaContext()->_luaopen_os(L); };
EXPORT_GAME_LUA_API(luaopen_package)
int GameDbg_luaopen_package(lua_State *L) { return GetGameLuaContext()->_luaopen_package(L); };
EXPORT_GAME_LUA_API(luaopen_string)
int GameDbg_luaopen_string(lua_State *L) { return GetGameLuaContext()->_luaopen_string(L); };
EXPORT_GAME_LUA_API(luaopen_table)
int GameDbg_luaopen_table(lua_State *L) { return GetGameLuaContext()->_luaopen_table(L); };
EXPORT_GAME_LUA_API(lua_pushfstring)
const char *GameDbg_lua_pushfstring(lua_State *L, const char *fmt, ...) {
    va_list argp;
    va_start(argp, fmt);
    auto ret = GetGameLuaContext()->_lua_pushvfstring(L, fmt, argp);
    va_end(argp);
    return ret;
};
EXPORT_GAME_LUA_API(luaL_error)
int GameDbg_luaL_error(lua_State *L, const char *fmt, ...) {
    va_list argp;
    va_start(argp, fmt);
    auto ret = GetGameLuaContext()->_luaL_error(L, fmt, argp);
    va_end(argp);
    return ret;
};

/* lua 5.2 */
EXPORT_GAME_LUA_API(lua_upvalueid)
void *GameDbg_lua_upvalueid(lua_State *L, int funcindex, int n) { return GetGameLuaContext()->_lua_upvalueid(L, funcindex, n); };
EXPORT_GAME_LUA_API(lua_upvaluejoin)
void GameDbg_lua_upvaluejoin(lua_State *L, int funcindex1, int n1, int funcindex2, int n2) { return GetGameLuaContext()->_lua_upvaluejoin(L, funcindex1, n1, funcindex2, n2); };
EXPORT_GAME_LUA_API(lua_loadx)
int GameDbg_lua_loadx(lua_State *L, lua_Reader reader, void *dt, const char *chunkname, const char *mode) { return GetGameLuaContext()->_lua_loadx(L, reader, dt, chunkname, mode); };
EXPORT_GAME_LUA_API(lua_version)
const lua_Number *GameDbg_lua_version(lua_State *L) { return GetGameLuaContext()->_lua_version(L); };
EXPORT_GAME_LUA_API(lua_copy)
void GameDbg_lua_copy(lua_State *L, int fromidx, int toidx) { return GetGameLuaContext()->_lua_copy(L, fromidx, toidx); };
EXPORT_GAME_LUA_API(lua_tonumberx)
lua_Number GameDbg_lua_tonumberx(lua_State *L, int idx, int *isnum) { return GetGameLuaContext()->_lua_tonumberx(L, idx, isnum); };
EXPORT_GAME_LUA_API(lua_tointegerx)
lua_Integer GameDbg_lua_tointegerx(lua_State *L, int idx, int *isnum) { return GetGameLuaContext()->_lua_tointegerx(L, idx, isnum); };

EXPORT_GAME_LUA_API(luaL_fileresult)
int GameDbg_luaL_fileresult(lua_State *L, int stat, const char *fname) { return GetGameLuaContext()->_luaL_fileresult(L, stat, fname); };
EXPORT_GAME_LUA_API(luaL_execresult)
int GameDbg_luaL_execresult(lua_State *L, int stat) { return GetGameLuaContext()->_luaL_execresult(L, stat); };
EXPORT_GAME_LUA_API(luaL_loadfilex)
int GameDbg_luaL_loadfilex(lua_State *L, const char *filename, const char *mode) { return GetGameLuaContext()->_luaL_loadfilex(L, filename, mode); };
EXPORT_GAME_LUA_API(luaL_loadbufferx)
int GameDbg_luaL_loadbufferx(lua_State *L, const char *buff, size_t sz, const char *name, const char *mode) { return GetGameLuaContext()->_luaL_loadbufferx(L, buff, sz, name, mode); };
EXPORT_GAME_LUA_API(luaL_traceback)
void GameDbg_luaL_traceback(lua_State *L, lua_State *L1, const char *msg, int level) { return GetGameLuaContext()->_luaL_traceback(L, L1, msg, level); };
EXPORT_GAME_LUA_API(luaL_setfuncs)
void GameDbg_luaL_setfuncs(lua_State *L, const luaL_Reg *l, int nup) { return GetGameLuaContext()->_luaL_setfuncs(L, l, nup); };
EXPORT_GAME_LUA_API(luaL_pushmodule)
void GameDbg_luaL_pushmodule(lua_State *L, const char *modname, int sizehint) { return GetGameLuaContext()->_luaL_pushmodule(L, modname, sizehint); };
EXPORT_GAME_LUA_API(luaL_testudata)
void *GameDbg_luaL_testudata(lua_State *L, int ud, const char *tname) { return GetGameLuaContext()->_luaL_testudata(L, ud, tname); };
EXPORT_GAME_LUA_API(luaL_setmetatable)
void GameDbg_luaL_setmetatable(lua_State *L, const char *tname) { return GetGameLuaContext()->_luaL_setmetatable(L, tname); };

/* lua 5.3 */
int lua_absindex(lua_State* L, int i);
EXPORT_GAME_LUA_API(lua_absindex)
int GameDbg_lua_absindex(lua_State *L, int idx) { return GetGameLuaContext()->_lua_absindex(L, idx); };