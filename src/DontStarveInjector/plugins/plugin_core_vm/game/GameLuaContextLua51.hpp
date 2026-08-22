// game/GameLuaContextLua51.hpp — Lua 5.1 context (base for GameLuaContextGame)
#pragma once

#include "game/GameLuaContextImpl.hpp"

struct GameLua51Context : GameLuaContextImpl {
    using GameLuaContextImpl::GameLuaContextImpl;
    virtual ~GameLua51Context() = default;
    void LoadMyLuaApi() override {
        GameLuaContextImpl::LoadMyLuaApi();
        HOOK_LUA_API(lua_newstate) + [](lua_Alloc f, void *ud) {
            return CreateLuaStateForCurrentVm(f, ud, "lua_newstate");
        };
        api._luaL_traceback = +[](lua_State *L, lua_State *L1, const char *msg, int level) {
            auto &ctx = static_cast<GameLua51Context &>(*currentCtx);
            return ctx.luaL_traceback(L, L1, msg, level);
        };
        api._lua_copy = +[](lua_State *L, int from, int to) {
            auto &ctx = static_cast<GameLua51Context &>(*currentCtx);
            int abs_to = ctx->_lua_absindex(L, to);
            ctx->_luaL_checkstack(L, 1, "not enough stack slots");
            ctx->_lua_pushvalue(L, from);
            ctx->_lua_replace(L, abs_to);
        };
        api._luaL_checkstack = +[](lua_State *L, int sp, const char *msg) {
            auto &ctx = static_cast<GameLua51Context &>(*currentCtx);
            if (!ctx->_lua_checkstack(L, sp + LUA_MINSTACK)) {
                if (msg != NULL)
                    ctx->_luaL_error(L, "stack overflow (%s)", msg);
                else {
                    ctx->_lua_pushliteral(L, "stack overflow");
                    ctx->_lua_error(L);
                }
            }
        };
        api._luaL_testudata = +[](lua_State *L, int ud, const char *tname) -> void * {
            auto &ctx = static_cast<GameLua51Context &>(*currentCtx);
            void* p = ctx->_lua_touserdata(L, ud);
            ctx->_luaL_checkstack(L, 2, "not enough stack slots");
            if (p == NULL || !ctx->_lua_getmetatable(L, ud))
                return NULL;
            else {
                int res = 0;
                ctx->_luaL_getmetatable(L, tname);
                res = ctx->_lua_rawequal(L, -1, -2);
                ctx->_lua_pop(L, 2);
                if (!res)
                    p = NULL;
            }
            return p;
        };
        api._luaL_setmetatable = +[](lua_State *L, const char *tname) {
            auto &ctx = static_cast<GameLua51Context &>(*currentCtx);
            ctx->_luaL_checkstack(L, 1, "not enough stack slots");
            ctx->_luaL_getmetatable(L, tname);
            ctx->_lua_setmetatable(L, -2);
        };
        api._lua_tonumberx = +[](lua_State *L, int i, int *isnum) -> lua_Number {
            auto &ctx = static_cast<GameLua51Context &>(*currentCtx);
            lua_Number n = ctx->_lua_tonumber(L, i);
            if (isnum) {
                *isnum = (n != 0 || ctx->_lua_isnumber(L, i));
            }
            return n;
        };
        api._lua_tointegerx = +[](lua_State *L, int i, int *isnum) -> lua_Integer {
            auto &ctx = static_cast<GameLua51Context &>(*currentCtx);
            int ok = 0;
            lua_Number n = ctx->_lua_tonumberx(L, i, &ok);
            if (ok) {
                if (n == (lua_Integer)n) {
                    if (isnum)
                        *isnum = 1;
                    return (lua_Integer)n;
                }
            }
            if (isnum)
                *isnum = 0;
            return 0;
        };
    }

#define LEVELS1 12 /* size of the first part of the stack */
#define LEVELS2 10 /* size of the second part of the stack */
    void luaL_traceback(lua_State *L, lua_State *L1, const char *msg, int level) {
        lua_Debug ar;
        int firstpart = 1; /* still before eventual '...' */
        int basetop = api._lua_gettop(L);
        if (msg)
            api._lua_pushfstring(L, "%s\n", msg);
        api._lua_pushliteral(L, "stack traceback:");
        while (api._lua_getstack(L1, level++, &ar)) {
            if (level > LEVELS1 && firstpart) {
                /* no more than 'LEVELS2' more levels? */
                if (!api._lua_getstack(L1, level + LEVELS2, &ar))
                    level--; /* keep going */
                else {
                    api._lua_pushliteral(L, "\n\t...");                 /* too many levels */
                    while (api._lua_getstack(L1, level + LEVELS2, &ar)) /* find last levels */
                        level++;
                }
                firstpart = 0;
                continue;
            }
            api._lua_pushliteral(L, "\n\t");
            api._lua_getinfo(L1, "Snl", &ar);
            api._lua_pushfstring(L, "%s:", ar.short_src);
            if (ar.currentline > 0)
                api._lua_pushfstring(L, "%d:", ar.currentline);
            if (*ar.namewhat != '\0') /* is there a name? */
                api._lua_pushfstring(L, " in function '%s'", ar.name);
            else {
                if (*ar.what == 'm') /* main? */
                    api._lua_pushliteral(L, " in main chunk");
                else if (*ar.what == 'C' || *ar.what == 't')
                    api._lua_pushliteral(L, " ?"); /* C function or tail call */
                else
                    api._lua_pushfstring(L, " in function <%s:%d>",
                                         ar.short_src, ar.linedefined);
            }
            api._lua_concat(L, api._lua_gettop(L) - basetop);
        }
        api._lua_concat(L, api._lua_gettop(L) - basetop);
    }
};
