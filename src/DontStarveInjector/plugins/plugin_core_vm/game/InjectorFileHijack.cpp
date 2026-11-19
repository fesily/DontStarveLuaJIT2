// game/InjectorFileHijack.cpp — injector file hijack policy: relocation + one-shot afterload.
//
// The Lua framework used to replace the globals `require` and `kleiloadlua` with Lua closures,
// so any Lua probe saw what="Lua", nups=3, source="@GameLuaInjectFramework.lua", the engine's
// stock C function object was gone and every load carried a Lua frame. This policy runs from the
// closure's implementation pointer instead (game/CfunctionHook.hpp), which keeps the Lua-visible
// object identical: same GCfunc, what="C", same upvalue count, same tostring and keys.
//
// Policy state stays in the framework's own Lua tables (GameLuaInjector.relocations /
// .injectors); this TU only reads them and calls GameLuaInjector.run_inject, which keeps the
// one-shot/xpcall semantics the Lua wrapper had.
#include "game/InjectorFileHijack.hpp"
#include "game/PrivateLuaRegistry.hpp"

#include <spdlog/spdlog.h>

namespace {

// filename = GameLuaInjector.relocations[filename] or filename. Mirrors the Lua original: any
// truthy value replaces the name, one level only. Leaves extra values on the stack; the caller
// restores the argument count with lua_settop.
void relocate_filename(LuaApis &api, lua_State *L) {
    api.push_game_injector(L);
    api._lua_getfield(L, -1, "relocations");
    if (!api._lua_istable(L, -1)) {
        api._lua_pop(L, 2);
        return;
    }
    api._lua_pushvalue(L, 1);
    api._lua_rawget(L, -2);
    if (api._lua_toboolean(L, -1)) {
        api._lua_replace(L, 1);
    } else {
        api._lua_pop(L, 1);
    }
}

// do_inject(GameLuaInjector.injectors[filename], module): the framework's own one-shot
// afterload runner, including its traceback handling. `first_result` is the stack slot of the
// loader's first result; the caller's stack is left exactly as it was found.
void run_afterload(LuaApis &api, lua_State *L, int first_result, int nres) {
    api.push_game_injector(L);
    api._lua_getfield(L, -1, "run_inject");
    if (!api._lua_isfunction(L, -1)) {
        api._lua_pop(L, 2);
        return;
    }
    api._lua_pushvalue(L, 1); // filename, after relocation
    if (nres > 0) {
        api._lua_pushvalue(L, first_result); // the loaded module
    } else {
        api._lua_pushnil(L);
    }
    if (api._lua_pcall(L, 2, 0, 0) != 0) {
        const char *err = api._lua_tostring(L, -1);
        spdlog::error("[luajit] GameLuaInjector.run_inject failed: {}", err ? err : "?");
        api._lua_pop(L, 1);
    }
    api._lua_pop(L, 1); // GameLuaInjector
}

} // namespace

namespace ds::core_vm::detail {

int file_hijack_policy(LuaApis &api, lua_State *L, lua_CFunction original, void *userdata) {
    (void) userdata; // one policy for every hooked loader; its state is in the Lua tables
    const int nargs = api._lua_gettop(L);
    if (nargs < 1) { // the policy indexes argument 1; let the original report the bad call
        return original(L);
    }
    relocate_filename(api, L);
    api._lua_settop(L, nargs); // the relocated call must see exactly the original arguments
    const int nres = original(L);
    // A C function's results are the TOP nres slots, not the first nres slots of the frame;
    // the caller keeps them by returning nres, so nothing may be left on top of them.
    run_afterload(api, L, api._lua_gettop(L) - nres + 1, nres);
    return nres;
}

} // namespace ds::core_vm::detail
