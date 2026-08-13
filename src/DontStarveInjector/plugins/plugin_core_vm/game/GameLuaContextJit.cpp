// game/GameLuaContextJit.cpp — LuaJIT contexts (jit + jit_gen share implementation)
#include "game/GameLuaContextImpl.hpp"
#include "game/GameLuaInternal.hpp"
#include "io/gameio.h"
#include <spdlog/spdlog.h>

using ds::core_vm::detail::CreateLuaStateForCurrentVm;
using ds::core_vm::detail::load_game_fn_io_open;
using ds::core_vm::detail::DefaultLuajitLibraryName;
using ds::core_vm::detail::DefaultLuajitGenLibraryName;

char luajit_ds_check_slowtailcall(lua_State *L, const char *chunkname);

struct GameLuaContextJit : GameLuaContextImpl {
    using GameLuaContextImpl::GameLuaContextImpl;
    virtual ~GameLuaContextJit() = default;

    void LoadAllInterfaces() override {
        GameLuaContextImpl::LoadAllInterfaces();
        LUAJIT_API_DEFINES(LOAD_LUA_API);
        LUAJIT_API_DEFINES_5_2(LOAD_LUA_API);
        LUAJIT_API_DEFINES_5_3(LOAD_LUA_API);

        if (LuaModule) {
            auto addr = find_export_by_name(LuaModule, "lua_getinfo_game");
            if (!addr) {
                spdlog::warn("lua_getinfo_game not found in luajit module");
                return;
            }
            api._lua_getinfo = (decltype(&lua_getinfo)) addr;
            typedef char (*lj_check_slowtailcall_fn)(lua_State *L, const char *chunkname);
            void (*lua_ds_set_slowtailcall_cb)(lj_check_slowtailcall_fn fn);
            lua_ds_set_slowtailcall_cb = (decltype(lua_ds_set_slowtailcall_cb)) gum_module_find_export_by_name(LuaModule, "lua_ds_set_slowtailcall_cb");
            if (lua_ds_set_slowtailcall_cb) {
                lua_ds_set_slowtailcall_cb(&luajit_ds_check_slowtailcall);
            }
        }
    }

    void LoadMyLuaApi() override;

    bool ReplaceApis(const Signatures &signatures, const ListExports_t &exports) override {
        if (!GameLuaContextImpl::ReplaceApis(signatures, exports)) return false;
        init_luajit_io(LuaModule);
        load_game_fn_io_open(signatures);
        return true;
    }
};


static GameLuaContextJit gameLuajitCtx{
        DefaultLuajitLibraryName(),
        GameLuaType::jit};

static GameLuaContextJit gameLuajitGenCtx{
        DefaultLuajitGenLibraryName(),
        GameLuaType::jit_gen};

namespace ds::core_vm::detail {
GameLuaContextImpl *ctx_jit() { return &gameLuajitCtx; }
GameLuaContextImpl *ctx_jit_gen() { return &gameLuajitGenCtx; }
} // namespace ds::core_vm::detail

void GameLuaContextJit::LoadMyLuaApi() {
    GameLuaContextImpl::LoadMyLuaApi();
    // Must use currentCtx: both classic jit and jit_gen share this method.
    // Hardcoding gameLuajitCtx leaves gen-mode API pointers null and SEGV on
    // the first lua_setfield during game io open (e.g. "__index").
    HOOK_LUA_API(lua_setfield) + [](lua_State *L, int idx, const char *k) {
        auto &api = currentCtx->api;
        if (api._lua_gettop(L) == 0)
            api._lua_pushnil(L);
        api._lua_setfield(L, idx, k);
    };
    api._lua_newstate = (decltype(&lua_newstate)) +[](lua_Alloc f, void *ud) {
        return CreateLuaStateForCurrentVm(f, ud, "lua_newstate");
    };
}
