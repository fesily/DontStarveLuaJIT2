// game/GameLuaContextJit.cpp — LuaJIT contexts (jit + jit_gen share implementation)
#include "game/GameLuaContextImpl.hpp"
#include "game/GameLuaInternal.hpp"
#include "game/LuaModDump.hpp"
#include "io/gameio.h"
#include <spdlog/spdlog.h>

using ds::core_vm::detail::CreateLuaStateForCurrentVm;
using ds::core_vm::detail::load_game_fn_io_open;
using ds::core_vm::detail::DefaultLuajitLibraryName;
using ds::core_vm::detail::DefaultLuajitGenLibraryName;

namespace {

using JitLuaLoadXFn = int (*)(lua_State *, lua_Reader, void *, const char *, const char *);
JitLuaLoadXFn g_jit_lua_loadx_original = nullptr;

// LuaJIT funnels every chunk load through lua_loadx (lua_load, luaL_loadbuffer/file and
// the Lua `load()` builtin all end up here), so hooking it covers the mod loader that the
// gdb backtrace showed entering lua_loadx directly.
int JitDumpLuaLoadX(lua_State *L, lua_Reader reader, void *data, const char *chunkname,
                    const char *mode) {
    if (g_jit_lua_loadx_original == nullptr) {
        return LUA_ERRRUN;  // never installed without a trampoline
    }
    if (!ds::core_vm::detail::LuaModDumpShouldDump(chunkname)) {
        return g_jit_lua_loadx_original(L, reader, data, chunkname, mode);
    }
    ds::core_vm::detail::LuaModDumpCall call;
    call.reader = reader;
    call.data = data;
    call.chunkname = chunkname;
    return g_jit_lua_loadx_original(L, &ds::core_vm::detail::LuaModDumpReader, &call,
                                    chunkname, mode);
}

} // namespace

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
        }
    }

    void LoadMyLuaApi() override;

    bool ReplaceApis(const Signatures &signatures, const ListExports_t &exports) override {
        if (!GameLuaContextImpl::ReplaceApis(signatures, exports)) return false;
        init_luajit_io(LuaModule);
        load_game_fn_io_open(signatures);
        // The engine calls the Lua API through the replaced field, so the dump hook must sit
        // on the loaded VM's own lua_load (the game-VM overrideapis route is bypassed here).
        if (ds::core_vm::detail::LuaModDumpEnabled()) {
            static void *hooked_target = nullptr;
            auto it = name2apis.find("lua_loadx");
            if (it != name2apis.end() && it->second != nullptr && *it->second != nullptr &&
                *it->second != hooked_target) {
                auto *interceptor = InjectorCtx::instance()->GetGumInterceptor();
                void *original = nullptr;
                const auto rc = ds::FastHook::Install(interceptor, *it->second,
                                                      (void *) &JitDumpLuaLoadX, &original);
                if (rc == GumReplaceReturn::GUM_REPLACE_OK) {
                    g_jit_lua_loadx_original = reinterpret_cast<JitLuaLoadXFn>(original);
                    hooked_target = *it->second;
                    spdlog::info("installed jit lua_loadx dump hook at {} (trampoline={})",
                                 *it->second, original);
                } else {
                    spdlog::warn("cannot install jit lua_loadx dump hook: {}", (int) rc);
                }
            }
        }
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
    // The streamed mod-source dump is installed in ReplaceApis, directly on the loaded
    // VM's lua_load: the engine calls the API field, so hooking the engine's own entry
    // (the overrideapis route used by the game VM) would be bypassed.
    // lua_setfield is not intercepted here anymore: the empty-stack push-nil guard only
    // masked the missing +1 from the one-way `ret` over the engine's register_debug_getsize
    // (fixed at the source by the VM-scoped gum replace_fast hijack). Verified: a pure-jit
    // boot reaches the same log depth (654 lines) without any guard in place.
    api._lua_newstate = (decltype(&lua_newstate)) +[](lua_Alloc f, void *ud) {
        return CreateLuaStateForCurrentVm(f, ud, "lua_newstate");
    };
}
