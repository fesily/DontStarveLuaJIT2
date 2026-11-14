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

// ---- Engine-equivalent file loaders (JIT context only) --------------------
//
// LuaJIT's dofile/loadfile end up in its own luaL_loadfile, i.e. the injector's
// lj_fopen path mapping, while io/modimport use the engine's file access. The
// engine's luaL_loadfile is not reachable (its body walks internal lauxlib
// layout), so this is a C equivalent: chunk name "@<path>"/"=stdin", hashbang
// and precompiled-chunk blocking, and reads through the engine io table that
// the same openlibs hook installed.
//
// Klei's errfile("OLDFILEACCESSMETHOD") marker is not reproduced: it is an
// anti-old-API watermark that ends up inside Proto->source (the second marker
// call replaces "@path" with the marker text and lua_load takes it as the chunk
// name); it never stays on the stack.
static int DsEngineLoadFile(lua_State *L, const char *path, size_t len) {
    auto &api = GetGameLuaContext().api;
    const std::string name = path != nullptr ? std::string{"@"} + std::string{path, len} : std::string{"=stdin"};

    api._lua_getfield(L, LUA_GLOBALSINDEX, "io");
    if (api._lua_type(L, -1) != LUA_TTABLE) {
        api._lua_settop(L, -(1) - 1);
        api._lua_pushfstring(L, "cannot open %s", path != nullptr ? path : "stdin");
        return LUA_ERRFILE;
    }
    if (path != nullptr) {
        api._lua_getfield(L, -1, "open");
        api._lua_pushlstring(L, path, len);
        api._lua_pushstring(L, "rb");
        api._lua_call(L, 2, 1);
        api._lua_remove(L, -2);
    } else {
        api._lua_getfield(L, -1, "stdin");
        api._lua_remove(L, -2);
    }
    if (api._lua_type(L, -1) != LUA_TUSERDATA) {
        api._lua_settop(L, -(1) - 1);
        api._lua_pushfstring(L, "cannot open %s", path != nullptr ? path : "stdin");
        return LUA_ERRFILE;
    }
    api._lua_getfield(L, -1, "read");
    api._lua_pushvalue(L, -2);
    api._lua_pushstring(L, "*a");
    api._lua_call(L, 2, 1);
    api._lua_remove(L, -2);
    size_t srclen = 0;
    const char *src = api._lua_tolstring(L, -1, &srclen);
    if (src == nullptr) {
        api._lua_settop(L, -(1) - 1);
        api._lua_pushfstring(L, "cannot read %s", path != nullptr ? path : "stdin");
        return LUA_ERRFILE;
    }
    if (srclen > 0) {
        const auto first = static_cast<unsigned char>(src[0]);
        if (first == '#') {
            api._lua_pushfstring(L, "%s - Hashbang blocked.", name.c_str());
            api._lua_remove(L, -2);
            return LUA_ERRSYNTAX;
        }
        if (first == 0x1B && path != nullptr) {
            api._lua_pushfstring(L, "%s - Compiled Lua blocked.", name.c_str());
            api._lua_remove(L, -2);
            return LUA_ERRSYNTAX;
        }
    }
    const int status = api._luaL_loadbuffer(L, src, srclen, name.c_str());
    api._lua_remove(L, -2);
    return status;
}

static int DsDoFile(lua_State *L) {
    auto &api = GetGameLuaContext().api;
    const int nargs = api._lua_gettop(L);
    size_t len = 0;
    const char *path = api._luaL_optlstring(L, 1, nullptr, &len);
    if (DsEngineLoadFile(L, path, len) != 0) {
        return api._lua_error(L);
    }
    api._lua_call(L, 0, LUA_MULTRET);
    return api._lua_gettop(L) - nargs;
}

// JIT states only: the PUC/game state already runs the engine's luaL_loadfile.
// loadfile is left alone on purpose: main.lua replaces it with the engine's
// loadfn (-> kleiloadlua), which is already engine file access; only dofile
// stays LuaJIT's lbaselib + luaL_loadfile, which is the leaking path.
static void InstallEngineDofile(lua_State *L) {
    auto &api = GetGameLuaContext().api;
    api._lua_pushcfunction(L, DsDoFile);
    api._lua_setfield(L, LUA_GLOBALSINDEX, "dofile");
    spdlog::info("Replaced Lua dofile with the engine file access");
}

} // namespace

struct GameLuaContextJit : GameLuaContextImpl {
    using GameLuaContextImpl::GameLuaContextImpl;
    virtual ~GameLuaContextJit() = default;

    void luaL_openlibs_hooker(lua_State *L) override {
        GameLuaContextImpl::luaL_openlibs_hooker(L);
        InstallEngineDofile(L);
    }

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
