#include "GameLua.hpp"
#include "config.hpp"
#include "DontStarveSignature.hpp"
#include "GameSignature.hpp"
#include "util/inlinehook.hpp"
#include "gameio.h"
#include <string_view>
#include <map>
#include <spdlog/spdlog.h>
#include <functional>
using namespace std::literals;


#ifdef _WIN32
#define SHARED_LIBRARY_EXT ".dll"
#define SHARED_LIBRARY_PRE ""
#elif defined(__linux__)
#define SHARED_LIBRARY_EXT ".so"
#define SHARED_LIBRARY_PRE "lib"
#elif defined(__APPLE__)
#define SHARED_LIBRARY_EXT ".dylib"
#define SHARED_LIBRARY_PRE "lib"
#endif


#pragma region GAME_IO
bool UseGameIO() {
    bool use_game_io = getenv("USE_GAME_IO") != nullptr;
    return use_game_io;
}
int (*luaopen_game_io)(lua_State *L);
void GameLuaContext::luaL_openlibs_hooker(lua_State *L) {
    api._luaL_openlibs(L);
    if (luaopen_game_io) {
        api._lua_pushcclosure(L, (luaopen_game_io), 0);
        api._lua_pushstring(L, LUA_IOLIBNAME);
        api._lua_call(L, 1, 0);
    }
}

void load_game_fn_io_open(const Signatures &signatures) {
    auto offset = signatures.funcs.at("luaopen_io").offset;
    auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
    luaopen_game_io = decltype(luaopen_game_io)(target);
}
#pragma endregion GAME_IO

#define WAPPER_LUA_API(name)                          \
    static decltype(&name) real_##name = api._##name; \
    api._##name = (decltype(&name))

void lua_event_notifyer(LUA_EVENT, lua_State *);

struct GameLuaContextImpl : GameLuaContext {
    GameLuaContextImpl(const char *sharedLibraryName, GameLuaType type)
        : GameLuaContext{sharedLibraryName, type} {
    }
    bool LoadLuaModule() {
        if (getenv("GAME_LUA_MODULE_NAME")) {
            sharedlibraryName = getenv("GAME_LUA_MODULE_NAME");
        }

        LuaModule = gum_process_find_module_by_name(sharedlibraryName.c_str());
        if (!LuaModule) {
            GError *error = nullptr;
            LuaModule = gum_module_load(sharedlibraryName.c_str(), &error);
            if (!LuaModule) {
                spdlog::error("Cannot load Lua module: {}, error: {}", sharedlibraryName, error->message);
                g_error_free(error);
            } else {
                spdlog::info("Loaded Lua module: {}", sharedlibraryName);
            }
        }
        if (!LuaModule) {
            spdlog::error("Failed to load Lua module: {}", sharedlibraryName);
        }
        return LuaModule != nullptr;
    }
    virtual void LoadAllInterfaces() {
        if (LuaModule) {
#define LOAD_LUA_API(name) \
    api._##name = (decltype(&name)) gum_module_find_export_by_name(LuaModule, #name);
            LUA51_API_DEFINES(LOAD_LUA_API);
        }
    }

    virtual void *GetLuaExport(const std::string_view &target) {
        if (!LuaModule) {
            spdlog::error("Lua module is not loaded, cannot find export: {}", target);
            return nullptr;
        }
        if (UseGameIO() && target == "luaL_openlibs") {
            decltype(&luaL_openlibs) hooker = +[](lua_State *L) {
                return GetGameLuaContext().luaL_openlibs_hooker(L);
            };
            return (void *) hooker;
        }
#define GET_LUA_API(name)            \
    if (target == #name) {           \
        return (void *) api._##name; \
    }
        LUA51_API_DEFINES(GET_LUA_API);
#undef GET_LUA_API
        return nullptr;
    }

    virtual void LoadMyLuaApi() {
        WAPPER_LUA_API(lua_gc) + [](lua_State *L, int what, int data) {
            lua_event_notifyer(LUA_EVENT::call_lua_gc, L);
            return real_lua_gc(L, what, data);
        };
        WAPPER_LUA_API(lua_close) + [](lua_State *L) {
            lua_event_notifyer(LUA_EVENT::close_state, L);
            spdlog::info("lua_close:{}", (void *) L);
            return real_lua_close(L);
        };
    }

    virtual ~GameLuaContextImpl() = default;
    GameLuaContextImpl(const GameLuaContextImpl &) = delete;
};

struct GameLua51Context : GameLuaContextImpl {
    using GameLuaContextImpl::GameLuaContextImpl;
    virtual ~GameLua51Context() = default;
    void LoadMyLuaApi() override {
        GameLuaContextImpl::LoadMyLuaApi();
        WAPPER_LUA_API(lua_newstate) + [](lua_Alloc f, void *ud) {
            lua_event_notifyer(LUA_EVENT::new_state, nullptr);
            auto L = real_lua_newstate(f, ud);
            spdlog::info("lua_newstate:{}", (void *) L);
            return L;
        };
    }
};

struct GameLuaContextJit : GameLuaContextImpl {
    using GameLuaContextImpl::GameLuaContextImpl;
    virtual ~GameLuaContextJit() = default;

    void LoadAllInterfaces() override {
        GameLuaContextImpl::LoadAllInterfaces();
        LUAJIT_API_DEFINES(LOAD_LUA_API);
        LUAJIT_API_DEFINES_5_2(LOAD_LUA_API);
        LUAJIT_API_DEFINES_5_3(LOAD_LUA_API);

        if (LuaModule) {
            api._lua_getinfo = (decltype(&lua_getinfo)) gum_module_find_export_by_name(LuaModule, "lua_getinfo_game");
        }
    }

    void LoadMyLuaApi() override;

    void *lua_newstate_hooker(void *, void *ud) {
        lua_event_notifyer(LUA_EVENT::new_state, nullptr);
        auto L = api._luaL_newstate();
        spdlog::info("luaL_newstate:{}", (void *) L);
        return L;
    }
};

constexpr const char *defualtLua51LibraryName = SHARED_LIBRARY_PRE "lua51Original" SHARED_LIBRARY_EXT;
constexpr const char *defualtLuajitLibraryName = SHARED_LIBRARY_PRE "lua51DS" SHARED_LIBRARY_EXT;

GameLua51Context gameLua51Ctx{
        defualtLua51LibraryName,
        GameLuaType::_51};

GameLuaContextJit gameLuajitCtx{
        defualtLuajitLibraryName,
        GameLuaType::jit};

void GameLuaContextJit::LoadMyLuaApi() {
    GameLuaContextImpl::LoadMyLuaApi();
    WAPPER_LUA_API(lua_setfield) + [](lua_State *L, int idx, const char *k) {
        auto &api = gameLuajitCtx.api;
        if (api._lua_gettop(L) == 0)
            api._lua_pushnil(L);
        real_lua_setfield(L, idx, k);
    };
    api._lua_newstate = (decltype(&lua_newstate)) +[](lua_Alloc f, void *ud) {
        return gameLuajitCtx.lua_newstate_hooker(f, ud);
    };
}

GameLuaContextImpl *currentCtx = &gameLuajitCtx;
GameLuaContext &GetGameLuaContext() {
    return *currentCtx;
}

static void voidFunc() {
}

GameLuaType currentLuaType = GameLuaType::jit;

extern "C" DONTSTARVEINJECTOR_API void DS_LUAJIT_set_vm_type(GameLuaType type, const char *moduleName) {
    currentLuaType = type;
    if (type == GameLuaType::_51) {
        currentCtx = &gameLua51Ctx;
    } else if (type == GameLuaType::jit) {
        currentCtx = &gameLuajitCtx;
    }
    if (moduleName && std::filesystem::exists(moduleName)) {
        currentCtx->sharedlibraryName = moduleName;
    }
}

void ReplaceLuaModule(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports) {
    if (currentCtx == nullptr) {
        spdlog::error("GameLuaContext is not initialized, cannot replace Lua module");
        return;
    }
    if (!currentCtx->LoadLuaModule())
        return;
    currentCtx->LoadAllInterfaces();
    currentCtx->LoadMyLuaApi();
    std::vector<const std::string *> hookTargets;
    hookTargets.reserve(exports.size());
    for (auto &[name, _]: exports) {
        if (UseGameIO() && name == "luaopen_io"sv) {
            continue;
        }
        hookTargets.emplace_back(&name);
    }

    std::list<uint8_t *> hookeds;
    for (auto *_name: hookTargets) {
        auto &name = *_name;
        auto offset = signatures.funcs.at(name).offset;
        auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
        auto replacer = (uint8_t *) currentCtx->GetLuaExport(name);
        if (!Hook(target, replacer)) {
            spdlog::error("replace {} failed", name);
            break;
        }
        hookeds.emplace_back(target);
        spdlog::info("replace {}: {} to {}", name, (void *) target, (void *) replacer);
    }

    if (hookeds.size() != hookTargets.size()) {
        for (auto target: hookeds) {
            ResetHook(target);
        }
        spdlog::info("reset all hook");
        return;
    }

#if DEBUG_GETSIZE_PATCH
    // In the game code direct read the internal lua vm sturct offset, will crash here
    if (luaRegisterDebugGetsizeSignature.scan(mainPath.c_str())) {
#if DEBUG_GETSIZE_PATCH == 1
        auto code = std::to_array<uint8_t>(
#ifdef _WIN32
                {0x48, 0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x90}
#else
                {0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00, 0x90}
#endif
        );
        HookWriteCode((uint8_t *) luaRegisterDebugGetsizeSignature.target_address, code.data(), code.size());
#else
        Hook((uint8_t *) luaRegisterDebugGetsizeSignature.target_address, (uint8_t *) &voidFunc);
#endif
    }
#endif

    if (currentLuaType == GameLuaType::jit) {
        init_luajit_jit_opt(currentCtx->LuaModule);
        if (getenv("DISABLE_REPLACE_IO") != nullptr) {
            spdlog::info("DISABLE_REPLACE_IO is set, skip replacing io module");
        } else {
            init_luajit_io(currentCtx->LuaModule);
        }
    }
}
