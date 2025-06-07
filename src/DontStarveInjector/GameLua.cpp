#include "GameLua.hpp"
#include <string_view>
#include <spdlog/spdlog.h>
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

constexpr const char* defualtLua51LibraryName = SHARED_LIBRARY_PRE "lua51Original" SHARED_LIBRARY_EXT;
constexpr const char* defualtLuajitLibraryName = SHARED_LIBRARY_PRE "lua51DS" SHARED_LIBRARY_EXT;

GameLuaContext gameLua51Ctx{
        .sharedlibraryName = defualtLua51LibraryName,
        .luaType = GameLuaType::Lua51,
        .luaState = nullptr,
        .interface = nullptr};

GameLuaContext gameLuajitCtx{
        .sharedlibraryName = defualtLuajitLibraryName,
        .luaType = GameLuaType::LuaJit,
        .luaState = nullptr,
        .interface = nullptr};

GameLuaContext &GetGameLuaContext() {
    static GameLuaContext ctx;
    return ctx;
}

#include "api_listener.hpp"

#if USE_FAKE_API
extern std::unordered_map<std::string_view, void *> lua_fake_apis;

#include <lua.hpp>
void *GetLuaJitAddress(const char *name) {
    char buf[64];
    snprintf(buf, 64, "fake_%s", name);
    return lua_fake_apis[name];
}
#else
#define GetLuaJitAddress(name) loadlibproc(hluajitModule, name)
#endif

#if USE_LISTENER
static GumInterceptor *interceptor;
#endif

enum class LUA_EVENT {
    new_state,
    close_state,
    call_lua_gc,
};

void lua_event_notifyer(LUA_EVENT, lua_State *);
static void *lua_newstate_hooker(void *, void *ud) {
    auto L = luaL_newstate();
    lua_event_notifyer(LUA_EVENT::new_state, L);
    spdlog::info("luaL_newstate:{}", (void *) L);
    return L;
}

static void lua_close_hooker(lua_State *L) {
    lua_event_notifyer(LUA_EVENT::close_state, L);
    spdlog::info("lua_close:{}", (void *) L);
    lua_close(L);
}

static int lua_gc_hooker(lua_State *L, int w, int d) {
    lua_event_notifyer(LUA_EVENT::call_lua_gc, L);
    return lua_gc(L, w, d);
}
#if !ONLY_LUA51

#if USE_FAKE_API
extern lua_State *map_handler(lua_State *L);
#endif

void lua_setfield_fake(lua_State *L, int idx, const char *k) {
#if USE_FAKE_API
    L = map_handler(L);
#endif
    if (lua_gettop(L) == 0)
        lua_pushnil(L);
    lua_setfield(L, idx, k);
}

#endif

#if USE_LISTENER
GumInvocationListener *listener;
static gboolean PrintCallCb(const GumExportDetails *details,
                            gpointer user_data) {
    gum_interceptor_attach(interceptor, (void *) details->address, listener, (void *) details->name);
    return true;
}
#endif

int (*luaopen_game_io)(lua_State *L);
static void luaL_openlibs_hooker(lua_State *L) {
    luaL_openlibs(L);
    if (luaopen_game_io) {
        lua_pushcfunction(L, luaopen_game_io);
        lua_pushstring(L, LUA_IOLIBNAME);
        lua_call(L, 1, 0);
    }
}

static void *get_luajit_address(const std::string_view &name) {
    void *replacer = GetLuaJitAddress(name.data());
    assert(replacer != nullptr);
#if !ONLY_LUA51
    if (name == "lua_newstate"sv) {
        // TODO 2.1 delete this
        replacer = (void *) &lua_newstate_hooker;
    } else if (name == "lua_setfield"sv) {
        replacer = (void *) &lua_setfield_fake;
    } else if (name == "lua_close"sv) {
        replacer = (void *) &lua_close_hooker;
    } else if (name == "lua_gc"sv) {
        replacer = (void *) &lua_gc_hooker;
    }
#if USE_GAME_IO
    else if (name == "luaL_openlibs"sv) {
        replacer = (void *) &luaL_openlibs_hooker;
    }
#endif
#endif
    return replacer;
}

static void voidFunc() {
}

static std::map<std::string, std::string> replace_hook = {
#if !ONLY_LUA51
        {"lua_getinfo", "lua_getinfo_game"}
#endif
};

static void ReplaceLuaModule(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports) {
    hluajitModule = loadlib(luajitModuleName);
    if (!hluajitModule) {
        spdlog::error("cannot load luajit: {}", luajitModuleName);
        return;
    }
    std::vector<const std::string *> hookTargets;
    hookTargets.reserve(exports.size());
    for (auto &[name, _]: exports) {
#if USE_GAME_IO
        if (name == "luaopen_io"sv) {
            continue;
        }
#endif
        hookTargets.emplace_back(&name);
    }

    std::list<uint8_t *> hookeds;
    for (auto *_name: hookTargets) {
        auto &name = *_name;
        auto offset = signatures.funcs.at(name).offset;
        auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
        auto replacer = (uint8_t *) get_luajit_address(name);
        if (replace_hook.contains(name)) {
            spdlog::info("ReplaceLuaModule hook {} to {}", name, replace_hook[name]);
            auto replacer1 = (uint8_t *) get_luajit_address(replace_hook[name]);
            if (replacer1)
                replacer = replacer1;
        }
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
#if USE_GAME_IO
    {
        auto offset = signatures.funcs.at("luaopen_io").offset;
        auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
        luaopen_game_io = decltype(luaopen_game_io)(target);
    }
#endif

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

#if REPLACE_IO
    extern void init_luajit_io(module_handler_t hluajitModule);
    init_luajit_io(hluajitModule);
#endif

    extern void init_luajit_jit_opt(module_handler_t hluajitModule);
    init_luajit_jit_opt(hluajitModule);

#if USE_LISTENER
    listener = (GumInvocationListener *) g_object_new(EXAMPLE_TYPE_LISTENER, NULL);
    gum_module_enumerate_exports(target_module_name, PrintCallCb, NULL);
#endif
}


void ReplaceLuaApi(GameLuaType type, const char *shared_library_name) {
    if (type == GameLuaType::Lua51) {
        GetGameLuaContext().luaType = GameLuaType::Lua51;
        GetGameLuaContext().sharedlibraryName = shared_library_name;
        GetGameLuaContext().interface = new LuaInterfaces();
    } else if (type == GameLuaType::LuaJit) {
        GetGameLuaContext().luaType = GameLuaType::LuaJit;
        GetGameLuaContext().sharedlibraryName = shared_library_name;
        GetGameLuaContext().interface = new LuaInterfaces();
    }
}