#include "GameLua.hpp"
#include "gameModConfig.hpp"
#include "DontStarveSignature.hpp"
#include "GameSignature.hpp"
#include "util/inlinehook.hpp"
#include "util/platform.hpp"
#include "util/lua_io2.hpp"
#include "util/lua51_object.hpp"
#include "gameio.h"
#include "luajit_config.hpp"
#include "lua_debugger_helper.hpp"
#include <string_view>
#include <map>
#include <spdlog/spdlog.h>
#include <functional>
#include <list>
#include <cctype>
#include <ranges>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fstream>
using namespace std::literals;

#ifndef _WIN32
#include <dlfcn.h>
#else
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

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

struct LuaStackGuard {
    GameLuaContext &ctx;
    lua_State *L;
    int top;
    LuaStackGuard(GameLuaContext &c, lua_State *l) : ctx(c), L(l) {
        top = ctx.api._lua_gettop(L);
    }
    LuaStackGuard(GameLuaContext *p, lua_State *l) : LuaStackGuard(*p, l) {
    }
    ~LuaStackGuard() {
        int new_top = ctx.api._lua_gettop(L);
        if (new_top != top) {
            spdlog::error("Lua stack imbalance detected: before={} after={}", top, new_top);
            assert(top == new_top);
            ctx.api._lua_settop(L, top);
        }
    }
};

static int split_string(const std::string_view &str, std::vector<std::string_view> &out, char delimiter) {
    size_t start = 0;
    size_t end = str.find(delimiter);
    while (end != std::string_view::npos) {
        out.push_back(str.substr(start, end - start));
        start = end + 1;
        end = str.find(delimiter, start);
    }
    out.push_back(str.substr(start, end));
    return out.size();
}

#pragma region GAME_IO
bool UseGameIO() {
    return !InjectorConfig::instance()->DisableGameIO;
}
int (*luaopen_game_io)(lua_State *L);
void load_game_fn_io_open(const Signatures &signatures) {
    auto offset = signatures.funcs.at("luaopen_io").offset;
    auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
    luaopen_game_io = (decltype(luaopen_game_io)) target;
}

void replace_game_io_open(GameLuaContext &ctx, lua_State *L) {
    if (luaopen_game_io) {
        ctx.api._lua_pushcclosure(L, (luaopen_game_io), 0);
        ctx.api._lua_pushstring(L, LUA_IOLIBNAME);
        ctx.api._lua_call(L, 1, 0);
    }
}

#pragma endregion GAME_IO

void do_lua_env(GameLuaContext &ctx, lua_State *L, const std::string_view &env) {
    if (env.empty())
        return;
    const char *init = getenv(env.data());
    if (init == NULL)
        return;
    if (init[0] == '@')
        ctx->_luaL_dofile(L, init + 1);
    else
        ctx->_luaL_dostring(L, init);
}

#define GameLuaInjectorName "GameLuaInjector"

struct GameLuaInjectorFramework {
    void init(GameLuaContext &ctx, lua_State *L) {
        LuaStackGuard guard(ctx, L);
#include "GameLuaInjectFramework.c"
        auto buffer = std::string{GameLuaInjectFramework, GameLuaInjectFramework_len};
        ctx->_luaL_loadbuffer(L, buffer.c_str(), buffer.size(), "@GameLuaInjectFramework.lua");

        // register spdlog in lua
        ctx->_lua_newtable(L);
        ctx->_lua_pushcfunction(L, +[](lua_State *L) -> int {
            auto &ctx = GetGameLuaContext();
            const char *msg = ctx->_luaL_checkstring(L, 1);
            spdlog::info("[Lua] {}", msg); 
            return 0; });
        ctx->_lua_setfield(L, -2, "info");
        ctx->_lua_pushcfunction(L, +[](lua_State *L) -> int {
            auto &ctx = GetGameLuaContext();
            const char *msg = ctx->_luaL_checkstring(L, 1);
            spdlog::warn("[Lua] {}", msg);
            return 0; });
        ctx->_lua_setfield(L, -2, "warn");
        ctx->_lua_pushcfunction(L, +[](lua_State *L) -> int {
            auto &ctx = GetGameLuaContext();
            const char *msg = ctx->_luaL_checkstring(L, 1);
            spdlog::error("[Lua] {}", msg);
            return 0; });
        ctx->_lua_setfield(L, -2, "error");

        if (ctx.luaType == GameLuaType::game) {
            // custom io2 for game lua
            ctx->_lua_pushcfunction(L, luaopen_io2);
            ctx->_lua_pushstring(L, "io2");
            ctx->_lua_call(L, 1, 0);
            // push native_getenv
            ctx->_lua_pushcfunction(L, +[](lua_State *L) -> int {
                auto &ctx = GetGameLuaContext();
                const char *varname = ctx->_luaL_checkstring(L, 1);
                const char *value = getenv(varname);
                if (value) {
                    ctx->_lua_pushstring(L, value);
                } else {
                    ctx->_lua_pushnil(L);
                }
                return 1; });
        } else {
            ctx->_lua_pushnil(L);
        }
        ctx->_lua_pcall(L, 2, 0, 0);
    }

    void forceEnabledLuaMod(GameLuaContext &ctx, lua_State *L, const std::string_view &modname) {
        LuaStackGuard guard(ctx, L);
        int ret = ctx->_luaL_dostring(L, fmt::format(GameLuaInjectorName ".forceEnableLuaMod(true, [[{}]])", modname).c_str());
        if (ret != LUA_OK) {
            spdlog::error("{}", ctx->_lua_tostring(L, -1));
        }
        assert(ret == LUA_OK);
        spdlog::info("Forced enabled Lua mod: {}", modname);
    }
};
static GameLuaInjectorFramework gameLuaInjectorFramework;

void lua_event_notifyer(LUA_EVENT, lua_State *);
static std::string wrapper_game_main_buffer(lua_State *L, std::string_view buffer);
struct GameLuaContextImpl : GameLuaContext {
    GameLuaContextImpl(const char *sharedLibraryName, GameLuaType type)
        : GameLuaContext{sharedLibraryName, type} {
    }

    virtual void luaL_openlibs_hooker(lua_State *L) {
        api._luaL_openlibs(L);
        do_lua_env(*this, L, "GAME_INIT");
        gameLuaInjectorFramework.init(*this, L);

        if (InjectorConfig::instance()->enable_lua_debugger) {
            dontstarveinjector::lua_debugger_helper::initialize_lua_debugger();
        }

        auto config = luajit_config::read_from_file();
        if (config) {
            if (InjectorConfig::instance()->DisableForceLoadLuaJITMod) {
                return;
            }
            if (!config->always_enable_mod) return;

            if (config->modmain_path.empty() || !std::filesystem::exists(config->modmain_path)) {
                return;
            }
            gameLuaInjectorFramework.forceEnabledLuaMod(*this, L, config->modname);
        }
        // register game injector
        int luaopen_GameInjector(lua_State *L);
        api._lua_pushcfunction(L, luaopen_GameInjector);
        api._lua_pushstring(L, "GameInjector");
        api._lua_call(L, 1, 0);
    }

    virtual bool LoadLuaModule() {
        if (getenv("GAME_LUA_MODULE_NAME")) {
            sharedlibraryName = getenv("GAME_LUA_MODULE_NAME");
        }

        LuaModule = gum_process_find_module_by_name(sharedlibraryName.c_str());
        if (!LuaModule) {
            GError *error = nullptr;
#ifndef _WIN32
            loadlib(sharedlibraryName.c_str());
#endif
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
#define LOAD_LUA_API(name)                                                 \
    api._##name = (decltype(&name)) find_export_by_name(LuaModule, #name); \
    name2apis[#name] = (void **) &api._##name;

            LUA51_API_DEFINES(LOAD_LUA_API);
        }
    }

    virtual void *GetLuaExport(const std::string_view &target) {
        if (!LuaModule) {
            spdlog::error("Lua module is not loaded, cannot find export: {}", target);
            return nullptr;
        }
        if (auto iter = overrideapis.find(std::string{target}); iter != overrideapis.end()) {
            return iter->second;
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
#define HOOK_LUA_API(name) \
    overrideapis[#name] = (void *) (decltype(&#name))

        HOOK_LUA_API(lua_gc) + [](lua_State *L, int what, int data) {
            lua_event_notifyer(LUA_EVENT::call_lua_gc, L);
            return (*currentCtx)->_lua_gc(L, what, data);
        };
        HOOK_LUA_API(lua_close) + [](lua_State *L) {
            lua_event_notifyer(LUA_EVENT::close_state, L);
            spdlog::info("lua_close:{}", (void *) L);
            return (*currentCtx)->_lua_close(L);
        };
        HOOK_LUA_API(luaL_openlibs) + [](lua_State *L) {
            LuaStackGuard guard(*currentCtx, L);
            currentCtx->luaL_openlibs_hooker(L);
        };
        HOOK_LUA_API(luaL_loadbuffer) + [](lua_State *L, const char *buff, size_t size, const char *name) {
            auto &ctx = *currentCtx;
            if (name == "@scripts/main.lua"sv) {
                ctx->_luaL_dostring(L, GameLuaInjectorName ".init()");
                // load custom main.lua script
                int top = ctx->_lua_gettop(L);
                auto new_buffer = wrapper_game_main_buffer(L, {buff, size});
                assert(ctx->_lua_gettop(L) == top);
                if (new_buffer.empty()) {
                    return ctx->_luaL_loadbuffer(L, buff, size, name);
                }
                return ctx->_luaL_loadbuffer(L, new_buffer.c_str(), new_buffer.size(), new_buffer.c_str());
            }
            return ctx->_luaL_loadbuffer(L, buff, size, name);
        };
    }

    virtual bool ReplaceApis(const Signatures &signatures, const ListExports_t &exports) {
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
            auto replacer = (uint8_t *) GetLuaExport(name);
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
            return false;
        }
        return true;
    }

    virtual void HotfixApis(const std::string &mainPath) {
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
    }

    virtual ~GameLuaContextImpl() = default;
    GameLuaContextImpl(const GameLuaContextImpl &) = delete;
    decltype(&gum_module_find_export_by_name) find_export_by_name = &gum_module_find_export_by_name;
    std::map<std::string, void *> overrideapis;
    std::map<std::string, void **> name2apis;
    static GameLuaContextImpl *currentCtx;
};

GameLuaContextImpl *GameLuaContextImpl::currentCtx = nullptr;
struct GameLua51Context : GameLuaContextImpl {
    using GameLuaContextImpl::GameLuaContextImpl;
    virtual ~GameLua51Context() = default;
    void LoadMyLuaApi() override {
        GameLuaContextImpl::LoadMyLuaApi();
        HOOK_LUA_API(lua_newstate) + [](lua_Alloc f, void *ud) {
            lua_event_notifyer(LUA_EVENT::new_state, nullptr);
            auto L = GetGameLuaContext()->_lua_newstate(f, ud);
            spdlog::info("lua_newstate:{}", (void *) L);
            return L;
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

    void *lua_newstate_hooker(void *ud) {
        lua_event_notifyer(LUA_EVENT::new_state, nullptr);
        auto L = api._luaL_newstate();
        spdlog::info("luaL_newstate:{}", (void *) L);
        return L;
    }
    bool ReplaceApis(const Signatures &signatures, const ListExports_t &exports) override {
        if (!GameLuaContextImpl::ReplaceApis(signatures, exports)) return false;
        init_luajit_jit_opt(LuaModule);
        init_luajit_io(LuaModule);
        if (InjectorCtx::instance()->config.DisableReplaceLuaIO) {
            spdlog::info("DISABLE_REPLACE_LUA_IO is set, skip replacing io module");
        } else {
            if (UseGameIO()) {
                load_game_fn_io_open(signatures);
                //void luaL_defaultlib_update(luaL_Reg* newlib);
                auto luaL_defaultlib_update = ((void (*)(luaL_Reg *)) gum_module_find_export_by_name(LuaModule, "luaL_defaultlib_update"));
                luaL_Reg game_io_lib = {
                        LUA_IOLIBNAME,
                        luaopen_game_io};
                luaL_defaultlib_update(&game_io_lib);

                auto luaopen_io2 = ((int (*)(lua_State *)) gum_module_find_export_by_name(LuaModule, "luaopen_io2"));
                if (luaopen_io2) {
                    luaL_Reg io2_lib = {
                            "io2",
                            luaopen_io2};
                    luaL_defaultlib_update(&io2_lib);
                    spdlog::info("Injector luaopen_io2");
                }
                spdlog::info("Replaced luaopen_io with game io open function");
            }
        }
        return true;
    }
};

struct GameLuaContextGame : GameLua51Context {
    GameLuaContextGame(GameLuaType type)
        : GameLua51Context{"", type} {
        find_export_by_name = &GameFindExportByName;
    }
    virtual ~GameLuaContextGame() = default;
    bool LoadLuaModule() override {
        // game lua module is already loaded by game
        interceptor = InjectorCtx::instance()->GetGumInterceptor();
        LuaModule = gum_process_get_main_module();
        InjectorConfig::EnvOrCmdOptValue dump_opts{"dump_lua_mods"};
        auto dump_mods_str = static_cast<const char *>(dump_opts);
        if (dump_mods_str && strlen(dump_mods_str) > 0) {
            //split by ';'
            std::string_view sv{dump_mods_str};
            std::vector<std::string_view> outs;
            split_string(sv, outs, ';');
            for (const auto &modname: outs) {
                dump_mod_names.emplace_back(std::string{modname});
            }
        }
        return true;
    }
    void luaL_openlibs_hooker(lua_State *L) override {
        if (InjectorConfig::instance()->enable_lua_debugger) {
            LuaStackGuard guard(*this, L);
            auto handler = dontstarveinjector::lua_debugger_helper::initialize_lua_debugger();
            auto so_path = getenv(LUA_DEBUG_CORE_DEBUGGER);
            if (so_path) {
                void **lib = ll_register(L, so_path);
                if (lib)
                    *lib = handler;
                else {
                    spdlog::warn("Cannot register lua debugger api");
                }
                api._lua_pop(L, 1);
            } else {
                spdlog::warn("LUA_DEBUG_CORE_DEBUGGER is not set, cannot register lua debugger api");
            }
        }
        GameLua51Context::luaL_openlibs_hooker(L);
        for (const auto &modname: dump_mod_names) {
            gameLuaInjectorFramework.forceEnabledLuaMod(*this, L, modname);
        }
    }

    struct LuaReaderWrapper {
        lua_Reader reader;
        const char *chunkname;
        GameLuaContextGame *ctx;
        std::list<std::string> buffers;
    };

    static const char *myReader(lua_State *L, void *ud, size_t *sz) {
        LuaReaderWrapper *wrapper = (LuaReaderWrapper *) ud;
        auto buf = wrapper->reader(L, nullptr, sz);
        if (buf && *sz > 0) {
            wrapper->buffers.emplace_back(buf, *sz);
        } else {
            // spilt "../mods/*" -> *
            auto path = std::string_view{wrapper->chunkname};
            path = path.substr(path.find("../mods/") + strlen("../mods/"));
                      
            auto output_path = std::filesystem::path{dump_mod_output_directory} / path;
            std::filesystem::create_directories(output_path.parent_path());
            // complete reading, concatenate all buffers
            std::ofstream dump_file(output_path, std::ios_base::out | std::ios_base::trunc);
            for (const auto &b: wrapper->buffers) {
                dump_file << b;
            }
        }
        return buf;
    }

    bool ShouldDumpMod(const std::string_view &chunkname) {
        for (const auto &modname: dump_mod_names) {
            if (chunkname.find(modname) != std::string_view::npos) {
                return true;
            }
        }
        return false;
    }

    void LoadMyLuaApi() override {
        GameLua51Context::LoadMyLuaApi();
        api._luaL_register = +[](lua_State *L, const char *libname, const luaL_Reg *l) {
            return GetGameLuaContext()->_luaL_openlib(L, libname, l, 0);
        };
        api._lua_setallocf = +[](lua_State *L, lua_Alloc f, void *ud) {
            return lua51_setallocf(L, f, ud);
        };
        api._lua_getallocf = +[](lua_State *L, void **ud) {
            return lua51_getallocf(L, ud);
        };
        api._lua_sethook = +[](lua_State *L, lua_Hook hook, int mask, int count) {
            return lua51_sethook(L, hook, mask, count);
        };
        api._lua_gethookcount = +[](lua_State *L) {
            return lua51_gethookcount(L);
        };
        // api._lua_gethookmask = +[](lua_State *L) {
        //     return lua51_gethookmask(L);
        // };
        api._lua_getlocal = +[](lua_State *L, const lua_Debug *ar, int n) {
            return lua51_getlocal(L, ar, n);
        };
        api._lua_setlocal = +[](lua_State *L, const lua_Debug *ar, int n) {
            return lua51_setlocal(L, ar, n);
        };
        // api._luaL_addstring = +[](luaL_Buffer *B, const char *s) {
        //     return lua51L_addstring(B, s);
        // };
        // api._luaL_loadfile = +[](lua_State *L, const char *filename) {
        //     return lua51L_loadfile(L, filename);
        // };
        // api._luaL_typerror = +[](lua_State *L, int narg, const char *tname) {
        //     return lua51L_typerror(L, narg, tname);
        // };
        // api._lua_cpcall = +[](lua_State *L, lua_CFunction func, void *ud) {
        //     return lua51_cpcall(L, func, ud);
        // };
        // api._lua_isuserdata = +[](lua_State *L, int idx) {
        //     return lua51_isuserdata(L, idx);
        // };
        // api._lua_setlevel = +[](lua_State *L, int level) {
        //     return lua51_setlevel(L, level);
        // };

        // HOOK_LUA_API(luaL_error) + [](lua_State *L, const char *fmt, ...) {
        //     auto &ctx = static_cast<GameLuaContextGame &>(GetGameLuaContext());
        //     va_list argp;
        //     va_start(argp, fmt);
        //     ctx->_luaL_where(L, 1);
        //     ctx->_lua_pushvfstring(L, fmt, argp);
        //     va_end(argp);
        //     ctx->_lua_concat(L, 2);
        //     spdlog::error("Lua Error: {}", ctx->_lua_tostring(L, -1));
        //     return ctx->_lua_error(L);
        // };
        // HOOK_LUA_API(lua_load) + [](lua_State *L, lua_Reader reader, void *data,
        //                             const char *chunkname) {
        //     auto ctx = static_cast<GameLuaContextGame *>(&GetGameLuaContext());
        //     return ctx->api._lua_load(L, reader, data, chunkname);
        // };
        if (dump_mod_names.empty()) return;
        HOOK_LUA_API(lua_load) + [](lua_State *L, lua_Reader reader, void *data,
                                    const char *chunkname) {
            auto ctx = static_cast<GameLuaContextGame *>(&GetGameLuaContext());
            if (data == nullptr && ctx->ShouldDumpMod(chunkname)) {
                thread_local LuaReaderWrapper wrapper;
                data = &wrapper;
                wrapper.reader = reader;
                wrapper.chunkname = chunkname;
                wrapper.buffers.clear();
                wrapper.ctx = ctx;
                reader = &myReader;
            }
            return ctx->api._lua_load(L, reader, data, chunkname);
        };
    }

    void **ll_register(lua_State *L, const char *path) {
        void **plib;
#define LIBPREFIX "LOADLIB: "
        api._lua_pushfstring(L, "%s%s", LIBPREFIX, path);
        api._lua_gettable(L, LUA_REGISTRYINDEX); /* check library in registry? */
        if (!api._lua_isnil(L, -1))              /* is there an entry? */
            plib = (void **) api._lua_touserdata(L, -1);
        else { /* no entry yet; create one */
            api._lua_pop(L, 1);
            plib = (void **) api._lua_newuserdata(L, sizeof(const void *));
            *plib = NULL;
            api._luaL_getmetatable(L, "_LOADLIB");
            api._lua_setmetatable(L, -2);
            api._lua_pushfstring(L, "%s%s", LIBPREFIX, path);
            api._lua_pushvalue(L, -2);
            api._lua_settable(L, LUA_REGISTRYINDEX);
        }
        return plib;
    }

    bool ReplaceApis(const Signatures &signatures, const ListExports_t &exports) override {
        for (auto &[name, newaddr]: overrideapis) {
            auto **api = name2apis.at(name);
            if (!api) {
                spdlog::error("Cannot find api pointer for {}", name);
                return false;
            }
            void *original = nullptr;
            if (gum_interceptor_replace(interceptor, *api, newaddr, nullptr, (void **) &original) == GumReplaceReturn::GUM_REPLACE_OK) {
                *api = original;
                spdlog::info("Replaced game lua api {}: {} to {}", name, (void *) original, (void *) newaddr);
            }
        }
        // for debug luaG_errormsg
        function_relocation::MemorySignature luaG_errormsg_signature{
                "48 89 74 24 30 48 8B 71 40", -0x19};
        if (luaG_errormsg_signature.scan(nullptr)) {
            // static void (*_luaG_errormsg)(lua_State *L);
            // gum_interceptor_replace(interceptor, (void *) luaG_errormsg_signature.target_address, (void *) +[](lua_State *L) {
            //                             auto &ctx = GetGameLuaContext();
            //                             auto stack = gum_interceptor_get_current_stack();
            //                             ctx->_luaL_traceback(L, L, nullptr, 0);
            //                             auto trace = ctx->_lua_tostring(L, -1);
            //                             ctx->_lua_pop(L, 1);
            //                             auto msg = ctx->_lua_tostring(L, -1);
            //                             _luaG_errormsg(L); }, nullptr, (void **) &_luaG_errormsg);
        }
        return true;
    }
    void HotfixApis(const std::string &mainPath) override {}

    static GumAddress GameFindExportByName(GumModule *self, const gchar *symbol_name);
    std::unordered_map<std::string, GumAddress> exports;
    GumInterceptor *interceptor = nullptr;
    std::list<std::string> dump_mod_names;
    constexpr static auto dump_mod_output_directory = "dumped_lua_mods/";
};

constexpr const char *defualtLua51LibraryName = SHARED_LIBRARY_PRE "lua51Original" SHARED_LIBRARY_EXT;
constexpr const char *defualtLuajitLibraryName = SHARED_LIBRARY_PRE "lua51DS" SHARED_LIBRARY_EXT;

#if DONTSTARVEINJECTOR_INITIALIZE_ALL_SO
static __attribute__((constructor)) void initialize_all_so() {
    loadlib(defualtLua51LibraryName);
    loadlib(defualtLuajitLibraryName);
}
#endif

static GameLua51Context gameLua51Ctx{
        defualtLua51LibraryName,
        GameLuaType::_51};

static GameLuaContextJit gameLuajitCtx{
        defualtLuajitLibraryName,
        GameLuaType::jit};

static GameLuaContextGame gameLuaGameCtx{
        GameLuaType::game};

void GameLuaContextJit::LoadMyLuaApi() {
    GameLuaContextImpl::LoadMyLuaApi();
    HOOK_LUA_API(lua_setfield) + [](lua_State *L, int idx, const char *k) {
        auto &api = gameLuajitCtx.api;
        if (api._lua_gettop(L) == 0)
            api._lua_pushnil(L);
        GetGameLuaContext()->_lua_setfield(L, idx, k);
    };
    api._lua_newstate = (decltype(&lua_newstate)) +[](lua_Alloc f, void *ud) {
        return gameLuajitCtx.lua_newstate_hooker(ud);
    };
}

GumAddress GameLuaContextGame::GameFindExportByName(GumModule *self, const gchar *symbol_name) {
    GameLuaContextGame &ctx = static_cast<GameLuaContextGame &>(GetGameLuaContext());
    if (ctx.luaType != GameLuaType::game) {
        spdlog::error("GameFindExportByName: invalid lua type");
        return 0;
    }
    if (ctx.exports.empty()) {
        spdlog::error("GameFindExportByName: exports is null");
        return 0;
    }
    auto iter = ctx.exports.find({symbol_name});
    if (iter != ctx.exports.end()) {
        return iter->second;
    }
    spdlog::error("GameFindExportByName: export {} not found", symbol_name);
    return 0;
}

GameLuaContext &GetGameLuaContext() {
    return *GameLuaContextImpl::currentCtx;
}

GameLuaType currentLuaType = GameLuaType::jit;
static
void set_vm_type(GameLuaType type, const char *moduleName) {
    currentLuaType = type;
    if (type == GameLuaType::_51) {
        GameLuaContextImpl::currentCtx = &gameLua51Ctx;
    } else if (type == GameLuaType::jit) {
        GameLuaContextImpl::currentCtx = &gameLuajitCtx;
    } else if (type == GameLuaType::game) {
        GameLuaContextImpl::currentCtx = &gameLuaGameCtx;
    }
    if (moduleName && std::filesystem::exists(moduleName)) {
        GameLuaContextImpl::currentCtx->sharedlibraryName = moduleName;
    }
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_set_vm_type(int type, const char *moduleName) {
    set_vm_type(GameLuaTypeFromString(GameLuaTypeToString((GameLuaType)type)), moduleName);
}


static std::string wrapper_game_main_buffer(lua_State *L, std::string_view buffer) {
    // before replace buffer frist line
    size_t first_newline = buffer.find('\n');
    if (first_newline != std::string_view::npos) {
        buffer = buffer.substr(first_newline + 1);
    }
    /*
    find ModManager:LoadMods() next line
   */
    constexpr std::string_view modManagerLoadMods = "ModManager:LoadMods()";
    auto pos = buffer.find(modManagerLoadMods);
    if (pos == std::string_view::npos) {
        spdlog::warn("ModManager:LoadMods() not found in main.lua, never injector script");
        return std::string(buffer);
    }

    // - lua code
    std::string before_code = "DBG=1;";
    std::string before_injector_code;
    auto ictx = InjectorCtx::instance();
    bool default_before_code = !ictx->config.GameInjectorNoDefaultBeforeCode;

    // -injector
    std::string_view injector_file;
    std::vector<std::string_view> injector_args;
    std::vector<std::pair<std::string_view, std::string_view>> relocation_files;

    auto injector_file_env = getenv("GAME_INJECTOR_FILE");
    auto injector_args_env = getenv("GAME_INJECTOR_ARGS");

    if (injector_file_env) {
        injector_file = injector_file_env;
    }
    if (injector_args_env) {
        split_string(injector_args_env, injector_args, ' ');
    }
    // skip first cmd, it is executable path
    auto cmds = get_cmds();
    for (size_t i = 1; i < cmds.size(); i++) {
        auto cmd = std::string_view{cmds[i]};
        if (cmd.starts_with('-') || cmd.starts_with("--")) {
            std::string_view key;
            std::string_view value;
            if (cmd.contains('=')) {
                // single cmd with key=value
                auto pos = cmd.find('=');
                key = cmd.substr(0, pos);
                value = cmd.substr(pos + 1);
            } else {
                key = cmd.substr(cmd.find_first_not_of("-"));
                if (i + 1 >= cmds.size() || cmds[i + 1].starts_with('-')) {
                    spdlog::error("No value provided for option: {}", key);
                    continue;
                }
                i++;
                value = cmds[i];
                if (value.empty()) {
                    spdlog::error("No value provided for option: {}", key);
                    continue;
                }
            }
            switch (key.front()) {
                case 'e':
                    if (key == "e"sv)
                        (default_before_code ? before_code : before_injector_code) += std::format("{};", value);
                    break;
                case 'E':
                    if (key == "E"sv)
                        before_injector_code += std::format("{};", value);
                case 'R':
                case 'r':
                    if (key == "r"sv || key == "R"sv || key == "relocation"sv || key == "Relocation"sv) {
                        std::vector<std::string_view> value_parts;
                        split_string(value, value_parts, '=');
                        if (value_parts.size() == 2) {
                            relocation_files.emplace_back(value_parts[0], value_parts[1]);
                        } else {
                            spdlog::warn("Invalid relocation format: {}\ntargetfile=newfile", value);
                        }
                    }
                default:
                    spdlog::warn("Unknown injector command line option: {}", key);
                    break;
            }
        } else if (std::filesystem::exists(std::filesystem::path{cmd})) {
            // last cmd is file args
            injector_file = cmd;
            for (size_t j = i + 1; j < cmds.size(); j++) {
                injector_args.push_back(cmds[j]);
            }
            break;
        }
    }
    /*
        local GameLuaInjector = _G.GameLuaInjector
        GameLuaInjector.register_event_before_main(<before_code>)
        GameLuaInjector.register_event_game_initialized(<before_injector_code>)
        GameLuaInjector.register_event_game_initialized_injector_file(<injector_file>, <injector_args>)
    */
    auto &ctx = *GameLuaContextImpl::currentCtx;
    ctx->_lua_getglobal(L, GameLuaInjectorName);
    if (!ctx->_lua_istable(L, -1)) {
        spdlog::error(GameLuaInjectorName " is not a table, cannot inject scripts");
        ctx->_lua_pop(L, 1);
        return {};
    }

    if (!before_code.empty()) {
        spdlog::info("Inject main before code: {}", before_code);

        ctx->_lua_getfield(L, -1, "register_event_before_main");
        if (!ctx->_lua_isfunction(L, -1)) {
            spdlog::error("register_event_before_main is not a function");
            ctx->_lua_pop(L, 2);
            return {};
        }

        ctx->_lua_pushstring(L, before_code.c_str());

        if (ctx->_lua_pcall(L, 1, 0, 0) != LUA_OK) {
            spdlog::error("Error calling register_event_before_main: {}", ctx->_lua_tostring(L, -1));
        }
    }


    if (!before_injector_code.empty()) {
        spdlog::info("Inject game initialized code: {}", before_injector_code);

        ctx->_lua_getfield(L, -1, "register_event_game_initialized");
        if (!ctx->_lua_isfunction(L, -1)) {
            spdlog::error("register_event_game_initialized is not a function");
            ctx->_lua_pop(L, 2);
            return {};
        }

        ctx->_lua_pushstring(L, before_injector_code.c_str());

        if (ctx->_lua_pcall(L, 1, 0, 0) != LUA_OK) {
            spdlog::error("Error calling register_event_game_initialized: {}", ctx->_lua_tostring(L, -1));
            ctx->_lua_pop(L, 1);
        }
    }

    if (!injector_file.empty()) {
        spdlog::info("Injector file: {}", injector_file);
        ctx->_lua_getfield(L, -1, "register_event_game_initialized_injector_file");
        if (!ctx->_lua_isfunction(L, -1)) {
            spdlog::error("register_event_game_initialized_injector_file is not a function");
            ctx->_lua_pop(L, 2);
            return {};
        }

        ctx->_lua_pushlstring(L, injector_file.data(), injector_file.size());
        ctx->_lua_createtable(L, injector_args.size(), 0);
        for (const auto &arg: injector_args) {
            ctx->_lua_pushlstring(L, arg.data(), arg.size());
            ctx->_lua_rawseti(L, -2, ctx->_lua_objlen(L, -2) + 1);
        }

        if (ctx->_lua_pcall(L, 2, 0, 0) != LUA_OK) {
            spdlog::error("Error calling register_event_game_initialized_injector_file: {}", ctx->_lua_tostring(L, -1));
            ctx->_lua_pop(L, 1);
        }
    }

    if (relocation_files.size() > 0) {
        for (const auto &[old_file, new_file]: relocation_files) {
            spdlog::info("Relocating {} to {}", old_file, new_file);
            ctx->_lua_getfield(L, -1, "relocation_file");
            if (!ctx->_lua_isfunction(L, -1)) {
                spdlog::error("relocation_file is not a function");
                ctx->_lua_pop(L, 2);
                return {};
            }
            ctx->_lua_pushlstring(L, old_file.data(), old_file.size());
            ctx->_lua_pushlstring(L, new_file.data(), new_file.size());
            if (ctx->_lua_pcall(L, 2, 0, 0) != LUA_OK) {
                spdlog::error("Error calling relocation_file: {}", ctx->_lua_tostring(L, -1));
                ctx->_lua_pop(L, 1);
            }
        }
    }

    ctx->_lua_pop(L, 1);

    auto buffer_prefix = buffer.substr(0, pos);
    auto buffer_after = buffer.substr(pos);
    // 在buffer_prefix反向中寻找一个空行, 必须检查该行是空行
    auto last_newline = buffer_prefix.find_last_of('\n');
    if (last_newline != std::string_view::npos) {
        // 确保找到的行是空行
        auto line_start = buffer_prefix.substr(0, last_newline).find_last_of('\n');
        if (line_start == std::string_view::npos) {
            line_start = 0;
        } else {
            line_start += 1;// 跳过换行符
        }
        auto line_content = buffer_prefix.substr(line_start, last_newline - line_start);
        if (std::ranges::all_of(line_content, [](char c) { return std::isspace(c); })) {
            buffer_prefix = buffer_prefix.substr(0, line_start);
        }
    }

    ctx->_luaL_dostring(L, GameLuaInjectorName ".push_event('before_main')");

    auto new_buffer = std::format("{};" GameLuaInjectorName ".push_event('game_initialized');{}", buffer_prefix, buffer_after);
    if (ictx->config.enable_lua_debugger) {
        // replace buffer
        if (!ictx->config.disable_lua_debugger_code_patch) {
            auto target = "DEBUGGER_ENABLED = TheSim:ShouldInitDebugger() and IsNotConsole() and CONFIGURATION ~= \"PRODUCTION\" and not TheNet:IsDedicated()"sv;
            auto npos = new_buffer.find(target);
            if (npos != std::string_view::npos) {
                spdlog::info("Enable lua debugger in main.lua");
                const char *debugger_preload_code = "DEBUGGER_ENABLED =" GameLuaInjectorName ".check_enable_debugger()";
                new_buffer = new_buffer.substr(0, npos) + debugger_preload_code + new_buffer.substr(npos + target.size());
            }
        }
    }
    //spdlog::info("New buffer:\n {}", new_buffer);
    return new_buffer;
}

void ReplaceLuaModule(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports) {
    auto ictx = InjectorCtx::instance();

    // init game lua
    for (auto &[name, address]: exports) {
        auto offset = signatures.funcs.at(name).offset;
        auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
        spdlog::info("Game export {}: {}", name, (void *) target);
        gameLuaGameCtx.exports[name] = (GumAddress) target;
    }
#ifdef WIN32
    auto hProcess = GetCurrentProcess();
    // 步骤1: 初始化符号处理器
    BOOL initSuccess = SymInitialize(hProcess, NULL, TRUE);// FALSE 表示不自动加载所有模块符号
    if (initSuccess) {
        ULONG64 moduleBase = (ULONG64) GetModuleHandleA(NULL);// 示例虚拟基址，确保在进程地址空间内
        for (auto &[name, addr]: gameLuaGameCtx.exports) {
            // 步骤3: 添加符号
            const char *symbolName = name.c_str();// 符号名
            DWORD64 symbolAddress = addr;         // 符号地址（必须在模块范围内）
            DWORD symbolSize = 0;                 // 符号大小（字节，可选）
            DWORD flags = 0;                      // 未使用

            BOOL addSuccess = SymAddSymbol(hProcess, moduleBase, symbolName, symbolAddress, symbolSize, flags);
            if (!addSuccess) {
                spdlog::error("Failed to add symbol [{}]: {}", name, GetLastError());
            }
        }
        //SymCleanup(hProcess);
    }
#endif
    auto luaType = GameLuaTypeFromString((const char *) ictx->config.lua_vm_type);
    auto currentCtx = GameLuaContextImpl::currentCtx;
    if (currentCtx == nullptr) {
        spdlog::error("GameLuaContext is not initialized, cannot replace Lua module");
        return;
    }
    if (!currentCtx->LoadLuaModule())
        return;
    currentCtx->LoadAllInterfaces();
    currentCtx->LoadMyLuaApi();
    currentCtx->ReplaceApis(signatures, exports);
    currentCtx->HotfixApis(mainPath);
}

/*
----------------------------------------------EXPORT_GAME_LUA_API
*/

#ifdef _WIN32
#define EXPORT_GAME_LUA_API(name) extern "C"
#else
#ifdef __linux__
#define EXPORT_GAME_LUA_API_NAME_CONCAT(a) #a
#define EXPORT_GAME_LUA_API_NAME(name) EXPORT_GAME_LUA_API_NAME_CONCAT(GameDbg_##name)
#define EXPORT_GAME_LUA_API(name) \
    decltype(name) name __attribute__((alias(EXPORT_GAME_LUA_API_NAME(name)))); \
    DONTSTARVEINJECTOR_API
#else
#define EXPORT_GAME_LUA_API(name) DONTSTARVEINJECTOR_API 
#endif
#endif
EXPORT_GAME_LUA_API(lua_getinfo)
int GameDbg_lua_getinfo(lua_State *L, const char *what, lua_Debug *ar) {
    int ret = GetGameLuaContext()->_lua_getinfo(L, what, ar);
    if (ret && std::string_view{what}.contains('S')) {
        std::string_view source{ar->source ? ar->source : ""};
        if (source[0] != '=') {
            // transform source path
            
            if (source.starts_with("../mods/") || source.starts_with("scripts/") || std::filesystem::exists(source)) {
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