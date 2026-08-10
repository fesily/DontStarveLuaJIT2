// game/GameLuaContextGame.cpp — in-process game Lua context + instance
#include "game/GameLuaContextLua51.hpp"
#include "game/GameLuaInternal.hpp"
#include "util/lua51_object.hpp"
#include "lua_debugger_helper.hpp"
#include "config/InjectorHostConfig.hpp"
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <list>
#include <vector>
#include <string>
#include <spdlog/spdlog.h>
#ifdef _WIN32
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

struct GameLuaContextGame : GameLua51Context {
    GameLuaContextGame(GameLuaType type)
        : GameLua51Context{"<Game>", type} {
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
            if (gum_interceptor_replace(interceptor, *api, newaddr, (void **) &original, nullptr) == GumReplaceReturn::GUM_REPLACE_OK) {
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

    void ResetApis(const Signatures &signatures, const ListExports_t &exports) override {
        GameLua51Context::ResetApis(signatures, exports);
        if (!interceptor) {
            interceptor = InjectorCtx::instance()->GetGumInterceptor();
        }
        if (!interceptor) {
            spdlog::warn("Game lua interceptor is not initialized, skip reverting game lua hooks");
            return;
        }
        for (auto &[name, api]: name2apis) {
            if (!api || !*api) {
                continue;
            }
            gum_interceptor_revert(interceptor, *api);
            spdlog::info("Reverted game lua api {}: {}", name, (void *) *api);
        }
    }

    void HotfixApis(const std::string &mainPath) override {}

    static GumAddress GameFindExportByName(GumModule *self, const gchar *symbol_name);
    std::unordered_map<std::string, GumAddress> exports;
    GumInterceptor *interceptor = nullptr;
    std::list<std::string> dump_mod_names;
    constexpr static auto dump_mod_output_directory = "dumped_lua_mods/";
};


static GameLuaContextGame gameLuaGameCtx{
        GameLuaType::game};

namespace ds::core_vm::detail {
GameLuaContextImpl *ctx_game() { return &gameLuaGameCtx; }
void NoteGameLuaExport(const std::string &name, GumAddress addr) {
    gameLuaGameCtx.exports[name] = addr;
}
void NoteGameLuaExportsForDebugSymbols() {
#if defined(WIN32) && !defined(NDEBUG)
    auto hProcess = GetCurrentProcess();
    BOOL initSuccess = SymInitialize(hProcess, NULL, TRUE);
    if (initSuccess) {
        ULONG64 moduleBase = (ULONG64) GetModuleHandleA(NULL);
        for (auto &[name, addr]: gameLuaGameCtx.exports) {
            const char *symbolName = name.c_str();
            DWORD64 symbolAddress = addr;
            DWORD symbolSize = 0;
            DWORD flags = 0;
            BOOL addSuccess = SymAddSymbol(hProcess, moduleBase, symbolName, symbolAddress, symbolSize, flags);
            if (!addSuccess) {
                spdlog::error("Failed to add symbol [{}]: {}", name, GetLastError());
            }
        }
    }
#endif
}
} // namespace ds::core_vm::detail

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
