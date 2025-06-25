#include "GameLua.hpp"
#include "config.hpp"
#include "DontStarveSignature.hpp"
#include "GameSignature.hpp"
#include "util/inlinehook.hpp"
#include "util/platform.hpp"
#include "gameio.h"
#include <string_view>
#include <map>
#include <spdlog/spdlog.h>
#include <functional>
#include <list>
#include <cctype>
#include <ranges>
using namespace std::literals;


#ifdef _WIN32
#define SHARED_LIBRARY_EXT ".dll"
#define SHARED_LIBRARY_PRE ""
#elif defined(__linux__)
#include <dlfcn.h>
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
void load_game_fn_io_open(const Signatures &signatures) {
    auto offset = signatures.funcs.at("luaopen_io").offset;
    auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
    luaopen_game_io = decltype(luaopen_game_io)(target);
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
        (ctx.api._luaL_loadfile(L, init + 1) || ctx.api._lua_pcall(L, 0, 0, 0));
    else
        (ctx.api._luaL_loadstring(L, init) || ctx.api._lua_pcall(L, 0, 0, 0));
}

void GameLuaContext::luaL_openlibs_hooker(lua_State *L) {
    api._luaL_openlibs(L);
    do_lua_env(*this, L, "GAME_INIT");
}

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

std::string wapper_game_main_buffer(std::string_view buffer) {
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
    pos = buffer.find('\n', pos + modManagerLoadMods.size());
    if (pos != std::string_view::npos) {
        pos += 1; // move to next line
    }

    std::string before_buffer;
    // handler arg "-e"
    auto cmds = get_cmds();
    for (size_t i = 0; i < cmds.size(); i++) {
        const auto &cmd = cmds[i];
        if (cmd == "-e"sv) {
            auto next = std::next(cmds.begin(), i + 1);
            if (next != cmds.end()) {
                auto &script = *next;
                if (script.empty()) {
                    spdlog::error("No Lua script provided after -e option");
                    continue;
                }
                //spdlog::info("Running Lua script from command line: {}", script);
                before_buffer += script + ";";
            }
        }
    }
    spdlog::info("Injecting -e script: {}", before_buffer);

    // handler -injector
    std::string_view injector_file;
    std::vector<std::string_view> injector_args;

    auto injector_file_env = getenv("GAME_INJECTOR_FILE");
    auto injector_args_env = getenv("GAME_INJECTOR_ARGS");

    if (injector_file_env) {
        injector_file = injector_file_env;
    }
    if (injector_args_env) {
        split_string(injector_args_env, injector_args, ' ');
    }
    for (size_t i = 0; i < cmds.size(); i++) {
        auto &cmd = cmds[i];
        if (cmd == "-injector-file"sv) {
            if (i + 1 < cmds.size()) {
                injector_file = cmds[i + 1];
            } else {
                spdlog::error("No injector file provided after -injector option");
                return std::string(buffer);
            }
        } else if (cmd == "-injector-args"sv) {
            if (i + 1 < cmds.size()) {
                split_string(cmds[i + 1], injector_args, ' ');
            } else {
                spdlog::error("No injector args provided after -injector-args option");
                return std::string(buffer);
            }
        }
    }

    if (injector_file.empty()) {
        spdlog::warn("No injector file provided, never injector script");
        return std::string(buffer);
    }
    std::string inject_buffer = std::format("print('DontStarveInjector: Load Injector File: {}');", injector_file);
    if (!injector_args.empty()) {
        std::string args_str;
        for (const auto &arg: injector_args) {
            args_str += std::string{arg} + " ";
        }
        args_str.pop_back();// remove last space
        /* lua code
        */
        inject_buffer += "global('inject_args'); inject_args={"sv;
        for (size_t i = 0; i < injector_args.size(); i++) {
            inject_buffer += std::format("[[{}]],", i + 1, injector_args[i]);
        }
        inject_buffer += "};";
    }
    inject_buffer += std::format(" local fn = dofile([[{}]]);"
                                 " if fn then"
                                 "       fn();"
                                 "   end;"
                                 "   error('DontStarveInjector: Load Injector File Done');"
                                 "TheSim:Quit();",
                                 injector_file);
    spdlog::info("Injecting script: {}", inject_buffer);

    auto buffer_prefix = buffer.substr(0, pos);
    auto buffer_after = buffer.substr(pos);
    auto new_line_end = buffer.find('\n', pos);
    if (new_line_end == std::string_view::npos) {
        new_line_end = pos;
        spdlog::warn("No newline found after ModManager:LoadMods(), injecting at end of buffer");
    } else {
        if (std::ranges::all_of(buffer.substr(pos, new_line_end - pos), [](char c) { return std::isspace(c); })) {
            buffer_after = buffer.substr(new_line_end + 1);
        }
    }
    
    return std::format("{}\n{} ;{}\n{}", before_buffer, buffer_prefix, inject_buffer, buffer_after);
}

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
#ifndef _WIN32
            loadlib(sharedlibraryName.c_str(), RTLD_GLOBAL);
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
        if (target == "luaL_openlibs") {
            decltype(&luaL_openlibs) hooker = +[](lua_State *L) {
                return GetGameLuaContext().luaL_openlibs_hooker(L);
            };
            return (void *) hooker;
        }
        if (target == "luaL_loadbuffer") {
            decltype(&luaL_loadbuffer) hooker = +[](lua_State *L, const char *buff, size_t size, const char *name) {
                if (name == "@scripts/main.lua"sv) {
                    // load custom main.lua script
                    auto new_buffer = wapper_game_main_buffer({buff, size});
                    return GetGameLuaContext().api._luaL_loadbuffer(L, new_buffer.data(), new_buffer.size(), name);
                }
                return GetGameLuaContext().api._luaL_loadbuffer(L, buff, size, name);
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

    void *lua_newstate_hooker(void *ud) {
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
        return gameLuajitCtx.lua_newstate_hooker(ud);
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

    if (UseGameIO())
        load_game_fn_io_open(signatures);

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
