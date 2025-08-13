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
#include <fmt/format.h>
#include <fmt/ranges.h>
using namespace std::literals;

#ifndef _WIN32
#include <dlfcn.h>
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


#pragma region GAME_IO
bool UseGameIO() {
    return !InjectorConfig::instance().DisableGameIO;
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

    // - lua code
    std::string before_code = "DBG=1;";
    std::string before_injector_code;
    bool default_before_code = !InjectorConfig::instance().GameInjectorNoDefaultBeforeCode;

    // -injector
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

    if (injector_file.empty()) {
        spdlog::warn("No injector file provided, never injector script");
        return std::string(buffer);
    }

    spdlog::info("Injecting -e script: {} {}", before_code, before_injector_code);
    if (!before_injector_code.empty()) before_injector_code += '\t';
    spdlog::info("Injector: {} {}", injector_file, fmt::join(injector_args, " "));
    auto v1 = fmt::format("{}", fmt::join(injector_args | std::ranges::views::transform([](auto &arg) { return std::format("[[{}]]", arg); }), ","));
    std::string inject_buffer = before_injector_code + std::format(
                                                               " local inject_fp=io.open([[{}]], 'r');"
                                                               " if not inject_fp then error ('DontStarveInjector: Cannot open Injector File'); end;"
                                                               " local fn = loadstring(inject_fp:read '*a');"
                                                               " inject_fp:close();"
                                                               " if fn then"
                                                               "   local inject_args = {{{}}};"
                                                               "   setfenv(fn, setmetatable({{arg=inject_args}}, {{__index = _G, __newindex = _G}}));"
                                                               "       pcall(fn);"
                                                               "   end;",
                                                               injector_file, v1);
    spdlog::info("Injecting script: {}", inject_buffer);

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

    auto new_buffer = std::format("{}\n{} ;{}\n{}", before_code, buffer_prefix, inject_buffer, buffer_after);
    spdlog::info("New buffer:\n {}", new_buffer);
    return new_buffer;
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

DONTSTARVEINJECTOR_API void DS_LUAJIT_set_vm_type(GameLuaType type, const char *moduleName) {
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
        if (InjectorConfig::instance().DisableReplaceLuaIO) {
            spdlog::info("DISABLE_REPLACE_LUA_IO is set, skip replacing io module");
        } else {
            if (UseGameIO()) {
                load_game_fn_io_open(signatures);
                //void luaL_defaultlib_update(luaL_Reg* newlib);
                auto luaL_defaultlib_update = ((void (*)(luaL_Reg *)) gum_module_find_export_by_name(currentCtx->LuaModule, "luaL_defaultlib_update"));
                luaL_Reg game_io_lib = {
                        LUA_IOLIBNAME,
                        luaopen_game_io};
                luaL_defaultlib_update(&game_io_lib);

                auto luaopen_io2 = ((int (*)(lua_State *)) gum_module_find_export_by_name(currentCtx->LuaModule, "luaopen_io2"));
                if (luaopen_io2) {
                    luaL_Reg io2_lib = {
                            "io2",
                            luaopen_io2};
                    luaL_defaultlib_update(&io2_lib);
                    spdlog::info("Injector luaopen_io2");
                }
                spdlog::info("Replaced luaopen_io with game io open function");
            }
            init_luajit_io(currentCtx->LuaModule);
        }
    }
}
