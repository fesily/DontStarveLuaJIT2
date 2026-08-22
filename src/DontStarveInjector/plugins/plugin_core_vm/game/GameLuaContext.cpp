// game/GameLuaContext.cpp — base context helpers, currentCtx, GetGameLuaContext
#include "game/GameLuaContextImpl.hpp"
#include "game/GameLuaInternal.hpp"
#include "VmConfig.hpp"
#include "LuajitVariantNames.hpp"
#include "config/ResolvedConfig.hpp"
#include "config/ConfigSession.hpp"
#include "util/platform.hpp"
#include "util/lua_io2.hpp"
#include "io/gameio.h"
#include "lua_debugger_helper.hpp"
#include <zlib.h>
#include <fstream>
#include <filesystem>
#include <vector>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <spdlog/spdlog.h>
#include <cassert>
#include <cstdlib>
#include <cstring>

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

LuaStackGuard::LuaStackGuard(GameLuaContext &c, lua_State *l) : ctx(c), L(l) {
    top = ctx.api._lua_gettop(L);
}
LuaStackGuard::LuaStackGuard(GameLuaContext *p, lua_State *l) : LuaStackGuard(*p, l) {
}
LuaStackGuard::~LuaStackGuard() {
    int new_top = ctx.api._lua_gettop(L);
    if (new_top != top) {
        spdlog::error("Lua stack imbalance detected: before={} after={}", top, new_top);
        assert(top == new_top);
        ctx.api._lua_settop(L, top);
    }
}

int split_string(const std::string_view &str, std::vector<std::string_view> &out, char delimiter) {
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
int (*luaopen_game_io)(lua_State *L);

namespace ds::core_vm::detail {

bool UseGameIO() {
    return !InjectorConfig::instance()->DisableGameIO;
}

void load_game_fn_io_open(const Signatures &signatures) {
    auto offset = signatures.funcs.at("luaopen_io").offset;
    auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
    luaopen_game_io = (decltype(luaopen_game_io)) target;
}

void replace_game_io_open(GameLuaContext &ctx, lua_State *L) {
    assert(luaopen_game_io);
    const int top = ctx.api._lua_gettop(L);
    ctx.api._lua_pushcclosure(L, luaopen_game_io, 0);
    ctx.api._lua_pushstring(L, LUA_IOLIBNAME);
    ctx.api._lua_call(L, 1, 0);
    assert(ctx.api._lua_gettop(L) == top);
}

} // namespace ds::core_vm::detail

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

static std::string decompress_embedded_lua_buffer(
    const unsigned char *buffer,
    unsigned int compressed_len,
    unsigned int original_len,
    const char *buffer_name) {
    if (buffer == nullptr || compressed_len == 0 || original_len == 0) {
        spdlog::error("{} buffer is empty", buffer_name);
        return {};
    }

    std::string output;
    output.resize(original_len);
    uLongf decompressed_len = original_len;
    auto ret = uncompress(
        reinterpret_cast<Bytef *>(output.data()),
        &decompressed_len,
        reinterpret_cast<const Bytef *>(buffer),
        compressed_len);
    if (ret != Z_OK) {
        spdlog::error("Failed to decompress {}: zlib error {}", buffer_name, ret);
        return {};
    }

    output.resize(decompressed_len);
    return output;
}

void GameLuaInjectorFramework::init(GameLuaContext &ctx, lua_State *L) {
        LuaStackGuard guard(ctx, L);
#include "../injector/GameLuaInjectFramework.c"
        auto buffer = decompress_embedded_lua_buffer(
            GameLuaInjectFramework,
            GameLuaInjectFramework_len,
            GameLuaInjectFramework_original_len,
            "GameLuaInjectFramework");
        if (buffer.empty()) {
            return;
        }
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
        // args: spdlog table + native_getenv; chunk sets global GameLuaInjector
        if (ctx->_lua_pcall(L, 2, 0, 0) != LUA_OK) {
            const char *err = ctx->_lua_tostring(L, -1);
            spdlog::error("GameLuaInjectFramework pcall failed: {}", err ? err : "?");
            ctx->_lua_pop(L, 1);
            return;
        }
        ctx->_lua_getglobal(L, GameLuaInjectorName);
        const bool ok = ctx->_lua_istable(L, -1) != 0;
        ctx->_lua_pop(L, 1);
        if (!ok) {
            spdlog::error("GameLuaInjector global is not a table after framework init");
            return;
        }
}

void GameLuaInjectorFramework::forceEnabledLuaMod(GameLuaContext &ctx, lua_State *L, const std::string_view &modname) {
        LuaStackGuard guard(ctx, L);
        int ret = ctx->_luaL_dostring(L, fmt::format(GameLuaInjectorName ".forceEnableLuaMod(true, [[{}]])", modname).c_str());
        if (ret != LUA_OK) {
            spdlog::error("{}", ctx->_lua_tostring(L, -1));
        }
        assert(ret == LUA_OK);
        spdlog::info("Forced enabled Lua mod: {}", modname);
}

GameLuaInjectorFramework gameLuaInjectorFramework;

GameLuaContextImpl *GameLuaContextImpl::currentCtx = nullptr;

namespace {
std::string MakeFullLibraryName(const char *baseName) {
    if (!baseName) return {};
    return std::string(SHARED_LIBRARY_PRE) + baseName + SHARED_LIBRARY_EXT;
}
} // namespace

namespace ds::core_vm::detail {

const char *DefaultLua51LibraryName() {
    static const std::string name = MakeFullLibraryName(GetLuajitVariantBaseName(GameLuaType::_51));
    return name.c_str();
}
const char *DefaultLuajitLibraryName() {
    static const std::string name = MakeFullLibraryName(GetLuajitVariantBaseName(GameLuaType::jit));
    return name.c_str();
}
const char *DefaultLuajitGenLibraryName() {
    static const std::string name = MakeFullLibraryName(GetLuajitVariantBaseName(GameLuaType::jit_gen));
    return name.c_str();
}

} // namespace ds::core_vm::detail

#if DONTSTARVEINJECTOR_INITIALIZE_ALL_SO
static __attribute__((constructor)) void initialize_all_so() {
    using ds::core_vm::detail::DefaultLua51LibraryName;
    using ds::core_vm::detail::DefaultLuajitLibraryName;
    using ds::core_vm::detail::DefaultLuajitGenLibraryName;
    loadlib(DefaultLua51LibraryName());
    loadlib(DefaultLuajitLibraryName());
    loadlib(DefaultLuajitGenLibraryName());
}
#endif

GameLuaContext &GetGameLuaContext() {
    if (!GameLuaContextImpl::currentCtx) {
        // default to jit
        auto *jit = ds::core_vm::detail::ctx_jit();
        jit->LoadLuaModule();
        jit->LoadAllInterfaces();
        GameLuaContextImpl::currentCtx = jit;
    }
    return *GameLuaContextImpl::currentCtx;
}

// Stable C export for plugins / L0 that cannot hard-link C++ mangled GetGameLuaContext.
// Windows: exported via GameLua.def; non-Windows: visibility default.
extern "C" {
#if !defined(_WIN32)
__attribute__((visibility("default")))
#endif
GameLuaContext &ds_core_vm_get_game_lua_context() {
    return GetGameLuaContext();
}
}

std::string wrapper_game_main_buffer(lua_State *L, std::string_view buffer) {
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

    // DBG=1 forces game debug APIs (getstack/getlocal via CallInfo). Those walk
    // L->ci/base_ci which do not exist on LuaJIT states and AV at LOADING LUA.
    // Only enable when lua debugger is explicitly requested.
    std::string before_code;
    if (InjectorConfig::instance()->enable_lua_debugger) {
        before_code = "DBG=1;";
    }
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
        const int ty = ctx->_lua_type(L, -1);
        spdlog::error(GameLuaInjectorName " is not a table (lua_type={}), cannot inject scripts", ty);
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
