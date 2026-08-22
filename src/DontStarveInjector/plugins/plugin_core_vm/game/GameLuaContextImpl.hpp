// game/GameLuaContextImpl.hpp — complete GameLuaContextImpl for multi-TU subclasses
#pragma once

#include "game/GameLuaContext.hpp"
#include "game/GameLuaInternal.hpp"
#include "DontStarveSignature.hpp"
#include "GameSignature.hpp"
#include "util/inlinehook.hpp"
#include "util/platform.hpp"
#include "util/lua_io2.hpp"
#include "config/InjectorHostConfig.hpp"
#include "config/ResolvedConfig.hpp"
#include "config/ConfigSession.hpp"
#include "lua_debugger_helper.hpp"
#include "LuaEvent.hpp"
#include "io/gameio.h"

#include <map>
#include <string>
#include <string_view>
#include <vector>
#include <list>
#include <array>
#include <cassert>
#include <cstdio>
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include <frida-gum.h>

using namespace std::literals;
using ds::core_vm::detail::UseGameIO;
using ds::core_vm::detail::replace_game_io_open;
using ds::core_vm::detail::load_game_fn_io_open;
using ds::core_vm::detail::CreateLuaStateForCurrentVm;
using ds::core_vm::detail::MarkLuaStateClosed;

#define GameLuaInjectorName "GameLuaInjector"

struct LuaStackGuard {
    GameLuaContext &ctx;
    lua_State *L;
    int top;
    LuaStackGuard(GameLuaContext &c, lua_State *l);
    LuaStackGuard(GameLuaContext *p, lua_State *l);
    ~LuaStackGuard();
};

int split_string(const std::string_view &str, std::vector<std::string_view> &out, char delimiter);
void do_lua_env(GameLuaContext &ctx, lua_State *L, const std::string_view &env);
std::string wrapper_game_main_buffer(lua_State *L, std::string_view buffer);
extern int (*luaopen_game_io)(lua_State *L);

struct GameLuaInjectorFramework {
    void init(GameLuaContext &ctx, lua_State *L);
    void forceEnabledLuaMod(GameLuaContext &ctx, lua_State *L, const std::string_view &modname);
};
extern GameLuaInjectorFramework gameLuaInjectorFramework;

// Available to subclass TUs (also redefined inside some method bodies historically).
#define HOOK_LUA_API(name) \
    overrideapis[#name] = (void *) (decltype(&#name))
#define LOAD_LUA_API(name)                                                 \
    api._##name = (decltype(&name)) find_export_by_name(LuaModule, #name); \
    name2apis[#name] = (void **) &api._##name;

struct GameLuaContextImpl : GameLuaContext {
    GameLuaContextImpl(const char *sharedLibraryName, GameLuaType type)
        : GameLuaContext{sharedLibraryName, type} {
    }

    void cleanup_lua_io_lib(lua_State *L) {
        // Drop global io table reference.
        api._lua_pushnil(L);
        api._lua_setglobal(L, "io");

        // Drop FILE* metatable so game io can recreate its own.
        api._lua_pushnil(L);
        api._lua_setfield(L, LUA_REGISTRYINDEX, LUA_FILEHANDLE);

        // Critical: clear package.loaded/registry._LOADED["io"].
        // Both Lua 5.1 and LuaJIT reuse _LOADED[libname] on re-open.
        // Without this, reloading io just mutates the old table (or fails).
        api._lua_getfield(L, LUA_REGISTRYINDEX, "_LOADED");
        if (api._lua_istable(L, -1)) {
            api._lua_pushnil(L);
            api._lua_setfield(L, -2, LUA_IOLIBNAME);
        }
        api._lua_pop(L, 1);

        // package.loaded is usually the same table as registry._LOADED,
        // but clear it explicitly for safety.
        api._lua_getglobal(L, "package");
        if (api._lua_istable(L, -1)) {
            api._lua_getfield(L, -1, "loaded");
            if (api._lua_istable(L, -1)) {
                api._lua_pushnil(L);
                api._lua_setfield(L, -2, LUA_IOLIBNAME);
            }
            api._lua_pop(L, 1);
        }
        api._lua_pop(L, 1);

        api._lua_gc(L, LUA_GCCOLLECT, 0);
        assert(!check_lua_io_lib(L));
    }

    bool check_lua_io_lib(lua_State *L) {
        api._lua_getglobal(L, "io");
        const bool ok = api._lua_istable(L, -1);
        api._lua_pop(L, 1);
        return ok;
    }

    virtual void luaL_openlibs_hooker(lua_State *L) {
        api._luaL_openlibs(L);
         if (InjectorCtx::instance()->config.DisableReplaceLuaIO) {
            spdlog::info("DISABLE_REPLACE_LUA_IO is set, skip replacing io module");
        } else if (UseGameIO()) {
            if (luaType != GameLuaType::game && luaopen_game_io) {
                cleanup_lua_io_lib(L);
                replace_game_io_open(*this, L);
                assert(check_lua_io_lib(L));
                spdlog::info("Replaced Lua io library with game io library");
            }
            // open io2 module
            api._lua_pushcfunction(L, luaopen_io2);
            api._lua_pushstring(L, "io2");
            api._lua_call(L, 1, 0);
            spdlog::info("Injector luaopen_io2");
        }

        do_lua_env(*this, L, "GAME_INIT");
        gameLuaInjectorFramework.init(*this, L);

        if (InjectorConfig::instance()->enable_lua_debugger) {
            dontstarveinjector::lua_debugger_helper::initialize_lua_debugger();
        }

        if (!InjectorConfig::instance()->DisableForceLoadLuaJITMod) {
            (void) ds::config::ensure_resolved();
            if (auto *rc = ds::config::current(); rc && rc->always_enable_mod()) {
                do {
                    auto modname = rc->modname();
                    if (modname.empty()) {
                        break;
                    }
                    gameLuaInjectorFramework.forceEnabledLuaMod(*this, L, std::string{modname});
                } while (0);
            }
        }

        // register game injector
        int luaopen_GameInjector(lua_State *L);
        api._lua_pushcfunction(L, luaopen_GameInjector);
        api._lua_pushstring(L, "GameInjector");
        api._lua_call(L, 1, 0);

        InjectorConfig::EnvOrCmdOptValue force_enable_opts{"force_enable_mods"};
        auto force_enable_str = static_cast<const char *>(force_enable_opts);
        if (force_enable_str && strlen(force_enable_str) > 0) {
            std::string_view sv{force_enable_str};
            std::vector<std::string_view> outs;
            split_string(sv, outs, ';');
            for (const auto &modname: outs) {
                gameLuaInjectorFramework.forceEnabledLuaMod(*this, L, modname);
            }
        }
    }

    virtual bool LoadLuaModule() {
        if (LuaModule) {
            return true;
        }
        if (getenv("GAME_LUA_MODULE_NAME")) {
            sharedlibraryName = getenv("GAME_LUA_MODULE_NAME");
        }

        // Windows: gum_module_load("lua51DS.dll") only searches the game bin64
        // default path and fails 0x7E when the VM is under Mod/deps. loadlib()
        // resolves Mod/deps (next to Injector / plugin_core_vm) and maps the DLL;
        // then gum attaches to the already-loaded module.
        auto try_attach = [&](const std::string &name) -> bool {
            if (name.empty()) {
                return false;
            }
            if (loadlib(name.c_str())) {
                LuaModule = gum_process_find_module_by_name(name.c_str());
                if (LuaModule) {
                    sharedlibraryName = name;
                    spdlog::info("Attached Lua module (loadlib): {}", name);
                    std::fprintf(stderr, "[core.vm] Attached Lua module (loadlib): %s\n", name.c_str());
                    return true;
                }
                // Loaded but gum name lookup failed — try basename of what loadlib used.
                std::fprintf(stderr,
                             "[core.vm] loadlib(%s) mapped module but gum_process_find_module_by_name failed\n",
                             name.c_str());
            }
            return false;
        };

        if (!try_attach(sharedlibraryName)) {
#ifdef _WIN32
            if (sharedlibraryName.find('.') == std::string::npos) {
                (void) try_attach(sharedlibraryName + ".dll");
            }
#endif
        }

        if (!LuaModule) {
            GError *error = nullptr;
            LuaModule = gum_module_load(sharedlibraryName.c_str(), &error);
            if (!LuaModule) {
                spdlog::error("Cannot load Lua module: {}, error: {}", sharedlibraryName,
                              error ? error->message : "unknown");
                std::fprintf(stderr, "[core.vm] Cannot load Lua module: %s, error: %s\n",
                             sharedlibraryName.c_str(), error ? error->message : "unknown");
                if (error) {
                    g_error_free(error);
                }
            } else {
                spdlog::info("Loaded Lua module: {}", sharedlibraryName);
                std::fprintf(stderr, "[core.vm] Loaded Lua module: %s\n", sharedlibraryName.c_str());
            }
        }
        if (!LuaModule) {
            spdlog::error("Failed to load Lua module: {}", sharedlibraryName);
            std::fprintf(stderr, "[core.vm] Failed to load Lua module: %s\n", sharedlibraryName.c_str());
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
            if (currentCtx->luaType == GameLuaType::jit_gen) {
                switch (what) {
                    case LUA_GCCOUNT:
                    case LUA_GCCOUNTB:
                        return (*currentCtx)->_lua_gc(L, what, data);
                    default:
                        lua_event_notifyer(LUA_EVENT::call_lua_gc, L);
                        return 0;
                }
            }
            lua_event_notifyer(LUA_EVENT::call_lua_gc, L);
            return (*currentCtx)->_lua_gc(L, what, data);
        };
        HOOK_LUA_API(lua_close) + [](lua_State *L) {
            lua_event_notifyer(LUA_EVENT::close_state, L);
            spdlog::info("lua_close:{}", (void *) L);
            (*currentCtx)->_lua_close(L);
            MarkLuaStateClosed(L, "lua_close");
        };
        HOOK_LUA_API(luaL_openlibs) + [](lua_State *L) {
            LuaStackGuard guard(*currentCtx, L);
            currentCtx->luaL_openlibs_hooker(L);
        };
        HOOK_LUA_API(luaL_loadbuffer) + [](lua_State *L, const char *buff, size_t size, const char *name) {
            auto &ctx = *currentCtx;
            if (name == "@scripts/main.lua"sv) {
                if (ctx->_luaL_dostring(L, GameLuaInjectorName ".init()") != LUA_OK) {
                    const char *err = ctx->_lua_tostring(L, -1);
                    spdlog::error("GameLuaInjector.init failed: {}", err ? err : "?");
                    if (err) {
                        ctx->_lua_pop(L, 1);
                    }
                }
                int top = ctx->_lua_gettop(L);
                auto new_buffer = wrapper_game_main_buffer(L, {buff, size});
                assert(ctx->_lua_gettop(L) == top);
                if (new_buffer.empty()) {
                    return ctx->_luaL_loadbuffer(L, buff, size, name);
                }
                // Keep original chunk name; do not use new_buffer.c_str() as name.
                return ctx->_luaL_loadbuffer(L, new_buffer.c_str(), new_buffer.size(), name);
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
            // Only APIs resolvable in the loaded LuaJIT module. Hook(null) AVs.
            if (GetLuaExport(name) == nullptr) {
                spdlog::warn("skip replace {}: no export in loaded Lua module", name);
                continue;
            }
            hookTargets.emplace_back(&name);
        }

        std::list<uint8_t *> hookeds;
        for (auto *_name: hookTargets) {
            auto &name = *_name;
            auto offset = signatures.funcs.at(name).offset;
            auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
#ifdef _WIN32
            if (name == "lua_getstack"sv &&
                target[0] == 0x0f && target[1] == 0xb6 && target[4] == 0xc3) {
                target += 0x20;
            }
            if (name == "lua_getinfo"sv) {
                bool has_gt = false;
                for (int k = 0; k < 0x40; ++k) {
                    if (target[k] == 0x80 && target[k + 1] == 0x3a && target[k + 2] == 0x3e) {
                        has_gt = true;
                        break;
                    }
                }
                assert(has_gt);
            }
#endif
            auto replacer = (uint8_t *) GetLuaExport(name);
            if (replacer == nullptr) {
                spdlog::error("replace {} aborted: null replacer", name);
                break;
            }
            if (!Hook(target, replacer)) {
                spdlog::error("replace {} failed", name);
                break;
            }
            hookeds.emplace_back(target);
            // Verify trampoline (12-byte mov rax,imm64; jmp rax) actually landed.
            const auto *b = reinterpret_cast<const uint8_t *>(target);
            const bool looks_hooked = (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0);
            if (!looks_hooked) {
                spdlog::error("replace {} wrote but bytes not hooked at {}", name, (void *) target);
            } else {
                spdlog::info("replace {}: {} to {}", name, (void *) target, (void *) replacer);
            }
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

    virtual void ResetApis(const Signatures &signatures, const ListExports_t &exports) {
        for (auto &[name, _]: exports) {
            auto offsetIter = signatures.funcs.find(name);
            if (offsetIter == signatures.funcs.end()) {
                continue;
            }
            auto offset = offsetIter->second.offset;
            auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
            ResetHook(target);
        }
    }

    virtual void HotfixApis(const std::string &mainPath) {
#if DEBUG_GETSIZE_PATCH
        // Game register_debug_getsize reads Lua 5.1 GC layout (base[1].value.gc->cl.c.f)
        // then lua_setfield(..., "getsize"). That is invalid under LuaJIT/arenagc and
        // the old mid-function "mov reg,0" patch left the following load live, so
        // getsize still registered. Disable the whole function at entry (ret).
        if (luaRegisterDebugGetsizeSignature.scan(mainPath.c_str())) {
            const auto ret = std::to_array<uint8_t>({0xC3});
            const auto addr = (uint8_t *) luaRegisterDebugGetsizeSignature.target_address;
            if (HookWriteCode(addr, ret.data(), ret.size())) {
                spdlog::info("Disabled game register_debug_getsize at {}", (void *) addr);
            } else {
                spdlog::error("Failed to disable game register_debug_getsize at {}", (void *) addr);
            }
        } else {
            spdlog::warn("register_debug_getsize signature not found; getsize may still register");
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
