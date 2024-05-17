// DontStarveInjector.cpp : Defines the exported functions for the DLL application.
//
#include <spdlog/spdlog.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_NONSTDC_NO_WARNINGS
#include <windows.h>
#include <spdlog/sinks/msvc_sink.h>
#else

#endif

#include <string>
#include <algorithm>
#include <map>
#include <cstdint>
#include <list>

#include <lua.hpp>

#if USE_LISTENER
#include <frida-gum.h>
#endif

#include "config.hpp"
#include "util/inlinehook.hpp"
#include "LuaModule.hpp"
#include "DontStarveSignature.hpp"
#include "util/platform.hpp"
#include "ctx.hpp"
#include "spdlog/sinks/basic_file_sink.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

G_NORETURN void showError(const std::string_view &msg) {
#ifdef _WIN32
    MessageBoxA(NULL, msg.data(), "error!", 0);
#else
    spdlog::error("error: {}", msg);
#endif
    std::exit(1);
}

static const char *luajitModuleName =
#if ONLY_LUA51
        "Lua51";
#else
        "Lua51DS";
#endif
static module_handler_t hluajitModule;

#include "api_listener.hpp"

#if USE_FAKE_API
extern std::unordered_map<std::string_view, void *> lua_fake_apis;

#include <lua.hpp>
void *GetLuaJitAddress(const char *name)
{
    char buf[64];
    snprintf(buf, 64, "fake_%s", name);
        return lua_fake_apis[name];
}
#else
#define GetLuaJitAddress(name) loadlibproc(hluajitModule, name)
#endif
#pragma region Attach

#if USE_LISTENER
static GumInterceptor *interceptor;
#endif

#if !ONLY_LUA51

static void *lua_newstate_hooker(void *, void *ud) {
    auto L = luaL_newstate();
    spdlog::info("luaL_newstate:{}", (void *) L);
    return L;
}

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
                            gpointer user_data)
{
    gum_interceptor_attach(interceptor, (void *)details->address, listener, (void *)details->name);
    return true;
}
#endif

static void *get_luajit_address(const std::string_view &name) {
    void *replacer = GetLuaJitAddress(name.data());
    assert(replacer != nullptr);
#if !ONLY_LUA51
    if (name == "lua_newstate"sv) {
        // TODO 2.1 delete this
        replacer = (void *) &lua_newstate_hooker;
    } else if (name == "lua_setfield"sv) {
        replacer = (void *) &lua_setfield_fake;
    }
#endif
    return replacer;
}

static void voidFunc() {
}

static std::map<std::string, std::string> replace_hook = {
        {"lua_getinfo", "lua_getinfo_game"}};

static void ReplaceLuaModule(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports) {
    hluajitModule = loadlib(luajitModuleName);

    std::list<uint8_t *> hookeds;
    for (auto &[name, _]: exports) {
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

    if (hookeds.size() != exports.size()) {
        for (auto target: hookeds) {
            ResetHook(target);
        }
        spdlog::info("reset all hook");
        return;
    }

#if DEBUG_GETSIZE_PATCH
    if (luaRegisterDebugGetsizeSignature.scan(mainPath.c_str())) {
#if DEBUG_GETSIZE_PATCH == 1
        auto code = std::to_array<uint8_t>({0x48, 0xc7, 0xc2, 0, 0, 0, 0, 0x90});
        HookWriteCode((uint8_t *) luaRegisterDebugGetsizeSignature.target_address, code.data(), code.size());
#else
        Hook((uint8_t *)luaRegisterDebugGetsizeSignature.target_address, (uint8_t *)&voidFunc);
#endif
    }
#endif

#if REPLACE_IO
    extern void init_luajit_io(module_handler_t hluajitModule);
    init_luajit_io(hluajitModule);
#endif

#if USE_LISTENER
    listener = (GumInvocationListener *)g_object_new(EXAMPLE_TYPE_LISTENER, NULL);
    gum_module_enumerate_exports(target_module_name, PrintCallCb, NULL);
#endif
}

#pragma endregion Attach
#ifdef _WIN32
#define DONTSTARVEINJECTOR_API __declspec(dllexport)
#else
#define DONTSTARVEINJECTOR_API
#endif
template<typename Fn>
auto create_defer(Fn&& fn) {
    auto deleter = [cb = std::forward<Fn>(fn)](void *) {
        cb();
    };
    return std::unique_ptr<void, decltype(deleter)>(nullptr, std::move(deleter));
}
extern "C" DONTSTARVEINJECTOR_API void Inject(bool isClient) {
    gum_init();
#ifdef _WIN32
    spdlog::set_default_logger(std::make_shared<spdlog::logger>("", std::make_shared<spdlog::sinks::msvc_sink_st>()));
#endif
    const auto log_path = "DontStarveInjector.log";
    std::filesystem::remove(log_path);
    spdlog::default_logger()->sinks().push_back(std::make_shared<spdlog::sinks::basic_file_sink_st>(log_path));
#if USE_LISTENER
    interceptor = gum_interceptor_obtain();
#endif
    
    if (!function_relocation::init_ctx()) {
        showError("can't init signature");
        return;
    }
    auto defer = create_defer(&function_relocation::deinit_ctx);

    auto lua51 = loadlib(lua51_name);
    if (!lua51) {
        showError("can't load lua51");
        return;
    }
    auto defer1 = create_defer([lua51]() {
        unloadlib(lua51);
    });
    
    auto mainPath = getExePath().string();
    if (luaModuleSignature.scan(mainPath.c_str()) == 0) {
        spdlog::error("can't find luamodule base address");
        return;
    }
    
    auto res = SignatureUpdater::create_or_update(isClient, luaModuleSignature.target_address);
    if (!res) {
        showError(res.error());
        return;
    }
    auto &val = res.value();
    ReplaceLuaModule(mainPath, val.signatures, val.exports);
#if 0
    RedirectOpenGLEntries();
#endif
}
