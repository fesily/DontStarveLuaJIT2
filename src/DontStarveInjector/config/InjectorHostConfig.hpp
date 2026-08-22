#pragma once
// L0 injector host process config (env/cmd flags, export macros, InjectorCtx).
// NOT game-option cascade — base does not register these as plugin options.
// Include this header for process flags / InjectorCtx / export macros.

#include <stdint.h>
#include <cstring>
#include <cstdlib>
#ifdef ENABLE_FAKE_API
#define USE_FAKE_API 1
#else
#define USE_FAKE_API 0
#endif

#ifdef ENABLE_ONLY_LUA51
#define ONLY_LUA51 1
#else
#define ONLY_LUA51 0
#endif

#ifdef ENABLE_USE_LISTENER
#define USE_LISTENER 1
#else
#define USE_LISTENER 0
#endif

#ifndef DEBUG_GETSIZE_PATCH
#define DEBUG_GETSIZE_PATCH 1
#endif

#ifndef ENABLE_LUA_DEBUGGER
#define ENABLE_LUA_DEBUGGER 1
#endif

#ifdef _WIN32
constexpr auto lua51_name = "lua51";
#else
constexpr auto lua51_name = "liblua51."
#if defined(__APPLE__)
                            "dylib"
#else
                            "so"
#endif
        ;
#endif
constexpr auto game_name = "dontstarve_";

#ifdef _WIN32
#  if defined(DONTSTARVEINJECTOR_BUILD)
#    define DONTSTARVEINJECTOR_API extern "C" __declspec(dllexport)
#    define DS_INJECTOR_CXX_API __declspec(dllexport)
#  elif defined(DS_PLUGIN_HOST_STATIC)
#    define DONTSTARVEINJECTOR_API extern "C"
#    define DS_INJECTOR_CXX_API
#  else
#    define DONTSTARVEINJECTOR_API extern "C" __declspec(dllimport)
#    define DS_INJECTOR_CXX_API __declspec(dllimport)
#  endif
#else
#  if defined(DONTSTARVEINJECTOR_BUILD)
#    define DONTSTARVEINJECTOR_API extern "C" __attribute__((visibility("default")))
#    define DS_INJECTOR_CXX_API __attribute__((visibility("default")))
#  else
#    define DONTSTARVEINJECTOR_API extern "C"
#    define DS_INJECTOR_CXX_API
#  endif
#endif

// GAME_API: feature exports may live in Injector or any plugin DLL.
// Always export when compiling a DLL that defines these entry points (historical).
// Callers resolve via GetProcAddress / delay-load rather than hard dllimport.
#if defined(_WIN32)
#  define DONTSTARVEINJECTOR_GAME_API extern "C" __declspec(dllexport)
#else
#  define DONTSTARVEINJECTOR_GAME_API extern "C" __attribute__((visibility("default")))
#endif

#if __linux__

#ifndef DONTSTARVEINJECTOR_INITIALIZE_ALL_SO
#define DONTSTARVEINJECTOR_INITIALIZE_ALL_SO 1
#endif

#endif

#define LUA_DEBUG_CORE_ROOT "LUA_DEBUG_CORE_ROOT"
#define LUA_DEBUG_CORE_DEBUGGER "LUA_DEBUG_CORE_DEBUGGER"

struct InjectorConfig {
    static DS_INJECTOR_CXX_API const char * getEnvOrCmdValue(const char *key, char *value, size_t value_size);
    struct EnvOrCmdOptFlag {
        const char *key;
        mutable bool has_cached = false;
        mutable bool flag = false;
        DS_INJECTOR_CXX_API operator bool() const;
    };
    struct EnvOrCmdOptValue {
        const char *key;
        mutable bool has_cached = false;
        mutable char value[256] = {};
        DS_INJECTOR_CXX_API operator const char*() const;
    };
    template<typename T, T default_value = 0>
    struct EnvOrCmdOptIntValue {
        const char *key;
        mutable bool has_cached = false;
        mutable T value = default_value;
        operator T() const;
    };

#define ENV_OR_CMD_OPT_FLAG(name) \
    const EnvOrCmdOptFlag name{#name};
#define ENV_OR_CMD_OPT_VALUE(name) \
    const EnvOrCmdOptValue name{#name};
#define ENV_OR_CMD_OPT_INT_VALUE(name) \
    const EnvOrCmdOptIntValue<int> name{#name};


    ENV_OR_CMD_OPT_FLAG(DontStarveInjectorDisable); // disbale all features
    ENV_OR_CMD_OPT_FLAG(DisableGameScriptsZip); // disable the game builtin script zip, directly load from directory
    ENV_OR_CMD_OPT_FLAG(DisableGameIO); // disable the game builtin io, redirect to lua io
    ENV_OR_CMD_OPT_FLAG(LuajitWaitDebuggerEnable); // wait for debugger attach before load
    ENV_OR_CMD_OPT_FLAG(DisableReplaceLuaIO);   // disable replace lua io, only work when DisableGameIO enabled
    ENV_OR_CMD_OPT_FLAG(DisableForceLoadLuaJITMod); // disable force load LuaJIT mod
    ENV_OR_CMD_OPT_FLAG(GameInjectorNoDefaultBeforeCode); // for game injector, do not patch before code
    ENV_OR_CMD_OPT_FLAG(disable_progress);      // disable repatch progress display
    ENV_OR_CMD_OPT_FLAG(enable_lua_debugger);   // enable lua debugger support
    ENV_OR_CMD_OPT_FLAG(disable_lua_debugger_code_patch); // disable lua debugger code patch, only work when enable_lua_debugger enabled
    ENV_OR_CMD_OPT_FLAG(AppVersionDevPatch);    // for developer, always treat app version as dev, so that can use dev code path

    ENV_OR_CMD_OPT_VALUE(lua_vm_type);     // specify lua vm type, can be lua51, luajit, or game, default is luajit

#undef ENV_OR_CMD_OPT_VALUE
#undef ENV_OR_CMD_OPT_FLAG

    static DS_INJECTOR_CXX_API InjectorConfig *instance();
};

template<typename T, T default_value>
InjectorConfig::EnvOrCmdOptIntValue<T, default_value>::operator T() const {
    if (has_cached) return value;
    char buf[64] = {};
    InjectorConfig::getEnvOrCmdValue(key, buf, sizeof(buf));
    char *endptr = buf + strlen(buf);
    if (endptr == buf) {
        has_cached = true;
        return value;
    }
    value = static_cast<T>(std::strtoll(buf, &endptr, 0));
    if (*endptr != '\0') {
        value = default_value;
    }
    has_cached = true;
    return value;
}

typedef struct _GumInterceptor GumInterceptor;
class InjectorCtx {
public:
    InjectorConfig &config;
    bool DontStarveInjectorIsClient{false};
    uint32_t steam_account_id{0};
    DS_INJECTOR_CXX_API GumInterceptor *GetGumInterceptor();
    InjectorCtx();
    static DS_INJECTOR_CXX_API InjectorCtx *instance();
private:
    GumInterceptor *interceptor{nullptr};
};
