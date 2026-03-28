#pragma once
#include "DstAngleBackend.hpp"
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
#define DONTSTARVEINJECTOR_API extern "C" __declspec(dllexport)
#else
#define DONTSTARVEINJECTOR_API extern "C" __attribute__((visibility("default")))
#endif

#define DONTSTARVEINJECTOR_GAME_API DONTSTARVEINJECTOR_API

#if __linux__

#ifndef DONTSTARVEINJECTOR_INITIALIZE_ALL_SO
#define DONTSTARVEINJECTOR_INITIALIZE_ALL_SO 1
#endif

#endif

#define LUA_DEBUG_CORE_ROOT "LUA_DEBUG_CORE_ROOT"
#define LUA_DEBUG_CORE_DEBUGGER "LUA_DEBUG_CORE_DEBUGGER"

struct InjectorConfig {
    static const char * getEnvOrCmdValue(const char *key, char *value, size_t value_size);
    struct EnvOrCmdOptFlag {
        const char *key;
        mutable bool has_cached = false;
        mutable bool flag = false;
        operator bool() const;
    };
    struct EnvOrCmdOptValue {
        const char *key;
        mutable bool has_cached = false;
        mutable char value[256] = {};
        operator const char*() const;
    };
    template<typename T, T default_value = 0>
    struct EnvOrCmdOptIntValue {
        const char *key;
        mutable bool has_cached = false;
        mutable T value = default_value;
        operator T() const;
    };

    template<typename T>
    struct EnvOrCmdOptEnum : public EnvOrCmdOptValue {
        mutable T value{};
        operator T() const;
    };

#define ENV_OR_CMD_OPT_FLAG(name) \
    const EnvOrCmdOptFlag name{#name};
#define ENV_OR_CMD_OPT_VALUE(name) \
    const EnvOrCmdOptValue name{#name};
#define ENV_OR_CMD_OPT_ENUM(_enum, name) \
    const EnvOrCmdOptEnum<_enum> name{#name};
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

    ENV_OR_CMD_OPT_ENUM(DstAngleBackend, DST_ANGLE_BACKEND); // specify ANGLE default platform, can be d3d11(default), d3d9, gl, vulkan
    ENV_OR_CMD_OPT_VALUE(lua_vm_type);     // specify lua vm type, can be lua51, luajit, or game, default is luajit

#undef ENV_OR_CMD_OPT_VALUE
#undef ENV_OR_CMD_OPT_FLAG
#undef ENV_OR_CMD_OPT_ENUM

    static InjectorConfig *instance();
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

template<typename T>
InjectorConfig::EnvOrCmdOptEnum<T>::operator T() const {
    if (has_cached) return value;
    const char *str_value = static_cast<const char *>(static_cast<const EnvOrCmdOptValue&>(*this));
    if (str_value == nullptr || str_value[0] == '\0') {
        has_cached = true;
        return value;
    }
    value = from_string(str_value);
    has_cached = true;
    return value;
}

typedef struct _GumInterceptor GumInterceptor;
class InjectorCtx {
public:
    InjectorConfig &config;
    bool DontStarveInjectorIsClient{false};
    uint32_t steam_account_id{0};
    GumInterceptor *GetGumInterceptor();
    InjectorCtx();
    static InjectorCtx *instance();
private:
    GumInterceptor *interceptor{nullptr};
};
