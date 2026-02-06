#pragma once

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
#define ENV_OR_CMD_OPT_FLAG(name) \
    const EnvOrCmdOptFlag name{#name};
#define ENV_OR_CMD_OPT_VALUE(name) \
    const EnvOrCmdOptValue name{#name};
#define ENV_OR_CMD_OPT_INT_VALUE(name) \
    const EnvOrCmdOptIntValue<int> name{#name};


    ENV_OR_CMD_OPT_FLAG(DontStarveInjectorDisable);
    ENV_OR_CMD_OPT_FLAG(DisableGameScriptsZip);
    ENV_OR_CMD_OPT_FLAG(DisableGameIO);
    ENV_OR_CMD_OPT_FLAG(LuajitWaitDebuggerEnable);
    ENV_OR_CMD_OPT_FLAG(DisableReplaceLuaIO);
    ENV_OR_CMD_OPT_FLAG(DisableForceLoadLuaJITMod);
    ENV_OR_CMD_OPT_FLAG(GameInjectorNoDefaultBeforeCode);
    ENV_OR_CMD_OPT_FLAG(disable_progress);
    ENV_OR_CMD_OPT_FLAG(enable_lua_debugger);
    ENV_OR_CMD_OPT_FLAG(disable_lua_debugger_code_patch);

    ENV_OR_CMD_OPT_VALUE(lua_vm_type);

#undef ENV_OR_CMD_OPT_VALUE
#undef ENV_OR_CMD_OPT_FLAG

    static InjectorConfig *instance();
};
typedef struct _GumInterceptor GumInterceptor;
class InjectorCtx {
public:
    InjectorConfig &config;
    bool DontStarveInjectorIsClient{false};
    GumInterceptor *GetGumInterceptor();
    InjectorCtx();
    static InjectorCtx *instance();
private:
    GumInterceptor *interceptor{nullptr};
};