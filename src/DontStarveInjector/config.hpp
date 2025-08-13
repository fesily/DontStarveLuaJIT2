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


struct InjectorConfig {
    struct EnvOrCmdOptFlag {
        const char *key;
        operator bool() const;
    };
#define ENV_OR_CMD_OPT_FLAG(name) \
    EnvOrCmdOptFlag name{#name};

    ENV_OR_CMD_OPT_FLAG(DontStarveInjectorDisable);
    ENV_OR_CMD_OPT_FLAG(DisableGameScriptsZip);
    ENV_OR_CMD_OPT_FLAG(DisableGameIO);
    ENV_OR_CMD_OPT_FLAG(LuajitWaitDebuggerEnable);
    ENV_OR_CMD_OPT_FLAG(DisableReplaceLuaIO);
    ENV_OR_CMD_OPT_FLAG(DisableForceLoadLuaJITMod);
    ENV_OR_CMD_OPT_FLAG(GameInjectorNoDefaultBeforeCode);
    ENV_OR_CMD_OPT_FLAG(disable_progress);

#undef ENV_OR_CMD_OPT_FLAG

    bool DontStarveInjectorIsClient{false};
    static InjectorConfig &instance();
};
