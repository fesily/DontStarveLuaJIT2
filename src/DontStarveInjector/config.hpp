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
#define DONTSTARVEINJECTOR_API __declspec(dllexport)
#else
#define DONTSTARVEINJECTOR_API
#endif
