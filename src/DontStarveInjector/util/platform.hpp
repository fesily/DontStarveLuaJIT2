#pragma once

#include <filesystem>
#include <vector>
#include <string>
#include <cstdint>

#if defined(_WIN32) && defined(DONTSTARVEINJECTOR_BUILD)
#  define DS_PLATFORM_API __declspec(dllexport)
#elif defined(_WIN32) && defined(DS_INJECTOR_CONSUMER)
#  define DS_PLATFORM_API __declspec(dllimport)
#elif !defined(_WIN32)
#  define DS_PLATFORM_API __attribute__((visibility("default")))
#else
#  define DS_PLATFORM_API
#endif

DS_PLATFORM_API std::filesystem::path getExePath();

using module_handler_t = void *;

DS_PLATFORM_API module_handler_t loadlib(const char *name, int mode = 0);

DS_PLATFORM_API void *loadlibproc(module_handler_t h, const char *name);

DS_PLATFORM_API void unloadlib(module_handler_t h);

DS_PLATFORM_API uintptr_t getParentId();

DS_PLATFORM_API std::string get_cmd(uintptr_t pid = 0);
DS_PLATFORM_API std::vector<std::string> get_cmds(uintptr_t pid = 0);

DS_PLATFORM_API void set_worker_directory(const char *path);

DS_PLATFORM_API void set_env_variable(const char *key, const char *value);
