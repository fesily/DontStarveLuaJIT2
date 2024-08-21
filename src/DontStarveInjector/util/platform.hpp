#pragma once

#include <filesystem>
#include <vector>

std::filesystem::path getExePath();

using module_handler_t = void *;

module_handler_t loadlib(const char *name);

void *loadlibproc(module_handler_t h, const char *name);

void unloadlib(module_handler_t h);

uintptr_t getParentId();

std::string get_cwd(uintptr_t pid = 0);
std::vector<std::string> get_cwds(uintptr_t pid = 0);

void set_worker_directory(const char *path);
