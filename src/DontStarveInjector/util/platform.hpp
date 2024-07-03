#pragma once

#include <filesystem>

std::filesystem::path getExePath();

using module_handler_t = void *;

module_handler_t loadlib(const char *name);

void *loadlibproc(module_handler_t h, const char *name);

void unloadlib(module_handler_t h);

uintptr_t getParentId();

const char *get_cwd(uintptr_t pid = 0);

void set_worker_directory(const char *path);
