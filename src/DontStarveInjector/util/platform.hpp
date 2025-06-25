#pragma once

#include <filesystem>
#include <vector>

std::filesystem::path getExePath();

using module_handler_t = void *;

module_handler_t loadlib(const char *name, int mode = 0);

void *loadlibproc(module_handler_t h, const char *name);

void unloadlib(module_handler_t h);

uintptr_t getParentId();

std::string get_cmd(uintptr_t pid = 0);
std::vector<std::string> get_cmds(uintptr_t pid = 0);

void set_worker_directory(const char *path);
