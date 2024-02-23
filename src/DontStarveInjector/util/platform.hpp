#pragma once
#include <filesystem>

std::filesystem::path getExePath();

using module_handler_t = void*;

module_handler_t loadlib(const char* name);

void* loadlibproc(module_handler_t h, const char* name);

void unloadlib(module_handler_t h);

bool memory_is_execute(void* address);

const char* get_cwd();
