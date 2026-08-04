#pragma once
#include "config.hpp"
#include <string>
#include <cstdint>
#include <frida-gum.h>

DS_INJECTOR_CXX_API std::string get_module_path(const char *maybeName, uintptr_t ptr = 0);

DS_INJECTOR_CXX_API void gum_module_enumerate_imports_ext(GumModule * self,
                              GumFoundImportFunc func,
                              gpointer user_data);
