#pragma once
#include <string>
#include <cstdint>
#include <frida-gum.h>

std::string get_module_path(const char *maybeName, uintptr_t ptr = 0);

void gum_module_enumerate_imports_ext(GumModule * self,
                              GumFoundImportFunc func,
                              gpointer user_data);
