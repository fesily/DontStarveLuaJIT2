#pragma once
#ifdef _WIN32
#include "config/InjectorHostConfig.hpp"
#include <cstdint>
#include <Windows.h>

struct ExportDetails {
    enum Type {
        FUNCTION,
        DATA,
    };
    Type type;
    const char *name;
    void *address;
    uint16_t ordinal;
};
struct ImportDetails {
    enum Type {
        FUNCTION,
        DATA,
    };
    Type type;
    const char *name;
    void *address;
    const char *module;
    void *slot;
    uint16_t ordinal;
};
using FoundImportFunc = bool (*)(const ImportDetails *, void *);
using FoundExportFunc = bool (*)(const ExportDetails *, void *);

DS_INJECTOR_CXX_API void module_enumerate_exports(HMODULE module,
                              FoundExportFunc func,
                              void *user_data);

DS_INJECTOR_CXX_API void
module_enumerate_imports(HMODULE module,
                         FoundImportFunc func,
                         void *user_data);
#endif