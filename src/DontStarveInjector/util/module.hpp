#pragma once
#include <cstdint>
#include <minwindef.h>
struct ExportDetails
{
    enum Type
    {
        FUNCTION,
        DATA,
    };
    Type type;
    const char *name;
    void *address;
};
struct ImportDetails
{
    enum Type
    {
        FUNCTION,
        DATA,
    };
    Type type;
    const char *name;
    void *address;
    const char *module;
    void *slot;
};
using FoundImportFunc = bool (*)(const ImportDetails *, void *);
using FoundExportFunc = bool (*)(const ExportDetails *, void *);
void module_enumerate_exports(HMODULE module,
                              FoundExportFunc func,
                              void *user_data);
void
module_enumerate_imports (HMODULE module,
                              FoundImportFunc func,
                              void* user_data);