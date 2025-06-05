#include "gum_platform.hpp"
#include <filesystem>
#include <frida-gum.h>
#include <list>
#ifdef _WIN32
#include "module.hpp"
#endif
std::string get_module_path(const char *maybeName, uintptr_t ptr) {
    std::list<std::string> res;
    auto arg = std::tuple{&res, maybeName, ptr};
    gum_process_enumerate_modules(
            +[](GumModule *module,
                gpointer user_data) -> gboolean {
                auto &[res, maybeName, ptr] = *(decltype(arg) *) user_data;
                auto module_name = gum_module_get_name(module);
                if (std::string_view(module_name).contains(maybeName)) {
                    auto range = gum_module_get_range(module);
                    if (ptr != 0 && !(range->base_address <= ptr && ptr < range->base_address + range->size))
                        return true;
                    auto path = gum_module_get_path(module);
                    res->push_back(path);
                    return true;
                }
                return true;
            },
            (void *) &arg);
    for (auto &p: res) {
        if (p == maybeName)
            return p;
    }
    return res.back();
}

void gum_module_enumerate_imports_ext(GumModule *self,
                                      GumFoundImportFunc func,
                                      gpointer user_data) {
    auto range = gum_module_get_range(self);
#ifdef _WIN32
    std::pair args = {func, user_data};
    auto module = (HMODULE) range->base_address;
    module_enumerate_imports(module, +[](const ImportDetails *details, void *ud) {
        auto [func, user_data] = *(decltype(args) *) ud;
        GumImportDetails gumdetails;
        gumdetails.type = GUM_IMPORT_FUNCTION;
        gumdetails.name = details->name;
        gumdetails.address = (GumAddress)details->address;
        gumdetails.slot = (GumAddress)details->slot;
        bool ret = func(&gumdetails, user_data);
        return ret;
     }, (void*)&args);
#else
    gum_module_enumerate_imports(self, func, user_data);
#endif
}