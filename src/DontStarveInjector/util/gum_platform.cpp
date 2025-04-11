#include "gum_platform.hpp"
#include <frida-gum.h>
#include <filesystem>
#include <list>

std::string get_module_path(const char *maybeName, uintptr_t ptr) {
    std::list<std::string> res;
    auto arg = std::tuple{&res, maybeName, ptr};
    gum_process_enumerate_modules(
            +[](GumModule * module,
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
    for (auto& p : res) {
        if (p == maybeName)
            return p;
    }
    return res.back();
}