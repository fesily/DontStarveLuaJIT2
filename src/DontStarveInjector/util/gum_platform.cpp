#include "gum_platform.hpp"
#include <frida-gum.h>
#include <filesystem>
#include <list>

std::string get_module_path(const char *maybeName, uintptr_t ptr) {
    std::list<std::string> res;
    auto arg = std::tuple{&res, maybeName, ptr};
    gum_process_enumerate_modules(
            +[](const GumModuleDetails *details,
                gpointer user_data) -> gboolean {
                auto &[res, maybeName, ptr] = *(decltype(arg) *) user_data;
                if (std::string_view(details->name).contains(maybeName)) {
                    if (ptr != 0 && !(details->range->base_address <= ptr && ptr < details->range->base_address + details->range->size))
                        return true;
                    res->push_back(details->path);
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