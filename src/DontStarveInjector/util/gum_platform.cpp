#include "gum_platform.hpp"
#include <frida-gum.h>

std::string get_module_path(const char *maybeName, uintptr_t ptr) {
    std::string res;
    auto arg = std::tuple{&res, maybeName, ptr};
    gum_process_enumerate_modules(
            +[](const GumModuleDetails *details,
                gpointer user_data) -> gboolean {
                auto &[res, maybeName, ptr] = *(decltype(arg) *) user_data;
                if (std::string_view(details->name).contains(maybeName)) {
                    if (ptr != 0 && !(details->range->base_address <= ptr && ptr < details->range->base_address + details->range->size))
                        return true;
                    res->append(details->path);
                    return false;
                }
                return true;
            },
            (void *) &arg);
    return res;
}