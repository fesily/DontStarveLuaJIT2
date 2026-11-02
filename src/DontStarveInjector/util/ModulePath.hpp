#pragma once
// Locate a loaded module by file stem WITHOUT going through the ELF global
// symbol scope: dl_iterate_phdr (Linux) / _dyld_image_count (macOS) enumerate
// every mapped object, including ones dlopen'd with RTLD_LOCAL.
//
// Why not the obvious alternatives (all measured on this tree):
//  - dlsym(RTLD_DEFAULT, "<some symbol>") + dladdr: needs the module to export
//    that symbol into the global scope, which only holds for RTLD_GLOBAL
//    modules. Plugins are loaded RTLD_LOCAL.
//  - dlopen("<basename>", RTLD_NOLOAD): returns NULL for a module opened by
//    absolute path (glibc matches the name it was opened with, and our MODULE
//    targets carry no SONAME).
//
// Windows callers keep GetModuleHandleW/A, which is already scope-independent,
// so this helper returns {} there.
#include <filesystem>
#include <string>
#include <string_view>

#if defined(__linux__) || defined(__FreeBSD__)
#  include <link.h>
#elif defined(__APPLE__)
#  include <mach-o/dyld.h>
#endif

namespace ds::util {

namespace detail {

inline bool module_stem_matches(const char *path, std::string_view stem) {
    if (!path || !*path || stem.empty()) {
        return false;
    }
    const std::string_view full{path};
    const auto slash = full.find_last_of('/');
    const auto base = slash == std::string_view::npos ? full : full.substr(slash + 1);
    if (base.size() < stem.size() || base.compare(0, stem.size(), stem) != 0) {
        return false;
    }
    // "plugin_core_vm" then ".so" / ".dylib"; reject "plugin_core_vm_extra".
    const auto rest = base.substr(stem.size());
    return rest.empty() || rest.front() == '.';
}

} // namespace detail

// Absolute path of the loaded module whose file stem equals `stem`
// (e.g. "plugin_core_vm", "libInjector"); empty when it is not mapped.
inline std::filesystem::path loaded_module_path_by_stem(std::string_view stem) {
    const std::string stem_copy{stem};
#if defined(__linux__) || defined(__FreeBSD__)
    struct Ctx {
        const std::string &stem;
        std::filesystem::path found;
    } ctx{stem_copy, {}};
    dl_iterate_phdr(
        [](struct dl_phdr_info *info, size_t, void *data) -> int {
            auto *c = static_cast<Ctx *>(data);
            if (detail::module_stem_matches(info->dlpi_name, c->stem)) {
                c->found = info->dlpi_name;
                return 1;
            }
            return 0;
        },
        &ctx);
    return ctx.found;
#elif defined(__APPLE__)
    const uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (detail::module_stem_matches(name, stem_copy)) {
            return std::filesystem::path{name};
        }
    }
    return {};
#else
    (void)stem_copy;
    return {};
#endif
}

} // namespace ds::util
