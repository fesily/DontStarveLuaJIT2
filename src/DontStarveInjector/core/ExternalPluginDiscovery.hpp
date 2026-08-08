#pragma once
#include "config/InjectorHostConfig.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace ds::plugin {

// True if candidate is the same as root or a path strictly under root after
// weakly_canonical. Used as path jail before any LoadLibrary of pack modules.
DS_INJECTOR_CXX_API bool path_under_root(const std::filesystem::path &root,
                                         const std::filesystem::path &candidate);

// Absolute module paths under mod_root/plugins/plugin_*/plugin_*.{dll,so,dylib}
// that pass path_under_root. Does not LoadLibrary.
DS_INJECTOR_CXX_API std::vector<std::filesystem::path>
list_pack_modules_under_mod(const std::filesystem::path &mod_root);

} // namespace ds::plugin
