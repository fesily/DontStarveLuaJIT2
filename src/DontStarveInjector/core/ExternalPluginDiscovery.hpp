#pragma once
#include "config/InjectorHostConfig.hpp"
#include "PluginHost.hpp"

#include <filesystem>
#include <functional>
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

struct ExternalDiscoverReport {
    size_t mods_seen = 0;
    size_t mods_accepted = 0;
    size_t modules_loaded = 0;
    std::vector<std::string> skipped; // reason lines
    std::vector<std::string> loaded_modules;
};

// Optional test seam: if set, called instead of real LoadLibrary path.
// Returns true if "loaded".
using ExternalModuleLoadFn =
    std::function<bool(const std::filesystem::path &module_path, std::string *skip_reason)>;

// Enumerate enabled external mods, parse modinfo trust gate, then load package
// modules. Never LoadLibrary before trust gate. this_mod_root is skipped.
// load_fn: production passes nullptr to use DynamicPluginLoader::load_module_path.
DS_INJECTOR_CXX_API ExternalDiscoverReport
discover_and_load_external_plugins(PluginHost &host, bool is_client,
                                   const std::filesystem::path &this_mod_root,
                                   ExternalModuleLoadFn load_fn = {});

} // namespace ds::plugin
