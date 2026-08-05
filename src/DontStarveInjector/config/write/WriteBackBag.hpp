#pragma once
// Internal projection bag for client save write-back only.
// Runtime SSOT remains ResolvedConfig / ds::config::current().

#include "core/PluginTypes.hpp"

#include <optional>
#include <string>

namespace ds::config {

struct WriteBackBag {
    std::optional<std::string> save_file;
    std::optional<std::string> modmain_path;
    std::optional<std::string> modname;
    std::optional<std::string> modid;
    std::string LuaVmType;
    bool AlwaysEnableMod = false;
    bool DisableJITWhenServer = false;
    bool EnabledGenGC = false;
    // True when ResolvedConfig.view carried VM schema keys (plugin_core_vm present).
    bool has_vm_options = false;
    ds::plugin::ConfigView business_options;
};

} // namespace ds::config
