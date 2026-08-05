#pragma once
// Write-back projection bag only (map_to_game_jit_mod_config / save writer).
// Runtime SSOT: ds::config::current() / ResolvedConfig accessors.
// Save write API: config/write/SaveConfigWriter.hpp

#include "config.hpp"
#include "core/PluginTypes.hpp"

#include <filesystem>
#include <optional>
#include <string>

struct GameJitModConfig {
    std::optional<std::string> save_file;
    std::optional<std::string> modmain_path;
    std::optional<std::string> modname;
    std::optional<std::string> modid;
    std::string LuaVmType;
    bool AlwaysEnableMod = false;
    bool DisableJITWhenServer = false;
    bool EnabledGenGC = false;
    // True when cascade ResolvedConfig.view carried VM schema keys
    // (plugin_core_vm present). False ⇒ write-back must not emit empty/false
    // bag defaults over an existing client save.
    bool has_vm_options = false;

    // Filled by map_to_game_jit_mod_config for save write-back only.
    // Do not use for Host gates or L0 hot path.
    ds::plugin::ConfigView business_options;

    static DS_INJECTOR_CXX_API std::optional<GameJitModConfig> instance();
};
