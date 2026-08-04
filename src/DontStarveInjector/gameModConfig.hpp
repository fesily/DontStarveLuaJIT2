#pragma once
#include "config.hpp"
#include "GameLuaType.hpp"
#include "core/PluginTypes.hpp"
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

// L0 core identity / VM config projection from ResolvedConfig (CF-S5/S6).
// Prefer ds::config::current() accessors for Inject / Host / plugin readers.
// Typed fields remain for write-back and GAME_API fps paths.
//
// business_options remains a legacy projection from map_to_game_jit_mod_config
// for save write-back — do not use for Host gates or L0 hot path.
struct GameJitModConfig {
    std::optional<std::string> save_file;
    std::optional<std::string> modmain_path;
    std::optional<std::string> modname;
    std::optional<std::string> modid;
    std::string LuaVmType;
    bool AlwaysEnableMod = false;
    bool DisableJITWhenServer = false;
    bool EnabledGenGC = false;

    // Deprecated for Host (CF-S4/S5): cascade ConfigView is SSOT. Still filled by
    // map_to_game_jit_mod_config for save write-back and a few legacy readers.
    ds::plugin::ConfigView business_options;

    static DS_INJECTOR_CXX_API std::optional<GameJitModConfig> instance();
};

// Client save write-back only (load path is config/sources/*).
bool WriteGameJitModConfigToSaveFile(const std::filesystem::path &path, const GameJitModConfig &config);

DONTSTARVEINJECTOR_API int DS_LUAJIT_set_target_fps(int fps, int tt);
