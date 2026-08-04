#pragma once
#include "config.hpp"
#include "GameLuaType.hpp"
#include "core/PluginTypes.hpp"
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

enum class GameJitConfigSource {
    none,
    modinfo_default,
    luajit_config,
    save_file,
    env_or_cmd,
};

// L0 core identity / VM config only. Business option gates (EnableVBPool,
// AngleBackend, NetworkOpt, EnableNetSim, …) are cascade-resolved into
// ResolvedConfig.view (Host SSOT via BuildConfigView late defaults).
//
// business_options remains a legacy projection from map_to_game_jit_mod_config
// for write-back / a few plugin readers until CF-S5 — do not use for Host gates.
struct GameJitModConfig {
    std::optional<std::string> save_file;
    std::optional<std::string> modmain_path;
    std::optional<std::string> modname;
    std::optional<std::string> modid;
    std::string LuaVmType;
    bool AlwaysEnableMod = false;
    bool DisableJITWhenServer = false;
    bool EnabledGenGC = false;

    // Deprecated for Host (CF-S4): cascade ConfigView is SSOT. Still filled by
    // map_to_game_jit_mod_config for save write-back and legacy field readers.
    ds::plugin::ConfigView business_options;

    GameJitConfigSource modmain_path_source = GameJitConfigSource::none;
    GameJitConfigSource modname_source = GameJitConfigSource::none;
    GameJitConfigSource modid_source = GameJitConfigSource::none;
    GameJitConfigSource LuaVmTypeSource = GameJitConfigSource::none;
    GameJitConfigSource AlwaysEnableModSource = GameJitConfigSource::none;
    GameJitConfigSource DisableJITWhenServerSource = GameJitConfigSource::none;
    GameJitConfigSource EnabledGenGCSource = GameJitConfigSource::none;

    GameLuaType GetLuaVmType() const {
        if (EnabledGenGC) {
            return GameLuaType::jit_gen;
        }
        if (LuaVmTypeSource == GameJitConfigSource::none) {
            return GameLuaType::unknown;
        }
        return GameLuaTypeFromString(LuaVmType);
    }

    static DS_INJECTOR_CXX_API std::optional<GameJitModConfig> instance();
};

GameJitModConfig make_default_game_mod_config();
bool LoadGameJitModConfigFromSaveFile(const std::filesystem::path &path, GameJitModConfig &resolved);
bool LoadGameJitModConfigFromModOverridesFile(const std::filesystem::path &path,
                                             const std::vector<std::string> &aliases,
                                             GameJitModConfig &resolved);
bool WriteGameJitModConfigToSaveFile(const std::filesystem::path &path, const GameJitModConfig &config);

DONTSTARVEINJECTOR_API int DS_LUAJIT_set_target_fps(int fps, int tt);
