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
// AngleBackend, NetworkOpt, EnableNetSim, …) live in business_options and are
// merged into ConfigView by BuildConfigView (schema → business → core).
struct GameJitModConfig {
    std::optional<std::string> save_file;
    std::optional<std::string> modmain_path;
    std::optional<std::string> modname;
    std::optional<std::string> modid;
    std::string LuaVmType;
    bool AlwaysEnableMod = false;
    bool DisableJITWhenServer = false;
    bool EnabledGenGC = false;

    // Save / overrides / env business keys by option name (C-S3).
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
