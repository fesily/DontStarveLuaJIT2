#pragma once
#include "ResolvedConfig.hpp"
#include "gameModConfig.hpp"

#include <string>
#include <string_view>

namespace ds::config {

inline GameJitConfigSource ToGameJitConfigSource(ConfigSource src) {
    switch (src) {
    case ConfigSource::ModinfoDefault:
        return GameJitConfigSource::modinfo_default;
    case ConfigSource::LuajitConfig:
        return GameJitConfigSource::luajit_config;
    case ConfigSource::SaveFile:
        return GameJitConfigSource::save_file;
    case ConfigSource::EnvOrCmd:
        return GameJitConfigSource::env_or_cmd;
    case ConfigSource::None:
    default:
        return GameJitConfigSource::none;
    }
}

inline GameJitConfigSource source_of_key(const ResolvedConfig &resolved, std::string_view key) {
    auto it = resolved.source_of.find(std::string{key});
    if (it == resolved.source_of.end()) {
        return GameJitConfigSource::none;
    }
    return ToGameJitConfigSource(it->second);
}

// Core keys owned by GameJitModConfig fields (not business_options).
inline bool is_core_option_key(std::string_view key) {
    return key == "AlwaysEnableMod" || key == "DisableJITWhenServer" || key == "LuaVmType" ||
           key == "EnabledGenGC";
}

inline GameJitModConfig map_to_game_jit_mod_config(const ResolvedConfig &resolved) {
    GameJitModConfig out;

    // Identity snapshot
    if (!resolved.ctx.modname.empty()) {
        out.modname = resolved.ctx.modname;
        out.modname_source = GameJitConfigSource::luajit_config;
    }
    if (!resolved.ctx.modid.empty()) {
        out.modid = resolved.ctx.modid;
        out.modid_source = GameJitConfigSource::luajit_config;
    }
    if (!resolved.ctx.modmain_path.empty()) {
        out.modmain_path = resolved.ctx.modmain_path;
        out.modmain_path_source = GameJitConfigSource::luajit_config;
    }
    if (resolved.ctx.save_file) {
        out.save_file = *resolved.ctx.save_file;
    }

    for (const auto &[key, value] : resolved.view) {
        if (key == "AlwaysEnableMod" && value.type == ds::plugin::ConfigValueType::Bool) {
            out.AlwaysEnableMod = value.b;
            out.AlwaysEnableModSource = source_of_key(resolved, key);
            continue;
        }
        if (key == "DisableJITWhenServer" && value.type == ds::plugin::ConfigValueType::Bool) {
            out.DisableJITWhenServer = value.b;
            out.DisableJITWhenServerSource = source_of_key(resolved, key);
            continue;
        }
        if (key == "LuaVmType" && value.type == ds::plugin::ConfigValueType::String) {
            out.LuaVmType = value.s;
            out.LuaVmTypeSource = source_of_key(resolved, key);
            continue;
        }
        if (key == "EnabledGenGC" && value.type == ds::plugin::ConfigValueType::Bool) {
            out.EnabledGenGC = value.b;
            out.EnabledGenGCSource = source_of_key(resolved, key);
            continue;
        }
        if (!is_core_option_key(key)) {
            out.business_options[key] = value;
        }
    }

    return out;
}

} // namespace ds::config
