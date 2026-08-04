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

// Core + identity keys owned by GameJitModConfig fields (not business_options).
inline bool is_core_option_key(std::string_view key) {
    return key == "AlwaysEnableMod" || key == "DisableJITWhenServer" || key == "LuaVmType" ||
           key == "EnabledGenGC" || key == "modmain_path" || key == "modname" || key == "modid" ||
           key == "save_file";
}

inline GameJitModConfig map_to_game_jit_mod_config(const ResolvedConfig &resolved) {
    GameJitModConfig out;

    // Identity: prefer view keys (schema SSOT), fall back to CascadeContext.
    if (auto p = resolved.modmain_path(); !p.empty()) {
        out.modmain_path = std::string{p};
        out.modmain_path_source = source_of_key(resolved, "modmain_path");
        if (out.modmain_path_source == GameJitConfigSource::none) {
            out.modmain_path_source = GameJitConfigSource::luajit_config;
        }
    }
    if (auto n = resolved.modname(); !n.empty()) {
        out.modname = std::string{n};
        out.modname_source = source_of_key(resolved, "modname");
        if (out.modname_source == GameJitConfigSource::none) {
            out.modname_source = GameJitConfigSource::luajit_config;
        }
    }
    if (auto id = resolved.modid(); !id.empty()) {
        out.modid = std::string{id};
        out.modid_source = source_of_key(resolved, "modid");
        if (out.modid_source == GameJitConfigSource::none) {
            out.modid_source = GameJitConfigSource::luajit_config;
        }
    }
    if (auto sf = resolved.save_file()) {
        out.save_file = std::string{*sf};
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
