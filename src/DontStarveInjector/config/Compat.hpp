#pragma once
#include "ResolvedConfig.hpp"
#include "gameModConfig.hpp"

#include <string>
#include <string_view>

namespace ds::config {

// Core + identity keys owned by GameJitModConfig fields (not business_options).
inline bool is_core_option_key(std::string_view key) {
    return key == "AlwaysEnableMod" || key == "DisableJITWhenServer" || key == "LuaVmType" ||
           key == "EnabledGenGC" || key == "modmain_path" || key == "modname" || key == "modid" ||
           key == "save_file";
}

// Project ResolvedConfig into the write-back bag (typed core + business_options).
// Source provenance for Host/L0 lives on ResolvedConfig.source_of; not mirrored here.
inline GameJitModConfig map_to_game_jit_mod_config(const ResolvedConfig &resolved) {
    GameJitModConfig out;

    // Identity: prefer view keys (schema SSOT), fall back to CascadeContext.
    if (auto p = resolved.modmain_path(); !p.empty()) {
        out.modmain_path = std::string{p};
    }
    if (auto n = resolved.modname(); !n.empty()) {
        out.modname = std::string{n};
    }
    if (auto id = resolved.modid(); !id.empty()) {
        out.modid = std::string{id};
    }
    if (auto sf = resolved.save_file()) {
        out.save_file = std::string{*sf};
    }

    for (const auto &[key, value] : resolved.view) {
        if (key == "AlwaysEnableMod" && value.type == ds::plugin::ConfigValueType::Bool) {
            out.AlwaysEnableMod = value.b;
            continue;
        }
        if (key == "DisableJITWhenServer" && value.type == ds::plugin::ConfigValueType::Bool) {
            out.DisableJITWhenServer = value.b;
            continue;
        }
        if (key == "LuaVmType" && value.type == ds::plugin::ConfigValueType::String) {
            out.LuaVmType = value.s;
            continue;
        }
        if (key == "EnabledGenGC" && value.type == ds::plugin::ConfigValueType::Bool) {
            out.EnabledGenGC = value.b;
            continue;
        }
        if (!is_core_option_key(key)) {
            out.business_options[key] = value;
        }
    }

    return out;
}

} // namespace ds::config
