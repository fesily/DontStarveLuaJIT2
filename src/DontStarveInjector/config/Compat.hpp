#pragma once
#include "ResolvedConfig.hpp"
#include "write/WriteBackBag.hpp"
#include "BaseOptionKeys.hpp"
#include "plugins/plugin_core_vm/VmOptionKeys.hpp"

namespace ds::config {
namespace {

bool is_core_or_identity_key(std::string_view key) {
    using namespace keys;
    return key == kAlwaysEnableMod || key == kDisableJITWhenServer || key == kLuaVmType ||
           key == kEnabledGenGC || key == kModmainPath || key == kModname || key == kModid ||
           key == kSaveFile;
}

} // namespace

// Project ResolvedConfig into the write-back bag (typed core + business_options).
inline WriteBackBag map_to_write_back_bag(const ResolvedConfig &resolved) {
    WriteBackBag out;
    if (resolved.ctx.save_file && !resolved.ctx.save_file->empty()) {
        out.save_file = *resolved.ctx.save_file;
    }
    if (auto sf = resolved.save_file()) {
        out.save_file = std::string{*sf};
    }
    out.modmain_path = std::string{resolved.modmain_path()};
    out.modname = std::string{resolved.modname()};
    out.modid = std::string{resolved.modid()};

    using namespace keys;
    out.has_vm_options = resolved.view.count(std::string{kLuaVmType}) ||
                         resolved.view.count(std::string{kEnabledGenGC}) ||
                         resolved.view.count(std::string{kDisableJITWhenServer});

    for (const auto &[key, value] : resolved.view) {
        if (key == kAlwaysEnableMod && value.type == ds::plugin::ConfigValueType::Bool) {
            out.AlwaysEnableMod = value.b;
            continue;
        }
        if (key == kDisableJITWhenServer && value.type == ds::plugin::ConfigValueType::Bool) {
            out.DisableJITWhenServer = value.b;
            continue;
        }
        if (key == kLuaVmType && value.type == ds::plugin::ConfigValueType::String) {
            out.LuaVmType = value.s;
            continue;
        }
        if (key == kEnabledGenGC && value.type == ds::plugin::ConfigValueType::Bool) {
            out.EnabledGenGC = value.b;
            continue;
        }
        if (is_core_or_identity_key(key)) {
            continue;
        }
        out.business_options[key] = value;
    }
    return out;
}

// Back-compat name used by older call sites during migration.
inline WriteBackBag map_to_game_jit_mod_config(const ResolvedConfig &resolved) {
    return map_to_write_back_bag(resolved);
}

} // namespace ds::config
