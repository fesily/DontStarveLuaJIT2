#pragma once
// core.vm interpretation of cascade ResolvedConfig VM keys.
// Config module only stores string/bool keys; mapping to GameLuaType lives here.

#include "GameLuaType.hpp"
#include "VmOptionKeys.hpp"
#include "config/ResolvedConfig.hpp"

#include <string>
#include <string_view>

namespace ds::core_vm {

inline bool disable_jit_when_server(const ds::config::ResolvedConfig &rc) {
    using ds::config::keys::kDisableJITWhenServer;
    auto it = rc.view.find(std::string{kDisableJITWhenServer});
    return it != rc.view.end() && it->second.type == ds::plugin::ConfigValueType::Bool && it->second.b;
}

inline bool enabled_gen_gc(const ds::config::ResolvedConfig &rc) {
    using ds::config::keys::kEnabledGenGC;
    auto it = rc.view.find(std::string{kEnabledGenGC});
    return it != rc.view.end() && it->second.type == ds::plugin::ConfigValueType::Bool && it->second.b;
}

inline std::string_view lua_vm_type_string(const ds::config::ResolvedConfig &rc) {
    using ds::config::keys::kLuaVmType;
    auto it = rc.view.find(std::string{kLuaVmType});
    if (it != rc.view.end() && it->second.type == ds::plugin::ConfigValueType::String) {
        return it->second.s;
    }
    return {};
}

inline GameLuaType get_lua_vm_type(const ds::config::ResolvedConfig &rc) {
    if (enabled_gen_gc(rc)) {
        return GameLuaType::jit_gen;
    }
    using ds::config::keys::kLuaVmType;
    auto it = rc.source_of.find(std::string{kLuaVmType});
    auto raw = lua_vm_type_string(rc);
    if (it == rc.source_of.end() || it->second == ds::config::ConfigSource::None) {
        if (raw.empty()) {
            return GameLuaType::unknown;
        }
    }
    if (raw.empty()) {
        return GameLuaType::unknown;
    }
    return GameLuaTypeFromString(raw);
}

} // namespace ds::core_vm
