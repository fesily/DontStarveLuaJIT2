#pragma once
#include "ConfigSource.hpp"
#include "IConfigSource.hpp"
#include "ConfigSchema.hpp"
#include "BaseOptionKeys.hpp"
#include "plugins/plugin_core_vm/VmOptionKeys.hpp"
#include "core/PluginTypes.hpp"
#include "GameLuaType.hpp"
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace ds::config {

struct ResolvedConfig {
    ds::plugin::ConfigView view;
    std::unordered_map<std::string, ConfigSource> source_of;
    CascadeContext ctx; // identity snapshot

    // L0 hot-path accessors over view + identity (CF-S5). Prefer these over the
    // legacy GameJitModConfig bag for inject / core.vm / render readers.
    bool always_enable_mod() const {
        auto it = view.find(std::string{keys::kAlwaysEnableMod});
        return it != view.end() && it->second.type == ds::plugin::ConfigValueType::Bool &&
               it->second.b;
    }

    bool disable_jit_when_server() const {
        auto it = view.find(std::string{keys::kDisableJITWhenServer});
        return it != view.end() && it->second.type == ds::plugin::ConfigValueType::Bool &&
               it->second.b;
    }

    bool enabled_gen_gc() const {
        auto it = view.find(std::string{keys::kEnabledGenGC});
        return it != view.end() && it->second.type == ds::plugin::ConfigValueType::Bool &&
               it->second.b;
    }

    std::string_view lua_vm_type() const {
        auto it = view.find(std::string{keys::kLuaVmType});
        if (it != view.end() && it->second.type == ds::plugin::ConfigValueType::String) {
            return it->second.s;
        }
        return {};
    }

    GameLuaType get_lua_vm_type() const {
        if (enabled_gen_gc()) {
            return GameLuaType::jit_gen;
        }
        auto it = source_of.find(std::string{keys::kLuaVmType});
        if (it == source_of.end() || it->second == ConfigSource::None) {
            // empty / never set → unknown (matches legacy bag GetLuaVmType)
            if (lua_vm_type().empty()) {
                return GameLuaType::unknown;
            }
        }
        auto raw = lua_vm_type();
        if (raw.empty()) {
            return GameLuaType::unknown;
        }
        return GameLuaTypeFromString(raw);
    }

    std::string_view modmain_path() const {
        auto it = view.find(std::string{keys::kModmainPath});
        if (it != view.end() && it->second.type == ds::plugin::ConfigValueType::String &&
            !it->second.s.empty()) {
            return it->second.s;
        }
        return ctx.modmain_path;
    }

    std::string_view modname() const {
        auto it = view.find(std::string{keys::kModname});
        if (it != view.end() && it->second.type == ds::plugin::ConfigValueType::String &&
            !it->second.s.empty()) {
            return it->second.s;
        }
        return ctx.modname;
    }

    std::string_view modid() const {
        auto it = view.find(std::string{keys::kModid});
        if (it != view.end() && it->second.type == ds::plugin::ConfigValueType::String &&
            !it->second.s.empty()) {
            return it->second.s;
        }
        return ctx.modid;
    }

    std::optional<std::string_view> save_file() const {
        auto it = view.find(std::string{keys::kSaveFile});
        if (it != view.end() && it->second.type == ds::plugin::ConfigValueType::String &&
            !it->second.s.empty()) {
            return std::string_view{it->second.s};
        }
        if (ctx.save_file && !ctx.save_file->empty()) {
            return std::string_view{*ctx.save_file};
        }
        return std::nullopt;
    }

    std::string_view angle_backend() const {
        auto it = view.find("AngleBackend");
        if (it != view.end() && it->second.type == ds::plugin::ConfigValueType::String) {
            return it->second.s;
        }
        return "auto";
    }

    // Generic typed lookup for remaining business keys.
    std::optional<bool> bool_opt(std::string_view key) const {
        auto it = view.find(std::string{key});
        if (it == view.end() || it->second.type != ds::plugin::ConfigValueType::Bool) {
            return std::nullopt;
        }
        return it->second.b;
    }

    std::optional<std::string_view> string_opt(std::string_view key) const {
        auto it = view.find(std::string{key});
        if (it == view.end() || it->second.type != ds::plugin::ConfigValueType::String) {
            return std::nullopt;
        }
        return std::string_view{it->second.s};
    }
};
// L0 cascade cache filled by GameJitModConfig::instance() / refresh path.
// Null before first resolve. Host / L0 hot path consume current() (CF-S4/S5).
// Exported so plugins can import from Injector.dll.
#include "config.hpp"
DS_INJECTOR_CXX_API const ResolvedConfig *current();

// After DynamicPluginLoader module_init has registered late keys (VM/business),
// merge host schema into cascade schema and re-resolve so save/env apply to them.
// Overwrites g_resolved_config / GameJitModConfig cache (OB-S2).
DS_INJECTOR_CXX_API void refresh_cascade_after_plugins(
    const ds::plugin::ConfigSchemaRegistry &host_schema);
} // namespace ds::config
