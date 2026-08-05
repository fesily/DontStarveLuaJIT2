#pragma once
#include "config.hpp" // DS_INJECTOR_CXX_API (must be outside ds::config)
#include "ConfigSource.hpp"
#include "IConfigSource.hpp"
#include "ConfigSchema.hpp"
#include "BaseOptionKeys.hpp"
#include "plugins/plugin_render_angle/AngleOptionKeys.hpp"
#include "core/PluginTypes.hpp"
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace ds::config {

struct ResolvedConfig {
    ds::plugin::ConfigView view;
    std::unordered_map<std::string, ConfigSource> source_of;
    CascadeContext ctx; // identity snapshot

    // L0 base accessors only (identity + AlwaysEnableMod).
    // VM selection (GameLuaType / get_lua_vm_type) lives in plugin_core_vm/VmConfig.hpp.
    bool always_enable_mod() const {
        auto it = view.find(std::string{keys::kAlwaysEnableMod});
        return it != view.end() && it->second.type == ds::plugin::ConfigValueType::Bool &&
               it->second.b;
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
    // Business convenience (render.angle owns the key; keep thin until Host API).
    std::string_view angle_backend() const {
        auto it = view.find(std::string{keys::kAngleBackend});
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
// L0 cascade cache filled by ensure_resolved() / refresh_cascade_after_plugins.
// Null before first resolve. Host / L0 hot path consume current() / ensure_resolved().
DS_INJECTOR_CXX_API const ResolvedConfig *current();
DS_INJECTOR_CXX_API const ResolvedConfig *ensure_resolved();

// After DynamicPluginLoader module_init has registered late keys (VM/business),
// merge host schema into cascade schema and re-resolve so save/env apply to them.
// Overwrites g_resolved_config (OB-S2).
DS_INJECTOR_CXX_API void refresh_cascade_after_plugins(
    const ds::plugin::ConfigSchemaRegistry &host_schema);
} // namespace ds::config
