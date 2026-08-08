#pragma once
#include "config/InjectorHostConfig.hpp" // DS_INJECTOR_CXX_API
#include <filesystem>
#include <string>

namespace ds::plugin {

// Light sandbox parse of a DST mod's modinfo.lua for the external plugin-pack
// trust gate. Never LoadLibrary. Fields beyond marker + plugin_id are ignored.
struct PluginPackModinfo {
    bool ok = false;
    bool luajit_plugin_pack = false;
    std::string plugin_id;
    std::string parse_error;
};

// Sandbox-executes modinfo.lua at path with a minimal env
// (folder_name, locale, ChooseTranslationTable). Never LoadLibrary.
DS_INJECTOR_CXX_API PluginPackModinfo
parse_plugin_pack_modinfo(const std::filesystem::path &modinfo_path);

// Trust gate for external packs: ok && luajit_plugin_pack && !plugin_id.empty().
// This mod itself is marker-exempt at a higher layer; external requires id.
DS_INJECTOR_CXX_API bool external_pack_trust_ok(const PluginPackModinfo &info);

} // namespace ds::plugin
