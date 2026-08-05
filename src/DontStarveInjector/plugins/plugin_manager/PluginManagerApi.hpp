#pragma once
// plugin.manager — C API surface for GameInjector / soft Lua bindings.
// Implementations live in PluginManagerApi.cpp (config real; HTTP/apply stubs for Task 8).

#include "config/InjectorHostConfig.hpp"

// All exports are C ABI; registered via register_game_injector_export in module_init.
// Soft absence: if plugin_manager module is not loaded, Lua sees nil for these names.

DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_config_path();
DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_manager_status_json();
DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_config_reload();
DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_config_set_json(const char *json);
DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_pin_set(const char *id, const char *version, bool is_override);
DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_pin_clear(const char *id);
DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_fetch_manifest(const char *release_tag_or_null);
DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_manifest_json();
DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_plugin_plan_apply_json();
DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_apply(const char *id_or_null);
DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_plugin_needs_restart();

// Internal: reload pin config from disk (used by IPlugin::load).
namespace ds::plugin_manager {
void reload_pin_config();
}
