#pragma once
// plugin.manager — C API surface for GameInjector / soft Lua bindings.
// Implementations live in PluginManagerApi.cpp (inventory + HTTP fetch/apply).

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
// fetch_manifest_blocking / apply_blocking: synchronous — EarlyNative boot only.
// UI uses the non-blocking DS_LUAJIT_plugin_* exports (worker threads + status.progress).
namespace ds::plugin_manager {
void reload_pin_config();
bool auto_apply_on_boot();
bool fetch_manifest_blocking(const char *release_tag_or_null);
bool apply_blocking(const char *id_or_null);
}
