// plugin_manager — optional package manager (runtime-optional if DLL deleted).
// Soft GameInjector exports: register_game_injector_export only (no GameLuaModule host_service).
// When this module is absent, Lua sees nil for DS_LUAJIT_plugin_* — fail-soft.
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/GameInjectorLuaBind.hpp"
#include "core/PluginTypes.hpp"
#include "core/PluginServices.hpp"
#include "PluginManagerApi.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct PluginManagerPlugin final : IPlugin {
    PluginManifest man{};

    PluginManagerPlugin() {
        man.id = "plugin.manager";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        // Non-critical; inventory/UI only. No other plugin depends on us.
        man.priority = 50;
        man.options.kind = OptionRuleKind::AlwaysOn;
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &) const override {
        // Cross-platform skeleton (HTTP later Task 8).
        return true;
    }

    void load(PluginContext &) override {
        // Reload pin config only — no network in load().
        ds::plugin_manager::reload_pin_config();
        std::fprintf(stderr, "[plugin_manager] pin config reloaded (no network)\n");
    }

    void unload(PluginContext &) override {
        // Sticky for process lifetime; exports stay mapped.
    }
};

PluginManagerPlugin g_plugin;

} // namespace

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }

    // Soft Lua bindings via typed GameInjector export registry (GiType auto-deduced).
    // Deleting this DLL ⇒ no registration ⇒ luaopen_GameInjector leaves names nil.
    (void)host->register_game_injector_export("DS_LUAJIT_plugin_config_path",
                                              &DS_LUAJIT_plugin_config_path);
    (void)host->register_game_injector_export("DS_LUAJIT_plugin_manager_status_json",
                                              &DS_LUAJIT_plugin_manager_status_json);
    (void)host->register_game_injector_export("DS_LUAJIT_plugin_config_reload",
                                              &DS_LUAJIT_plugin_config_reload);
    (void)host->register_game_injector_export("DS_LUAJIT_plugin_config_set_json",
                                              &DS_LUAJIT_plugin_config_set_json);
    (void)host->register_game_injector_export("DS_LUAJIT_plugin_pin_set",
                                              &DS_LUAJIT_plugin_pin_set);
    (void)host->register_game_injector_export("DS_LUAJIT_plugin_pin_clear",
                                              &DS_LUAJIT_plugin_pin_clear);
    (void)host->register_game_injector_export("DS_LUAJIT_plugin_fetch_manifest",
                                              &DS_LUAJIT_plugin_fetch_manifest);
    (void)host->register_game_injector_export("DS_LUAJIT_plugin_manifest_json",
                                              &DS_LUAJIT_plugin_manifest_json);
    (void)host->register_game_injector_export("DS_LUAJIT_plugin_plan_apply_json",
                                              &DS_LUAJIT_plugin_plan_apply_json);
    (void)host->register_game_injector_export("DS_LUAJIT_plugin_apply",
                                              &DS_LUAJIT_plugin_apply);
    (void)host->register_game_injector_export("DS_LUAJIT_plugin_needs_restart",
                                              &DS_LUAJIT_plugin_needs_restart);

    // Optional C service table (same names) for native callers; Lua uses exports above.
    (void)host->register_service("DS_LUAJIT_plugin_config_path", &DS_LUAJIT_plugin_config_path);
    (void)host->register_service("DS_LUAJIT_plugin_manager_status_json",
                                 &DS_LUAJIT_plugin_manager_status_json);
    (void)host->register_service("DS_LUAJIT_plugin_config_reload", &DS_LUAJIT_plugin_config_reload);
    (void)host->register_service("DS_LUAJIT_plugin_config_set_json",
                                 &DS_LUAJIT_plugin_config_set_json);
    (void)host->register_service("DS_LUAJIT_plugin_pin_set", &DS_LUAJIT_plugin_pin_set);
    (void)host->register_service("DS_LUAJIT_plugin_pin_clear", &DS_LUAJIT_plugin_pin_clear);
    (void)host->register_service("DS_LUAJIT_plugin_fetch_manifest",
                                 &DS_LUAJIT_plugin_fetch_manifest);
    (void)host->register_service("DS_LUAJIT_plugin_manifest_json",
                                 &DS_LUAJIT_plugin_manifest_json);
    (void)host->register_service("DS_LUAJIT_plugin_plan_apply_json",
                                 &DS_LUAJIT_plugin_plan_apply_json);
    (void)host->register_service("DS_LUAJIT_plugin_apply", &DS_LUAJIT_plugin_apply);
    (void)host->register_service("DS_LUAJIT_plugin_needs_restart",
                                 &DS_LUAJIT_plugin_needs_restart);

    host->register_plugin(&g_plugin);
    std::fprintf(stderr, "[plugin_manager] module init registered plugin.manager (soft exports)\n");
    return true;
}
