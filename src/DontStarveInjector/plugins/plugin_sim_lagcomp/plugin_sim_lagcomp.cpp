// plugin_sim_lagcomp — dynamic EarlyNative face of sim.lagcomp
// Lua face: Mod/plugins/sim_lagcomp.lua (AfterModMain, EnableLagCompensation).
// Native APIs: DS_LUAJIT_lag_comp_* + DS_LUAJIT_entity_get_raw_ptr (Win x64 only).
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/GameInjectorLuaBind.hpp"
#include "core/PluginTypes.hpp"
#include "config/ConfigSource.hpp"
#include "LagCompOptionKeys.hpp"

#include "core/PluginServices.hpp"
#include "plugins/plugin_core_vm/VmServices.hpp"

#include <cstdio>
#include <stdexcept>

namespace {

using namespace ds::plugin;

struct SimLagcompPlugin final : IPlugin {
    PluginManifest man{};

    SimLagcompPlugin() {
        man.id = "sim.lagcomp";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        // Hard: service + plugin-id (topo + Failed propagation if core.vm fails).
        man.depends = {"core.vm"};
        man.requires_services = {"ds_core_vm_get_game_lua_context"};
        // Inventory priority 60 (with network.sim / save.fork).
        man.priority = 60;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {std::string{ds::config::keys::kEnableLagCompensation}};
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &ctx) const override {
#ifdef _WIN32
        // Lua face also requires mastersim; native APIs are Win-only.
        (void) ctx;
        return true;
#else
        (void) ctx;
        return false;
#endif
    }

    void load(PluginContext &ctx) override {
        // DI: Host injects requires_services; cache for FFI hot path (GameSimHook).
        if (!ds::core_vm::BindGameLuaContextService(&ctx)) {
            throw std::runtime_error("sim.lagcomp: missing ds_core_vm_get_game_lua_context");
        }
        // No eager hooks — lag_compensation.lua drives lag_comp_* via FFI.
        std::fprintf(stderr, "[plugin_sim_lagcomp] native lag_comp APIs ready (GameLuaContext bound)\n");
    }

    void unload(PluginContext &) override {
        // Sticky for process lifetime.
    }
};

SimLagcompPlugin g_sim_lagcomp;

} // namespace

struct lua_State;
extern "C" int DS_LUAJIT_entity_get_raw_ptr(lua_State *L);

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    OptionSchemaEntry e;
    e.key = std::string{ds::config::keys::kEnableLagCompensation};
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(false);
    e.allowed_sources =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_sim_lagcomp] schema conflict %s\n",
                     std::string{ds::config::keys::kEnableLagCompensation}.c_str());
        return false;
    }

        (void) host->register_game_injector_export("DS_LUAJIT_entity_get_raw_ptr", &DS_LUAJIT_entity_get_raw_ptr);
    host->register_plugin(&g_sim_lagcomp);
    std::fprintf(stderr, "[plugin_sim_lagcomp] module init registered sim.lagcomp\n");
    return true;
}
