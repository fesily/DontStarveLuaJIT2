// plugin_sim_lagcomp — dynamic EarlyNative face of sim.lagcomp
// Lua face: Mod/plugins/sim_lagcomp.lua (AfterModMain, EnableLagCompensation).
// Native APIs: DS_LUAJIT_lag_comp_* + DS_LUAJIT_entity_get_raw_ptr (Win x64 only).
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct SimLagcompPlugin final : IPlugin {
    PluginManifest man{};

    SimLagcompPlugin() {
        man.id = "sim.lagcomp";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        // Inventory priority 60 (with network.sim / save.fork).
        man.priority = 60;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {"EnableLagCompensation"};
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

    void load(PluginContext &) override {
        // No eager hooks — lag_compensation.lua drives lag_comp_* via FFI.
        std::fprintf(stderr, "[plugin_sim_lagcomp] native lag_comp APIs ready\n");
    }

    void unload(PluginContext &) override {
        // Sticky for process lifetime.
    }
};

SimLagcompPlugin g_sim_lagcomp;

} // namespace

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    OptionSchemaEntry e;
    e.key = "EnableLagCompensation";
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(false);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_sim_lagcomp] schema conflict EnableLagCompensation\n");
        return false;
    }
    host->register_plugin(&g_sim_lagcomp);
    std::fprintf(stderr, "[plugin_sim_lagcomp] module init registered sim.lagcomp\n");
    return true;
}
