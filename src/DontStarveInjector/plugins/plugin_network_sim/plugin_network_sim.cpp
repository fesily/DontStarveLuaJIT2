// plugin_network_sim — dynamic EarlyNative face of network.sim
// Lua face: Mod/plugins/network_sim.lua (AfterModMain, EnableNetSim).
// Native APIs: DS_LUAJIT_net_sim_* (lazy hook install on enable).
#include "gum_plugin_export.hpp"
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"
#include "config/ConfigSource.hpp"
#include "NetSimOptionKeys.hpp"

#include "core/PluginServices.hpp"
#include "ctx.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct NetworkSimPlugin final : IPlugin {
    PluginManifest man{};

    NetworkSimPlugin() {
        man.id = "network.sim";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        // Inventory priority 60. Gated by EnableNetSim (schema default false).
        // DynamicPluginLoader still maps the DLL and registers the plugin; Host
        // resolve skips load() when off. Exports remain available via host service
        // table for Lua GameInjector.DS_LUAJIT_net_sim_* when the option is later
        // enabled in Lua (lazy hook install on DS_LUAJIT_net_sim_enable).
        man.priority = 60;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {std::string{ds::config::keys::kEnableNetSim}};
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &ctx) const override {
#ifdef _WIN32
        (void) ctx;
        return true;
#else
        (void) ctx;
        return false;
#endif
    }

    void load(PluginContext &) override {
        // function_relocation is static-linked into this DLL; init local capstone/ctx.
        // Gum is process-global via Injector re-exports. Hooks install lazily on
        // DS_LUAJIT_net_sim_enable(true) from Lua.
        (void) function_relocation::init_ctx();
        std::fprintf(stderr, "[plugin_network_sim] native net_sim APIs ready (lazy hook)\n");
    }

    void unload(PluginContext &) override {
        // Sticky; SendBitStream hooks are not torn down.
    }
};

NetworkSimPlugin g_network_sim;

} // namespace

extern "C" void DS_LUAJIT_net_sim_enable(bool enable);
extern "C" void DS_LUAJIT_net_sim_set(unsigned, unsigned, unsigned);
extern "C" void DS_LUAJIT_net_sim_update();
extern "C" const void *DS_LUAJIT_net_sim_get_stats();

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    OptionSchemaEntry e;
    e.key = std::string{ds::config::keys::kEnableNetSim};
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(false);
    e.allowed_sources =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_network_sim] schema conflict %s\n",
                     std::string{ds::config::keys::kEnableNetSim}.c_str());
        return false;
    }

    ds_host_register_service("DS_LUAJIT_net_sim_enable",
                             reinterpret_cast<void *>(&DS_LUAJIT_net_sim_enable));
    ds_host_register_service("DS_LUAJIT_net_sim_set",
                             reinterpret_cast<void *>(&DS_LUAJIT_net_sim_set));
    ds_host_register_service("DS_LUAJIT_net_sim_update",
                             reinterpret_cast<void *>(&DS_LUAJIT_net_sim_update));
    ds_host_register_service("DS_LUAJIT_net_sim_get_stats",
                             reinterpret_cast<void *>(&DS_LUAJIT_net_sim_get_stats));
    host->register_plugin(&g_network_sim);
    std::fprintf(stderr, "[plugin_network_sim] module init registered network.sim\n");
    return true;
}
