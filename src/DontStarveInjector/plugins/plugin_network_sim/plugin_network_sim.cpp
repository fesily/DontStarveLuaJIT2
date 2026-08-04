// plugin_network_sim — dynamic EarlyNative face of network.sim
// Lua face: Mod/plugins/network_sim.lua (AfterModMain, EnableNetSim).
// Native APIs: DS_LUAJIT_net_sim_* (lazy hook install on enable).
#include "gum_plugin_export.hpp"
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"
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
        // Inventory priority 60. EnableNetSim is Lua-gated (AfterModMain); native
        // hooks install lazily on DS_LUAJIT_net_sim_enable. Always load the DLL on
        // Windows so GameInjector can resolve exports when Lua enables sim.
        man.priority = 60;
        man.options.kind = OptionRuleKind::AlwaysOn;
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

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    host->register_plugin(&g_network_sim);
    std::fprintf(stderr, "[plugin_network_sim] module init registered network.sim\n");
    return true;
}
