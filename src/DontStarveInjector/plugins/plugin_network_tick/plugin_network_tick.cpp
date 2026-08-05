// plugin_network_tick — independent of network.rpc / network.sim
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/GameInjectorLuaBind.hpp"
#include "core/PluginTypes.hpp"
#include "core/PluginServices.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct NetworkTickPlugin final : IPlugin {
    PluginManifest man{};
    NetworkTickPlugin() {
        man.id = "network.tick";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 45;
        man.options.kind = OptionRuleKind::AlwaysOn;
    }
    const PluginManifest &manifest() const override { return man; }
    bool can_load(const PluginContext &ctx) const override {
#ifdef _WIN32
        (void)ctx;
        return true;
#else
        (void)ctx;
        return false;
#endif
    }
    void load(PluginContext &) override {
        std::fprintf(stderr, "[plugin_network_tick] network.tick API ready\n");
    }
    void unload(PluginContext &) override {}
};

NetworkTickPlugin g_plugin;

} // namespace

extern "C" int DS_LUAJIT_replace_network_tick(char upload_tick, char download_tick, bool isclient);

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
        (void) host->register_game_injector_export(
        "DS_LUAJIT_replace_network_tick",
        {ds::plugin::GiType::I32, ds::plugin::GiType::I8, ds::plugin::GiType::I8, ds::plugin::GiType::Bool},
        reinterpret_cast<void *>(&DS_LUAJIT_replace_network_tick));
    host->register_plugin(&g_plugin);
    std::fprintf(stderr, "[plugin_network_tick] module init registered network.tick\n");
    return true;
}
