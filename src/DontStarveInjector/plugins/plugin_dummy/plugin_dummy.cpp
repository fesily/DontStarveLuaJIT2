// plugin_dummy.cpp - log-only dynamic plugin for DynamicPluginLoader smoke.
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct DummyPlugin final : IPlugin {
    PluginManifest man{};
    DummyPlugin() {
        man.id = "debug.dummy";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 1000;
        man.options.kind = OptionRuleKind::AlwaysOn;
    }
    const PluginManifest &manifest() const override { return man; }
    bool can_load(const PluginContext &) const override { return true; }
    void load(PluginContext &) override {
        std::fprintf(stderr, "[plugin_dummy] dynamic plugin dummy load\n");
        // fprintf is enough for smoke (no spdlog dep)
    }
    void unload(PluginContext &) override {}
};

DummyPlugin g_dummy;

} // namespace

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) return false;
    host->register_plugin(&g_dummy);
    std::fprintf(stderr, "[plugin_dummy] module init registered debug.dummy\n");
    return true;
}
