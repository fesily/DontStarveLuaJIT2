#include "RegisterBuiltinPlugins.hpp"
#include "PluginHost.hpp"
#include "PluginTypes.hpp"

#include "GameNetwork.hpp"

namespace ds::plugin {
namespace {

// Native EarlyNative face of dual-face plugin network.rpc.
// Lua face (AfterModMain) lives in Mod/plugins/network_rpc.lua under the same id.
struct NetworkRpcPlugin final : IPlugin {
    PluginManifest man{};

    NetworkRpcPlugin() {
        man.id = "network.rpc";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 40;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {"NetworkOpt"};
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &) const override { return true; }

    void load(PluginContext &) override {
        // Installs RPC4 SetNextRpcInfo probe + entity serialize channel hooks.
        // Entity Lua face (network.entity) hard-depends on this plugin so the
        // serialize hooks are present whenever entity opt is allowed to load.
        GameNetWorkHookRpc4();
    }

    void unload(PluginContext &) override {
        // Sticky by default; gum probes are not torn down.
    }
};

NetworkRpcPlugin g_network_rpc;

} // namespace

void RegisterBuiltinPlugins(PluginHost &host) {
    host.register_plugin(&g_network_rpc);
}

} // namespace ds::plugin
