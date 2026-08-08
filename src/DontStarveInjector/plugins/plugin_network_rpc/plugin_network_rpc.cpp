// plugin_network_rpc — dynamic EarlyNative face of network.rpc
// Lua face: plugins/plugin_network_rpc/ (modinfo + modmain).
#include "gum_plugin_export.hpp"
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"

#include "core/PluginTypes.hpp"
#include "config/ConfigSource.hpp"
#include "RpcOptionKeys.hpp"

#include "GameNetwork.hpp"
#include "ctx.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct NetworkRpcPlugin final : IPlugin {
    PluginManifest man{};

    NetworkRpcPlugin() {
        man.id = "network.rpc";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 40;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {std::string{ds::config::keys::kNetworkOpt}};
    }

    const PluginManifest &manifest() const override { return man; }
    bool can_load(const PluginContext &) const override { return true; }

    void load(PluginContext &) override {
        // Shared function_relocation ctx (refcounted). Gum via Injector re-exports.
        (void) function_relocation::init_ctx();
        GameNetWorkHookRpc4();
        std::fprintf(stderr, "[plugin_network_rpc] GameNetWorkHookRpc4 installed\n");
    }

    void unload(PluginContext &) override {
        // Sticky; gum probes are not torn down.
    }
};

NetworkRpcPlugin g_network_rpc;

} // namespace

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    OptionSchemaEntry e;
    e.key = std::string{ds::config::keys::kNetworkOpt};
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(true);
    e.allowed_sources =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_network_rpc] schema conflict %s\n",
                     std::string{ds::config::keys::kNetworkOpt}.c_str());
        return false;
    }

    RegisterNetworkRpcHostServices(host);
    host->register_plugin(&g_network_rpc);
    std::fprintf(stderr, "[plugin_network_rpc] module init registered network.rpc\n");
    return true;
}
