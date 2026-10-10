// plugin_network_stats — dynamic EarlyNative face of network.stats
// Per-client RTT: cNetworkClientObject2::UpdateNetStats listener reading the
// engine's own stats ring (no engine code is replaced; Windows/Linux x64).
// Lua face: plugins/plugin_network_stats/ (modinfo + modmain).
#include "gum_plugin_export.hpp"
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"

#include "core/PluginTypes.hpp"
#include "config/ConfigSource.hpp"
#include "ClientPingOptionKeys.hpp"

#include "ClientPingHook.hpp"
#include "ctx.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct NetworkStatsPlugin final : IPlugin {
    PluginManifest man{};

    NetworkStatsPlugin() {
        man.id = "network.stats";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 42;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {std::string{ds::config::keys::kEnableClientPing}};
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &) const override {
#if defined(_M_X64) || defined(__x86_64__)
        return true;
#else
        return false; // decode/probe is x86-64 only
#endif
    }

    void load(PluginContext &) override {
        // Shared function_relocation ctx (refcounted); gum via Frida::Gum.
        (void) function_relocation::init_ctx();
        if (ds::net_stats::install()) {
            std::fprintf(stderr, "[net.stats] installed (read-only ring probe)\n");
        }
    }

    void unload(PluginContext &) override {
        // Sticky; gum probes are not torn down (matches network.rpc / lagcomp).
    }
};

NetworkStatsPlugin g_network_stats;

} // namespace

extern "C" int32_t DS_LUAJIT_net_client_ping(const char *userid);

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    OptionSchemaEntry e;
    e.key = std::string{ds::config::keys::kEnableClientPing};
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(true);
    e.allowed_sources =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_network_stats] schema conflict %s\n",
                     std::string{ds::config::keys::kEnableClientPing}.c_str());
        return false;
    }

    static constexpr GiType kPingTypes[] = {GiType::I32, GiType::CString};
    (void) host->register_game_injector_export("DS_LUAJIT_net_client_ping", kPingTypes,
                                               reinterpret_cast<void *>(&DS_LUAJIT_net_client_ping));
    host->register_plugin(&g_network_stats);
    std::fprintf(stderr, "[plugin_network_stats] module init registered network.stats\n");
    return true;
}
