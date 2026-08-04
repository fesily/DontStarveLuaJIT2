// plugin_render_vbpool — dynamic EarlyNative face of render.vbpool
#include "gum_plugin_export.hpp"
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"
#include "config/ConfigSource.hpp"

#include "core/PluginServices.hpp"
#include "ctx.hpp"

#include <cstdio>

// Declared/exported by GameRenderHook (Win) / stub (non-Win).
extern "C" void DS_LUAJIT_set_vbpool_enabled(bool enable);

namespace {

using namespace ds::plugin;

struct RenderVbpoolPlugin final : IPlugin {
    PluginManifest man{};

    RenderVbpoolPlugin() {
        man.id = "render.vbpool";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        // Before network.rpc; matches former LoadGameModConfig order (vbpool then angle).
        man.priority = 20;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {"EnableVBPool"};
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &ctx) const override {
#ifdef _WIN32
        return ctx.is_client;
#else
        (void) ctx;
        return false;
#endif
    }

    void load(PluginContext &) override {
        // Static-lib copy of function_relocation needs per-DLL capstone/ctx init.
        (void) function_relocation::init_ctx();
        DS_LUAJIT_set_vbpool_enabled(true);
        std::fprintf(stderr, "[plugin_render_vbpool] VBPool enabled\n");
    }

    void unload(PluginContext &) override {
        // Sticky; pool hooks stay for process lifetime.
    }
};

RenderVbpoolPlugin g_render_vbpool;

} // namespace

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    OptionSchemaEntry e;
    e.key = "EnableVBPool";
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(false);
    e.allowed_sources =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_render_vbpool] schema conflict EnableVBPool\n");
        return false;
    }

    ds_host_register_service("DS_LUAJIT_set_vbpool_enabled",
                             reinterpret_cast<void *>(&DS_LUAJIT_set_vbpool_enabled));
    host->register_plugin(&g_render_vbpool);
    std::fprintf(stderr, "[plugin_render_vbpool] module init registered render.vbpool\n");
    return true;
}
