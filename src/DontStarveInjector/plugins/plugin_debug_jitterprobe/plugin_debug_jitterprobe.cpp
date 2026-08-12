// plugin_debug_jitterprobe — temporary EarlyNative face of debug.jitterprobe
// Lua face: scripts/jitter_probe.lua (client prediction-OFF path samples).
// Native: DS_LUAJIT_jitter_probe_* (Win x64 Gum hooks + ring buffer).
#include "gum_plugin_export.hpp"
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/GameInjectorLuaBind.hpp"
#include "core/PluginTypes.hpp"
#include "config/ConfigSource.hpp"
#include "JitterOptionKeys.hpp"

#include "core/PluginServices.hpp"
#include "ctx.hpp"

#include <cstdio>
#include <string>

extern "C" void DS_LUAJIT_jitter_probe_enable(bool enable);
extern "C" bool DS_LUAJIT_jitter_probe_is_enabled();
extern "C" void DS_LUAJIT_jitter_probe_set_track(void *transform);
extern "C" void DS_LUAJIT_jitter_probe_set_track_entity(void *entity);
extern "C" void DS_LUAJIT_jitter_probe_set_local_only(bool on);
extern "C" void DS_LUAJIT_jitter_probe_flush();
extern "C" void DS_LUAJIT_jitter_probe_set_vm_tag(const char *tag);

namespace {

using namespace ds::plugin;

struct JitterProbePlugin final : IPlugin {
    PluginManifest man{};

    JitterProbePlugin() {
        man.id = "debug.jitterprobe";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 15;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {std::string{ds::config::keys::kEnableJitterProbe}};
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
        (void)function_relocation::init_ctx();
        DS_LUAJIT_jitter_probe_enable(true);
        std::fprintf(stderr,
                     "[plugin_debug_jitterprobe] native load: probe enable requested\n");
    }

    void unload(PluginContext &) override {
        DS_LUAJIT_jitter_probe_flush();
    }
};

JitterProbePlugin g_jitter_probe;

} // namespace

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    OptionSchemaEntry e;
    e.key = std::string{ds::config::keys::kEnableJitterProbe};
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(false);
    e.allowed_sources =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_debug_jitterprobe] schema conflict %s\n",
                     std::string{ds::config::keys::kEnableJitterProbe}.c_str());
        return false;
    }

    (void)host->register_game_injector_export("DS_LUAJIT_jitter_probe_enable",
                                              &DS_LUAJIT_jitter_probe_enable);
    (void)host->register_game_injector_export("DS_LUAJIT_jitter_probe_is_enabled",
                                              &DS_LUAJIT_jitter_probe_is_enabled);
    (void)host->register_game_injector_export("DS_LUAJIT_jitter_probe_set_track",
                                              &DS_LUAJIT_jitter_probe_set_track);
    (void)host->register_game_injector_export("DS_LUAJIT_jitter_probe_set_track_entity",
                                              &DS_LUAJIT_jitter_probe_set_track_entity);
    (void)host->register_game_injector_export("DS_LUAJIT_jitter_probe_set_local_only",
                                              &DS_LUAJIT_jitter_probe_set_local_only);
    (void)host->register_game_injector_export("DS_LUAJIT_jitter_probe_flush",
                                              &DS_LUAJIT_jitter_probe_flush);
    (void)host->register_game_injector_export("DS_LUAJIT_jitter_probe_set_vm_tag",
                                              &DS_LUAJIT_jitter_probe_set_vm_tag);
    host->register_plugin(&g_jitter_probe);
    std::fprintf(stderr, "[plugin_debug_jitterprobe] module init registered debug.jitterprobe\n");
    return true;
}
