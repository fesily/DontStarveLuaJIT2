// plugin_fps_render — native face of fps.render (independent of network.tick).
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"
#include "core/PluginServices.hpp"
#include "config/ConfigSchema.hpp"
#include "FpsOptionKeys.hpp"
#include "config.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;
using ds::config::keys::kTargetRenderFPS;

struct FpsRenderPlugin final : IPlugin {
    PluginManifest man{};
    FpsRenderPlugin() {
        man.id = "fps.render";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 50;
        // AlwaysOn native so exports exist when Lua AfterModMain calls set_target_fps.
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
        std::fprintf(stderr, "[plugin_fps_render] fps.render APIs ready\n");
    }
    void unload(PluginContext &) override {}
};

FpsRenderPlugin g_plugin;

} // namespace

extern "C" int DS_LUAJIT_set_target_fps(int fps, int tt);
extern "C" float DS_LUAJIT_get_frame_time_s(void);

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    OptionSchemaEntry e;
    e.key = std::string{kTargetRenderFPS};
    e.type = ConfigValueType::Number;
    e.default_value = ConfigValue::number(60);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_fps_render] schema conflict TargetRenderFPS\n");
        return false;
    }
    ds_host_register_service("DS_LUAJIT_set_target_fps",
                             reinterpret_cast<void *>(&DS_LUAJIT_set_target_fps));
    ds_host_register_service("DS_LUAJIT_get_frame_time_s",
                             reinterpret_cast<void *>(&DS_LUAJIT_get_frame_time_s));
    host->register_plugin(&g_plugin);
    std::fprintf(stderr, "[plugin_fps_render] module init registered fps.render\n");
    return true;
}
