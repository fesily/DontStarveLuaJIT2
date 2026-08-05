// plugin_render_angle — dynamic EarlyNative face of render.angle
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/GameInjectorLuaBind.hpp"
#include "core/PluginTypes.hpp"
#include "config/ConfigSource.hpp"
#include "AngleOptionKeys.hpp"

#include "core/PluginServices.hpp"
#include "GameOpenGl.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct RenderAnglePlugin final : IPlugin {
    PluginManifest man{};

    RenderAnglePlugin() {
        man.id = "render.angle";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        // After vbpool in former LoadGameModConfig sequence.
        man.priority = 30;
        man.options.kind = OptionRuleKind::AlwaysOn;
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

    void load(PluginContext &ctx) override {
        // Backend string is already in ConfigView / GameJitModConfig; InitGameOpenGl
        // reads the resolved singleton (same cascade the bridge mirrors).
        (void) ctx;
        InitGameOpenGl();
        std::fprintf(stderr, "[plugin_render_angle] InitGameOpenGl called\n");
    }

    void unload(PluginContext &) override {
        // Sticky ANGLE IAT rebind.
    }
};

RenderAnglePlugin g_render_angle;

} // namespace

// GAME_API defined in GameOpenGl.cpp
extern "C" const char *DS_LUAJIT_get_render_backend_name();

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    OptionSchemaEntry e;
    e.key = std::string{ds::config::keys::kAngleBackend};
    e.type = ConfigValueType::String;
    e.default_value = ConfigValue::string("auto");
    e.allowed = {"auto", "vulkan", "d3d11", "d3d9"};
    e.allowed_sources =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_render_angle] schema conflict %s\n",
                     std::string{ds::config::keys::kAngleBackend}.c_str());
        return false;
    }
    host->register_service("DS_LUAJIT_get_render_backend_name",
                             reinterpret_cast<void *>(&DS_LUAJIT_get_render_backend_name));
        (void) host->register_game_injector_export(
        "DS_LUAJIT_get_render_backend_name", ds::plugin::GiSig::CString_void, reinterpret_cast<void *>(&DS_LUAJIT_get_render_backend_name));
    host->register_plugin(&g_render_angle);
    std::fprintf(stderr, "[plugin_render_angle] module init registered render.angle\n");
    return true;
}
