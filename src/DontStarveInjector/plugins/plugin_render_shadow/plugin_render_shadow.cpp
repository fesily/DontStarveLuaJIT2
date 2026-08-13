// plugin_render_shadow — dynamic EarlyNative face of render.shadow
#include "gum_plugin_export.hpp"
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/GameInjectorLuaBind.hpp"
#include "core/PluginTypes.hpp"
#include "config/ConfigSource.hpp"
#include "ShadowOptionKeys.hpp"
#include "GenerateVBHook.hpp"
#include "SunModel.hpp"

#include "core/PluginServices.hpp"
#include "ctx.hpp"

#include <cstdio>

extern "C" void DS_LUAJIT_shadow_set_enabled(bool enable);
extern "C" void DS_LUAJIT_shadow_set_length_boost(double boost);
extern "C" void DS_LUAJIT_shadow_set_state(int phase_id, double progress, int fullmoon);

namespace {

using namespace ds::plugin;

struct RenderShadowPlugin final : IPlugin {
    PluginManifest man{};

    RenderShadowPlugin() {
        man.id = "render.shadow";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 35;
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

    void load(PluginContext &) override {
        // Static-lib copy of function_relocation needs per-DLL capstone/ctx init.
        (void) function_relocation::init_ctx();
        std::fprintf(stderr, "[plugin_render_shadow] EarlyNative load (exports ready)\n");
    }

    void unload(PluginContext &) override {
        // Sticky; GenerateVB hook (Task 4) stays for process lifetime.
    }
};

RenderShadowPlugin g_render_shadow;

} // namespace

extern "C" void DS_LUAJIT_shadow_set_enabled(bool enable) {
    ds::shadow::SetSunDriveEnabled(enable);
    std::fprintf(stderr, "[plugin_render_shadow] set_enabled=%d installed=%d\n", enable ? 1 : 0,
                 ds::shadow::IsHookInstalled() ? 1 : 0);
}

extern "C" void DS_LUAJIT_shadow_set_length_boost(double boost) {
    ds::shadow::SetLengthBoost(boost);
    std::fprintf(stderr, "[plugin_render_shadow] set_length_boost=%g\n",
                 ds::shadow::GetLengthBoost());
}

extern "C" void DS_LUAJIT_shadow_set_state(int phase_id, double progress, int fullmoon) {
    using ds::shadow::Phase;
    Phase p = Phase::Day;
    if (phase_id == 1) {
        p = Phase::Dusk;
    } else if (phase_id == 2) {
        p = Phase::Night;
    }
    float prog = static_cast<float>(progress);
    if (prog < 0.f) {
        prog = 0.f;
    }
    if (prog > 1.f) {
        prog = 1.f;
    }
    const auto sample =
        ds::shadow::Evaluate(p, prog, fullmoon != 0,
                             static_cast<float>(ds::shadow::GetLengthBoost()));
    ds::shadow::Publish(sample);
}

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kShadowSunDrive};
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(false);
        e.allowed_sources =
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
        if (!host->register_option_schema(std::move(e))) {
            std::fprintf(stderr, "[plugin_render_shadow] schema conflict %s\n",
                         std::string{ds::config::keys::kShadowSunDrive}.c_str());
            return false;
        }
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kShadowLengthBoost};
        e.type = ConfigValueType::Number;
        e.default_value = ConfigValue::number(1.0);
        e.allowed_sources =
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
        if (!host->register_option_schema(std::move(e))) {
            std::fprintf(stderr, "[plugin_render_shadow] schema conflict %s\n",
                         std::string{ds::config::keys::kShadowLengthBoost}.c_str());
            return false;
        }
    }

    (void) host->register_game_injector_export("DS_LUAJIT_shadow_set_enabled",
                                               &DS_LUAJIT_shadow_set_enabled);
    (void) host->register_game_injector_export("DS_LUAJIT_shadow_set_length_boost",
                                               &DS_LUAJIT_shadow_set_length_boost);
    (void) host->register_game_injector_export("DS_LUAJIT_shadow_set_state",
                                               &DS_LUAJIT_shadow_set_state);
    host->register_plugin(&g_render_shadow);
    std::fprintf(stderr, "[plugin_render_shadow] module init registered render.shadow\n");
    return true;
}
