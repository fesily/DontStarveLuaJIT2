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
#include "SilhouetteBatch.hpp"
#include "AnimDrawHook.hpp"

#include "core/PluginServices.hpp"
#include "ctx.hpp"

#include <cstdio>

#include <spdlog/spdlog.h>

extern "C" void DS_LUAJIT_shadow_set_enabled(bool enable);
extern "C" void DS_LUAJIT_shadow_set_ellipse(int on);
extern "C" void DS_LUAJIT_shadow_set_world(int phase_id, int timeinphase_centi, int time_centi,
                                           int flags);
extern "C" void DS_LUAJIT_shadow_set_length_boost(double boost);
extern "C" void DS_LUAJIT_shadow_set_hemisphere(int northern);
extern "C" void DS_LUAJIT_shadow_set_silhouette(int on);




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

extern "C" void DS_LUAJIT_shadow_set_ellipse(int on) {
    ds::shadow::SetEllipseEnabled(on != 0);
    std::fprintf(stderr, "[plugin_render_shadow] set_ellipse=%d\n", on != 0 ? 1 : 0);
}


extern "C" void DS_LUAJIT_shadow_set_world(int phase_id, int timeinphase_centi, int time_centi,
                                           int flags) {
    auto clamp_centi = [](int v) {
        if (v < 0) {
            return 0;
        }
        if (v > 10000) {
            return 10000;
        }
        return v;
    };
    ds::shadow::SunInput in{};
    if (phase_id == 0) {
        in.phase = ds::shadow::Phase::Day;
    } else if (phase_id == 1) {
        in.phase = ds::shadow::Phase::Dusk;
    } else {
        in.phase = ds::shadow::Phase::Night;
    }
    in.timeinphase = static_cast<float>(clamp_centi(timeinphase_centi)) / 10000.f;
    in.time = static_cast<float>(clamp_centi(time_centi)) / 10000.f;
    in.moonlit = (flags & 1) != 0;
    if (flags & 2) {
        in.season = ds::shadow::Season::Winter;
    } else if (flags & 4) {
        in.season = ds::shadow::Season::Summer;
    }
    in.wet = (flags & 8) != 0;
    in.length_boost = ds::shadow::LengthBoost();
    in.northern = ds::shadow::IsNorthernHemisphere();
    ds::shadow::Publish(ds::shadow::Evaluate(in));
}

extern "C" void DS_LUAJIT_shadow_set_length_boost(double boost) {
    ds::shadow::SetLengthBoost(static_cast<float>(boost));
}

extern "C" void DS_LUAJIT_shadow_set_hemisphere(int northern) {
    ds::shadow::SetNorthernHemisphere(northern != 0);
}



extern "C" void DS_LUAJIT_shadow_set_silhouette(int on) {
  ds::shadow::SetSilhouetteEnabled(on != 0);
  if (on != 0) {
    // Collect/flush only. Ellipse off is DS_LUAJIT_shadow_set_ellipse(0).
    if (!ds::shadow::InstallGenerateVBHook() || !ds::shadow::IsHookInstalled()) {
      ds::shadow::SetSilhouetteHealthy(false);
    } else {
      (void) ds::shadow::InstallSilhouetteHooks();
    }
  } else {
    ds::shadow::ClearSilhouetted();
  }
  std::fprintf(stderr, "[plugin_render_shadow] set_silhouette=%d healthy=%d gvb=%d\n",
               on != 0, ds::shadow::IsSilhouetteHealthy() ? 1 : 0,
               ds::shadow::IsHookInstalled() ? 1 : 0);
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
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kShadowHemisphere};
        e.type = ConfigValueType::String;
        e.default_value = ConfigValue::string("north");
        e.allowed = {"north", "south"};
        e.allowed_sources =
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
        if (!host->register_option_schema(std::move(e))) {
            std::fprintf(stderr, "[plugin_render_shadow] schema conflict %s\n",
                         std::string{ds::config::keys::kShadowHemisphere}.c_str());
            return false;
        }
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kShadowSilhouetteBatch};
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(false);
        e.allowed_sources =
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
        if (!host->register_option_schema(std::move(e))) {
            std::fprintf(stderr, "[plugin_render_shadow] schema conflict %s\n",
                         std::string{ds::config::keys::kShadowSilhouetteBatch}.c_str());
            return false;
        }
    }

    (void) host->register_game_injector_export("DS_LUAJIT_shadow_set_enabled",
                                               &DS_LUAJIT_shadow_set_enabled);
    (void) host->register_game_injector_export("DS_LUAJIT_shadow_set_ellipse",
                                               &DS_LUAJIT_shadow_set_ellipse);
    (void) host->register_game_injector_export("DS_LUAJIT_shadow_set_world",
                                               &DS_LUAJIT_shadow_set_world);
    (void) host->register_game_injector_export("DS_LUAJIT_shadow_set_length_boost",
                                               &DS_LUAJIT_shadow_set_length_boost);
    (void) host->register_game_injector_export("DS_LUAJIT_shadow_set_hemisphere",
                                               &DS_LUAJIT_shadow_set_hemisphere);
    (void) host->register_game_injector_export("DS_LUAJIT_shadow_set_silhouette",
                                               &DS_LUAJIT_shadow_set_silhouette);



    host->register_plugin(&g_render_shadow);
    std::fprintf(stderr, "[plugin_render_shadow] module init registered render.shadow dbg=sil-21\n");



    return true;
}
