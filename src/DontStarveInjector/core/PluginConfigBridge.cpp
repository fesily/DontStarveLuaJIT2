#include "PluginConfigBridge.hpp"

namespace ds::plugin {

ConfigView BuildConfigView(const ConfigSchemaRegistry &schema,
                           const GameJitModConfig &config) {
    ConfigView view;

    // 1. Schema defaults for each registered entry.
    for (auto *e : schema.all()) {
        view[e->key] = e->default_value;
    }

    // 2. Core fields always written from GameJitModConfig.
    view["AlwaysEnableMod"] = ConfigValue::boolean(config.AlwaysEnableMod);
    view["DisableJITWhenServer"] = ConfigValue::boolean(config.DisableJITWhenServer);
    view["LuaVmType"] = ConfigValue::string(config.LuaVmType);
    view["EnabledGenGC"] = ConfigValue::boolean(config.EnabledGenGC);

    // 3. Business dual-write while fields remain on GameJitModConfig.
    view["EnableVBPool"] = ConfigValue::boolean(config.EnableVBPool);
    view["AngleBackend"] = ConfigValue::string(config.AngleBackend);

    // 4. Temporary NetworkOpt=true only when schema did not register it.
    // After S1 plugins register NetworkOpt; do not force true over schema default.
    if (view.find("NetworkOpt") == view.end()) {
        view["NetworkOpt"] = ConfigValue::boolean(true);
    }

    return view;
}

ConfigView FromGameJitModConfig(const GameJitModConfig &config) {
    // Empty schema → BuildConfigView falls back to legacy NetworkOpt=true.
    ConfigSchemaRegistry empty;
    return BuildConfigView(empty, config);
}

} // namespace ds::plugin
