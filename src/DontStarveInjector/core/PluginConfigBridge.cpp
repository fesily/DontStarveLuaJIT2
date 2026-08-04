#include "PluginConfigBridge.hpp"

namespace ds::plugin {

ConfigView BuildConfigView(const ConfigSchemaRegistry &schema,
                           const GameJitModConfig &core,
                           const ConfigView &business) {
    ConfigView view;

    // 1. Schema defaults for each registered entry.
    for (auto *e : schema.all()) {
        view[e->key] = e->default_value;
    }

    // 2. Business overlay: core.business_options first, then explicit business arg
    // (later wins). Cascade load fills core.business_options; callers may also
    // pass extras directly.
    for (const auto &[key, value] : core.business_options) {
        view[key] = value;
    }
    for (const auto &[key, value] : business) {
        view[key] = value;
    }

    // 3. Core fields always written from GameJitModConfig.
    view["AlwaysEnableMod"] = ConfigValue::boolean(core.AlwaysEnableMod);
    view["DisableJITWhenServer"] = ConfigValue::boolean(core.DisableJITWhenServer);
    view["LuaVmType"] = ConfigValue::string(core.LuaVmType);
    view["EnabledGenGC"] = ConfigValue::boolean(core.EnabledGenGC);

    return view;
}

ConfigView FromGameJitModConfig(const GameJitModConfig &config) {
    // Empty schema: only core fields + business_options (no invented NetworkOpt).
    ConfigSchemaRegistry empty;
    return BuildConfigView(empty, config);
}

} // namespace ds::plugin
