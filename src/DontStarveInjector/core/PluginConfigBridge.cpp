#include "PluginConfigBridge.hpp"

namespace ds::plugin {

ConfigView FromGameJitModConfig(const GameJitModConfig &config) {
    ConfigView view;

    view["EnableVBPool"] = ConfigValue::boolean(config.EnableVBPool);
    view["AngleBackend"] = ConfigValue::string(config.AngleBackend);
    view["AlwaysEnableMod"] = ConfigValue::boolean(config.AlwaysEnableMod);
    view["DisableJITWhenServer"] = ConfigValue::boolean(config.DisableJITWhenServer);
    view["LuaVmType"] = ConfigValue::string(config.LuaVmType);
    view["EnabledGenGC"] = ConfigValue::boolean(config.EnabledGenGC);

    // NetworkOpt is not yet part of the native GameJitModConfig cascade (Lua-only today).
    // Provide modinfo default (true) so EarlyNative plugins can resolve against a stable key
    // until M2 migrates NetworkOpt into the native config surface.
    view["NetworkOpt"] = ConfigValue::boolean(true);

    return view;
}

} // namespace ds::plugin
