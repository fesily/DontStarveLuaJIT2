#include "ConfigSources.hpp"
#include "config.hpp"
#include "config/BaseOptionKeys.hpp"
#include "config/path/ConfigPaths.hpp"
#include "plugins/plugin_core_vm/VmOptionKeys.hpp"

#include <cstdlib>
#include <string>
#include <string_view>

namespace ds::config {

ConfigSource EnvOrCmdSource::id() const {
    return ConfigSource::EnvOrCmd;
}

ConfigPartial EnvOrCmdSource::read(CascadeContext &) const {
    ConfigPartial partial;

    auto lua_vm_type = static_cast<const char *>(InjectorConfig::instance()->lua_vm_type);
    if (lua_vm_type != nullptr && lua_vm_type[0] != '\0' &&
        path::is_supported_lua_vm_type(lua_vm_type)) {
        // Preserve legacy env semantics:
        // - raw LuaVmType string was stored for GameLuaTypeFromString
        // - jit_gen is expressed as LuaVmType=jit + EnabledGenGC=true
        //   (ResolvedConfig::get_lua_vm_type checks EnabledGenGC first)
        std::string_view raw{lua_vm_type};
        if (raw == "jit_gen") {
            partial.values[std::string{keys::kLuaVmType}] =
                ds::plugin::ConfigValue::string("jit");
            partial.values[std::string{keys::kEnabledGenGC}] =
                ds::plugin::ConfigValue::boolean(true);
        } else {
            // jit/game/_51/lua51/51/5.1 — store raw supported alias.
            partial.values[std::string{keys::kLuaVmType}] =
                ds::plugin::ConfigValue::string(std::string{raw});
        }
    }

    if (auto value = path::read_env_or_cmd_value("DST_ANGLE_BACKEND"); !value.empty()) {
        partial.values["AngleBackend"] = ds::plugin::ConfigValue::string(std::move(value));
    } else if (const auto *platform = std::getenv("ANGLE_DEFAULT_PLATFORM");
               platform != nullptr && platform[0] != '\0') {
        partial.values["AngleBackend"] = ds::plugin::ConfigValue::string(platform);
    }

    return partial;
}

} // namespace ds::config
