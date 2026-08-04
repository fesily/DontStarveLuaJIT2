#include "ConfigSources.hpp"
#include "config.hpp"
#include "config/ConfigPathAccess.hpp"

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
        // Schema.allowed is jit/game only. Extended aliases (lua51/51/jit_gen/…)
        // are accepted by legacy is_supported_lua_vm_type but rejected by
        // apply_partial against allowed set — normalize where possible.
        std::string_view raw{lua_vm_type};
        std::string value;
        if (raw == "jit" || raw == "game") {
            value = std::string{raw};
        } else if (raw == "jit_gen") {
            // GenGC is a separate bool key; leave LuaVmType unchanged.
        } else if (raw == "lua51" || raw == "51" || raw == "5.1" || raw == "_51") {
            // Historical env aliases for PUC 5.1 — map to "game" VM selection.
            value = "game";
        }
        if (!value.empty()) {
            partial.values["LuaVmType"] = ds::plugin::ConfigValue::string(std::move(value));
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
