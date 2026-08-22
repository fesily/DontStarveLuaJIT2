#include "ConfigSources.hpp"
#include "config/InjectorHostConfig.hpp"
#include "config/path/ConfigPaths.hpp"

#include <cstdlib>
#include <string>
#include <string_view>

namespace ds::config {

// Env/cmd bridge keys are owned by plugins (core.vm / render.angle).
// Literals only — cascade apply_partial drops unknown keys when schema missing.
namespace {
constexpr std::string_view kLuaVmType = "LuaVmType";
constexpr std::string_view kEnabledGenGC = "EnabledGenGC";
constexpr std::string_view kAngleBackend = "AngleBackend";
} // namespace

ConfigSource EnvOrCmdSource::id() const {
    return ConfigSource::EnvOrCmd;
}

ConfigPartial EnvOrCmdSource::read(CascadeContext &) const {
    ConfigPartial partial;

    auto lua_vm_type = static_cast<const char *>(InjectorConfig::instance()->lua_vm_type);
    if (lua_vm_type != nullptr && lua_vm_type[0] != '\0' &&
        path::is_supported_lua_vm_type(lua_vm_type)) {
        // Preserve legacy env semantics:
        // - raw LuaVmType string stored as-is for supported aliases
        // - jit_gen → LuaVmType=jit + EnabledGenGC=true
        //   (core.vm VmConfig::get_lua_vm_type checks EnabledGenGC first)
        std::string_view raw{lua_vm_type};
        if (raw == "jit_gen") {
            partial.values[std::string{kLuaVmType}] =
                ds::plugin::ConfigValue::string("jit");
            partial.values[std::string{kEnabledGenGC}] =
                ds::plugin::ConfigValue::boolean(true);
        } else {
            partial.values[std::string{kLuaVmType}] =
                ds::plugin::ConfigValue::string(std::string{raw});
        }
    }

    if (auto value = path::read_env_or_cmd_value("DST_ANGLE_BACKEND"); !value.empty()) {
        partial.values[std::string{kAngleBackend}] =
            ds::plugin::ConfigValue::string(std::move(value));
    } else if (const auto *platform = std::getenv("ANGLE_DEFAULT_PLATFORM");
               platform != nullptr && platform[0] != '\0') {
        partial.values[std::string{kAngleBackend}] =
            ds::plugin::ConfigValue::string(platform);
    }

    return partial;
}

} // namespace ds::config
