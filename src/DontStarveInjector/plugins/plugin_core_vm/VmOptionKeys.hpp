#pragma once
#include <string_view>

namespace ds::config::keys {

inline constexpr std::string_view kLuaVmType = "LuaVmType";
inline constexpr std::string_view kEnabledGenGC = "EnabledGenGC";
inline constexpr std::string_view kDisableJITWhenServer = "DisableJITWhenServer";

} // namespace ds::config::keys
