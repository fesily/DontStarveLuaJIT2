#pragma once
#include <string_view>

namespace ds::config::keys {

// Client-only: local run/idle drive when movement prediction is OFF.
inline constexpr std::string_view kEnableClientAnimOwn = "EnableClientAnimOwn";

} // namespace ds::config::keys
