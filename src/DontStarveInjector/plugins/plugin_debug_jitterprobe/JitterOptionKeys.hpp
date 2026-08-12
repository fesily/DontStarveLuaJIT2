#pragma once
#include <string_view>

namespace ds::config::keys {

// Temporary investigation probe for client prediction-OFF movement jitter.
inline constexpr std::string_view kEnableJitterProbe = "EnableJitterProbe";

} // namespace ds::config::keys
