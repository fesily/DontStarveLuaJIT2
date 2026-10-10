#pragma once
#include <cstddef>
#include <cstdint>

namespace ds::net_stats {

inline constexpr size_t kClientPingMaxClients = 64;

// Installs the UpdateNetStats invocation listener (called from plugin load()).
// Fail closed: returns false with the feature disabled when the signature,
// decode or gum attach fails.
bool install();

// Per-client RTT in milliseconds for `userid`, or -1 when unknown.
// This is the plugin's only published value; everything else a consumer needs
// (userid enumeration, names, netscore, ...) comes from the Lua side.
int32_t client_ping_lookup(const char *userid);

} // namespace ds::net_stats
