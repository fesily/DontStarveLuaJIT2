#pragma once

#include <cstdint>

// Shared layout for plugin_network_sim exports and GameLuaModule Lua table mapping.
// Implementation lives in plugins/plugin_network_sim/GameNetworkSim.cpp.
struct NetSimStats {
    bool     enabled;
    uint32_t delay_ms;
    uint32_t jitter_ms;
    uint32_t loss_pct;
    uint64_t packets_total;
    uint64_t packets_delayed;
    uint64_t packets_dropped;
    uint64_t packets_released;
    uint32_t queue_depth;
};
