#pragma once

#include <cstdint>

// Shared by GameNetworkSim (Injector) and Lua bindings (GameLuaModule).
// network.rpc plugin implementation does not own this type.
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
