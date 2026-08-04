#pragma once

#include <cstdint>

// Owned by plugin_network_sim. Layout is the C ABI of DS_LUAJIT_net_sim_get_stats().
// GameLuaModule includes this for the GetProcAddress return type only.
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
