#pragma once

#include "config.hpp"

#include <cstdint>

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

// Exported for dynamic plugin modules (plugin_network_rpc).
DONTSTARVEINJECTOR_GAME_API void GameNetWorkHookRpc4();
